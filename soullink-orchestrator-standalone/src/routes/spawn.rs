//! Route: Spawn
//!
//! `POST /api/mesh/spawn` turns a request body into a process. It is the only
//! site in the `UnsandboxedArbitraryCommand` allowlist with a demonstrated
//! remote path to it, which is why it was fixed first (roadmap P1-8-B).
//!
//! # What was actually wrong, and what was not
//!
//! The original code was **not** shell injection: it built argv with discrete
//! `.arg()` calls and never went through `sh -c`. Reporting it as command
//! injection would have been wrong, and "fixing" it by routing the joined
//! string through `Sandbox::execute` — which splits on whitespace — would have
//! *introduced* the splitting surface the code did not have. Three things were
//! genuinely wrong:
//!
//! 1. **Argument injection.** `domain` came straight from the request body and
//!    was passed as the value of `--brain`. A domain of `--config=/etc/shadow`
//!    is not a value to `brain_v12.py`'s argument parser, it is another flag.
//! 2. **Unbounded spawning.** Every request forked a `python3` that nothing
//!    ever reaped or counted against a ceiling. `increment_spawn_count`
//!    counted them for a metrics endpoint; it did not bound them.
//! 3. **No isolation.** The child inherited this process's privileges, file
//!    descriptors, address-space limits and network access in full.
//!
//! There is a fourth, unfixed here because it is a deployment decision rather
//! than a code defect: **the route has no authentication**. `soul_cors` (P1-10)
//! makes a browser's cross-origin call fail, but CORS is not authentication and
//! stops nothing that is not a browser — `curl` reaches this route regardless.
//! Recorded as MED-013.

use crate::state::AppState;
use axum::{extract::State, Json};
use serde_json::{json, Value};
use soul_sandbox::{Sandbox, SandboxPolicy, SpawnSpec};
use std::time::Duration as StdDuration;
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};

/// Maximum brains alive at once.
///
/// Without a ceiling, N requests fork N interpreters; the only limit is the
/// host's process table, which is a denial of service against the whole
/// machine rather than just this service. The number is deliberately small:
/// each brain is a Python process that binds a port, and the port search below
/// starts at 9016, so a large value would collide with whatever else the host
/// runs long before it ran out of brains.
const MAX_LIVE_BRAINS: usize = 16;

/// Highest port the search will hand out.
///
/// The original loop was `while used.contains(&port) { port += 1 }` on a `u16`
/// with no bound: with every port from 9016 up in use it walks to 65535 and
/// then overflows — a panic in debug, a wrap to 0 in release, and port 0 tells
/// the kernel "any free port", so the health check that follows would poll a
/// port the brain is not on. Bounding the search turns that into an error the
/// caller can see.
const MAX_BRAIN_PORT: u16 = 9999;

/// Characters allowed in a domain name.
///
/// An allowlist, not a denylist of bad characters: `domain` reaches an argument
/// parser and a log line, and enumerating everything that could matter to
/// either is how these get missed. Rejecting a leading `-` is
/// `SpawnSpec::value`'s job as well, so this is the second of two independent
/// checks rather than the only one.
fn valid_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 64
        && d.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        && !d.starts_with('-')
}

/// Policy for a spawned brain.
///
/// **`network_isolated` is false, deliberately.** A brain exists to bind a port
/// and answer HTTP on it; in an empty network namespace it would bind a port
/// nothing can reach and the health check below would fail every time. That is
/// a real reduction in isolation relative to `SandboxPolicy::default()` and it
/// is stated here rather than buried: the child keeps host networking. Seccomp,
/// `setpgid` and the `setrlimit` ceilings all still apply, so this is narrower
/// than the unsandboxed spawn it replaces, not equivalent to it.
fn brain_policy() -> SandboxPolicy {
    SandboxPolicy {
        network_isolated: false,
        // Not used by `spawn_supervised` — a daemon has no deadline — but left
        // at the default rather than something misleading like `MAX`.
        timeout: StdDuration::from_secs(30),
        ..Default::default()
    }
}

/// Route POST /api/mesh/spawn
pub async fn route_spawn(State(state): State<AppState>, Json(body): Json<Value>) -> Json<Value> {
    let domain = body
        .get("domain")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if domain.is_empty() {
        return Json(json!({"ok": false, "error": "domain requis"}));
    }

    if !valid_domain(&domain) {
        // The rejected value is not echoed back: it is attacker-controlled and
        // this response is rendered in a browser by the dashboard.
        return Json(json!({
            "ok": false,
            "error": "domain invalide: alphanumérique, '_' et '-' uniquement, \
                      1-64 caractères, ne peut pas commencer par '-'"
        }));
    }

    if state.brain_exists(&domain) {
        return Json(json!({
            "ok": false,
            "error": format!("Brain '{}' existe déjà", domain)
        }));
    }

    let used_ports: Vec<u16> = state.get_used_ports();
    if used_ports.len() >= MAX_LIVE_BRAINS {
        return Json(json!({
            "ok": false,
            "error": format!(
                "limite de {} brains atteinte — arrêter un brain avant d'en lancer un autre",
                MAX_LIVE_BRAINS
            )
        }));
    }

    let mut port = 9016u16;
    while used_ports.contains(&port) {
        if port >= MAX_BRAIN_PORT {
            return Json(json!({
                "ok": false,
                "error": "aucun port libre dans la plage 9016-9999"
            }));
        }
        port += 1;
    }

    let brain_dir = state.brain_dir.clone();
    let domain_c = domain.clone();
    let speciality: Vec<String> = body
        .get("speciality")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec![domain.clone()]);

    // `python3` and the script path are chosen here, so they are `flag`.
    // `domain_c` arrived in the request body, so it is `value` and
    // `spawn_supervised` refuses it if it looks like a flag.
    let mut spec = SpawnSpec::new("python3")
        .flag(format!("{}/brain_v12.py", brain_dir))
        .flag("--brain")
        .value(&domain_c);

    // Transmettre la speciality au brain lancé.
    for s in &speciality {
        spec = spec.flag("--speciality").value(s);
    }

    let sandbox = Sandbox::new(brain_policy());

    // Spawn *before* counting: the original incremented the counter and then
    // spawned in a detached task, so a spawn that failed still counted.
    let child = match sandbox.spawn_supervised(&spec) {
        Ok(child) => child,
        Err(e) => {
            error!("[SPAWN] ❌ refus sandbox pour '{}': {}", domain_c, e);
            return Json(json!({
                "ok": false,
                "error": format!("spawn refusé: {}", e)
            }));
        }
    };

    state.increment_spawn_count();
    info!(
        "[SPAWN] Brain-{} lancé sur :{} (pid {})",
        domain_c,
        port,
        child.pid()
    );

    tokio::spawn(async move {
        let mut child = child;

        sleep(Duration::from_secs(8)).await;

        let url = format!("http://localhost:{}/api/stats", port);
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                // The original `.unwrap()` here would have taken down the task
                // — and with it the only handle to the child — on a TLS-init
                // failure.
                error!("[SPAWN] client HTTP indisponible: {}", e);
                let _ = child.kill_group();
                return;
            }
        };

        for _ in 0..6 {
            if let Ok(Ok(resp)) =
                tokio::time::timeout(Duration::from_secs(2), client.get(&url).send()).await
            {
                if resp.status().is_success() {
                    info!("[SPAWN] ✅ Brain-{} actif sur :{}", domain_c, port);
                    return;
                }
            }
            sleep(Duration::from_secs(5)).await;
        }

        // The original logged this and returned, leaving a process that never
        // came up running forever against the ceiling. Reap it instead: a brain
        // that has not answered in ~38s is not going to.
        warn!(
            "[SPAWN] ⚠️ Brain-{} ne répond pas — arrêt du groupe de processus",
            domain_c
        );
        if let Err(e) = child.kill_group() {
            error!("[SPAWN] impossible d'arrêter Brain-{}: {}", domain_c, e);
        }
    });

    Json(json!({
        "ok": true,
        "domain": domain,
        "port": port,
        "msg": format!("Spawn Brain-{} en cours sur :{}", domain, port),
        "check": "/api/mesh/status dans 30s",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_domain_that_looks_like_a_flag_is_rejected() {
        assert!(!valid_domain("--config=/etc/shadow"));
        assert!(!valid_domain("-v"));
    }

    #[test]
    fn ordinary_domains_are_accepted() {
        for d in ["science", "crypto_2", "meta-organ", "A1"] {
            assert!(valid_domain(d), "{d} should be valid");
        }
    }

    #[test]
    fn shell_metacharacters_and_separators_are_rejected() {
        // None of these could escape argv, since there is no shell on this
        // path. They are rejected because `domain` also reaches log lines and a
        // JSON response, and because an allowlist is easier to be sure of than
        // a list of things that turned out to matter.
        for d in [
            "a;rm -rf /",
            "a b",
            "a/../../etc",
            "a$(id)",
            "a\nb",
            "a\u{0}b",
        ] {
            assert!(!valid_domain(d), "{d:?} should be rejected");
        }
    }

    #[test]
    fn the_length_bound_holds_at_the_edges() {
        assert!(valid_domain(&"a".repeat(64)));
        assert!(!valid_domain(&"a".repeat(65)));
        assert!(!valid_domain(""));
    }

    /// The spec must carry the domain as a value, not a flag — otherwise
    /// `spawn_supervised`'s argument-injection check never fires.
    #[test]
    fn the_domain_is_marked_as_a_caller_supplied_value() {
        let spec = SpawnSpec::new("python3")
            .flag("/brains/brain_v12.py")
            .flag("--brain")
            .value("--malicious");
        assert!(
            spec.preview().is_err(),
            "a flag-shaped domain must be refused by the spec"
        );
    }

    #[test]
    fn a_well_formed_spec_previews_as_exact_argv() {
        let spec = SpawnSpec::new("python3")
            .flag("/brains/brain_v12.py")
            .flag("--brain")
            .value("science");
        assert_eq!(
            spec.preview().unwrap(),
            vec!["python3", "/brains/brain_v12.py", "--brain", "science"]
        );
    }

    /// The brain must keep host networking or it cannot serve the port the
    /// health check polls. Pinned so a later "harden the defaults" change has
    /// to confront the tradeoff rather than silently break spawning.
    #[test]
    fn brain_policy_keeps_networking_but_not_the_other_protections() {
        let p = brain_policy();
        assert!(!p.network_isolated, "a brain must be reachable on its port");
        assert_eq!(
            p.seccomp_profile.as_deref(),
            Some("default"),
            "seccomp must still apply"
        );
    }
}
