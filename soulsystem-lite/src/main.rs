mod ollama_chat;

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Environment variable holding a comma-separated CORS origin allowlist.
///
/// Unset or blank permits no cross-origin browser access at all
/// (INV-NET-4). Each service names its own variable: they deploy
/// separately and have no reason to share an origin list.
const CORS_ALLOWLIST_VAR: &str = "SOULSYSTEM_LITE_CORS_ORIGINS";

#[derive(Clone)]
struct AppState {
    cervo: Arc<RwLock<Option<soul_bridge::cervo::CervoBridge>>>,
    ccos: soul_bridge::ccos::CcosClient,
    octa: soul_bridge::octasoma::OctaClient,
}

// ── REST API ────────────────────────────────────────────────────────

#[derive(Serialize)]
struct HealthResponse {
    ok: bool,
    cervo: bool,
    ccos: bool,
    octa: bool,
    time: String,
}

async fn health(State(s): State<AppState>) -> Json<HealthResponse> {
    let cervo_running = s.cervo.read().await.is_some();
    let ccos_ok = s.ccos.ping().await.unwrap_or(false);
    let octa_ok = s.octa.ping().await.unwrap_or(false);
    Json(HealthResponse {
        ok: cervo_running && ccos_ok && octa_ok,
        cervo: cervo_running,
        ccos: ccos_ok,
        octa: octa_ok,
        time: chrono::Utc::now().to_rfc3339(),
    })
}

#[derive(Deserialize)]
struct SpawnRequest {
    algorithm: String,
    factor: Option<usize>,
}

#[derive(Serialize)]
struct SpawnResponse {
    ok: bool,
    unit_id: Option<String>,
    error: Option<String>,
}

async fn cervo_spawn(
    State(s): State<AppState>,
    Json(req): Json<SpawnRequest>,
) -> Json<SpawnResponse> {
    let guard = s.cervo.read().await;
    match guard.as_ref() {
        Some(cortex) => match cortex.spawn_unit(&req.algorithm, req.factor).await {
            Ok(id) => Json(SpawnResponse {
                ok: true,
                unit_id: Some(id),
                error: None,
            }),
            Err(e) => Json(SpawnResponse {
                ok: false,
                unit_id: None,
                error: Some(e),
            }),
        },
        None => Json(SpawnResponse {
            ok: false,
            unit_id: None,
            error: Some("CERVO not started".into()),
        }),
    }
}

#[derive(Deserialize)]
struct MutateRequest {
    unit_id: String,
}

#[derive(Serialize)]
struct MutateResponse {
    ok: bool,
    outcome: Option<soul_bridge::cervo::MutationOutcome>,
    error: Option<String>,
}

async fn cervo_mutate(
    State(s): State<AppState>,
    Json(req): Json<MutateRequest>,
) -> Json<MutateResponse> {
    let guard = s.cervo.read().await;
    match guard.as_ref() {
        Some(cortex) => match cortex.mutate_unit(&req.unit_id).await {
            Ok(out) => Json(MutateResponse {
                ok: true,
                outcome: Some(out),
                error: None,
            }),
            Err(e) => Json(MutateResponse {
                ok: false,
                outcome: None,
                error: Some(e),
            }),
        },
        None => Json(MutateResponse {
            ok: false,
            outcome: None,
            error: Some("CERVO not started".into()),
        }),
    }
}

#[derive(Deserialize)]
struct ProcessRequest {
    payloads: Vec<Vec<u8>>,
}

#[derive(Serialize)]
struct ProcessResponse {
    ok: bool,
    results: Option<serde_json::Value>,
    error: Option<String>,
}

async fn cervo_process(
    State(s): State<AppState>,
    Json(req): Json<ProcessRequest>,
) -> Json<ProcessResponse> {
    let guard = s.cervo.read().await;
    match guard.as_ref() {
        Some(cortex) => match cortex.process_data(req.payloads).await {
            Ok(res) => Json(ProcessResponse {
                ok: true,
                results: Some(res),
                error: None,
            }),
            Err(e) => Json(ProcessResponse {
                ok: false,
                results: None,
                error: Some(e),
            }),
        },
        None => Json(ProcessResponse {
            ok: false,
            results: None,
            error: Some("CERVO not started".into()),
        }),
    }
}

#[derive(Serialize)]
struct TickResponse {
    ok: bool,
    error: Option<String>,
}

async fn cervo_tick(State(s): State<AppState>) -> Json<TickResponse> {
    let guard = s.cervo.read().await;
    match guard.as_ref() {
        Some(cortex) => {
            cortex.tick_all().await.unwrap_or(());
            Json(TickResponse {
                ok: true,
                error: None,
            })
        }
        None => Json(TickResponse {
            ok: false,
            error: Some("CERVO not started".into()),
        }),
    }
}

#[derive(Serialize)]
struct ReportResponse {
    ok: bool,
    report: Option<soul_bridge::cervo::CortexSummary>,
    error: Option<String>,
}

async fn cervo_report(State(s): State<AppState>) -> Json<ReportResponse> {
    let guard = s.cervo.read().await;
    match guard.as_ref() {
        Some(cortex) => match cortex.report().await {
            Ok(r) => Json(ReportResponse {
                ok: true,
                report: Some(r),
                error: None,
            }),
            Err(e) => Json(ReportResponse {
                ok: false,
                report: None,
                error: Some(e),
            }),
        },
        None => Json(ReportResponse {
            ok: false,
            report: None,
            error: Some("CERVO not started".into()),
        }),
    }
}

#[derive(Serialize)]
struct StatusResponse {
    ok: bool,
    status: Option<soul_bridge::cervo::BridgeStatus>,
    error: Option<String>,
}

async fn cervo_status(State(s): State<AppState>) -> Json<StatusResponse> {
    let guard = s.cervo.read().await;
    match guard.as_ref() {
        Some(cortex) => {
            let st = cortex.status().await;
            Json(StatusResponse {
                ok: true,
                status: Some(st),
                error: None,
            })
        }
        None => Json(StatusResponse {
            ok: false,
            status: None,
            error: Some("CERVO not started".into()),
        }),
    }
}

#[derive(Deserialize)]
struct CcosIngestRequest {
    uri: String,
    source: String,
}

#[derive(Serialize)]
struct CcosResponse {
    ok: bool,
    result: Option<serde_json::Value>,
    error: Option<String>,
}

async fn ccos_ingest(
    State(s): State<AppState>,
    Json(req): Json<CcosIngestRequest>,
) -> Json<CcosResponse> {
    match s.ccos.ingest(&req.uri, &req.source).await {
        Ok(r) => Json(CcosResponse {
            ok: true,
            result: Some(serde_json::to_value(r).unwrap()),
            error: None,
        }),
        Err(e) => Json(CcosResponse {
            ok: false,
            result: None,
            error: Some(e.to_string()),
        }),
    }
}

#[derive(Deserialize)]
struct CcosRecallRequest {
    strategy: String,
    text: Option<String>,
    anchor: Option<String>,
    budget: Option<usize>,
}

async fn ccos_recall(
    State(s): State<AppState>,
    Json(req): Json<CcosRecallRequest>,
) -> Json<CcosResponse> {
    match s
        .ccos
        .recall(
            &req.strategy,
            req.text.as_deref(),
            req.anchor.as_deref(),
            req.budget,
        )
        .await
    {
        Ok(r) => Json(CcosResponse {
            ok: true,
            result: Some(serde_json::to_value(r).unwrap()),
            error: None,
        }),
        Err(e) => Json(CcosResponse {
            ok: false,
            result: None,
            error: Some(e.to_string()),
        }),
    }
}

async fn ccos_stats(State(s): State<AppState>) -> Json<CcosResponse> {
    match s.ccos.stats().await {
        Ok(r) => Json(CcosResponse {
            ok: true,
            result: Some(serde_json::to_value(r).unwrap()),
            error: None,
        }),
        Err(e) => Json(CcosResponse {
            ok: false,
            result: None,
            error: Some(e.to_string()),
        }),
    }
}

async fn ccos_verify(State(s): State<AppState>) -> Json<CcosResponse> {
    match s.ccos.verify().await {
        Ok(v) => Json(CcosResponse {
            ok: true,
            result: Some(serde_json::json!({"valid": v})),
            error: None,
        }),
        Err(e) => Json(CcosResponse {
            ok: false,
            result: None,
            error: Some(e.to_string()),
        }),
    }
}

async fn ccos_ping(State(s): State<AppState>) -> Json<CcosResponse> {
    match s.ccos.ping().await {
        Ok(true) => Json(CcosResponse {
            ok: true,
            result: Some(serde_json::json!({"alive": true})),
            error: None,
        }),
        _ => Json(CcosResponse {
            ok: false,
            result: None,
            error: Some("CCOS not reachable".into()),
        }),
    }
}

// ── OctaSoma REST handlers ──────────────────────────────────────────

#[derive(Deserialize)]
struct OctaIngestRequest {
    uri: String,
    text: String,
    region: Option<String>,
}

#[derive(Serialize)]
struct OctaResponse {
    ok: bool,
    result: Option<serde_json::Value>,
    error: Option<String>,
}

async fn octa_ingest(
    State(s): State<AppState>,
    Json(req): Json<OctaIngestRequest>,
) -> Json<OctaResponse> {
    match s
        .octa
        .ingest(&req.uri, &req.text, req.region.as_deref())
        .await
    {
        Ok(r) => Json(OctaResponse {
            ok: true,
            result: Some(serde_json::to_value(r).unwrap()),
            error: None,
        }),
        Err(e) => Json(OctaResponse {
            ok: false,
            result: None,
            error: Some(e.to_string()),
        }),
    }
}

#[derive(Deserialize)]
struct OctaRecallRequest {
    text: String,
    region: Option<String>,
    strategy: Option<String>,
    k: Option<usize>,
}

async fn octa_recall(
    State(s): State<AppState>,
    Json(req): Json<OctaRecallRequest>,
) -> Json<OctaResponse> {
    match s
        .octa
        .recall(
            &req.text,
            req.region.as_deref(),
            req.strategy.as_deref(),
            req.k,
        )
        .await
    {
        Ok(r) => Json(OctaResponse {
            ok: true,
            result: Some(serde_json::to_value(r).unwrap()),
            error: None,
        }),
        Err(e) => Json(OctaResponse {
            ok: false,
            result: None,
            error: Some(e.to_string()),
        }),
    }
}

#[derive(Deserialize)]
struct OctaExplainRequest {
    text: String,
    region: Option<String>,
    k: Option<usize>,
}

async fn octa_explain(
    State(s): State<AppState>,
    Json(req): Json<OctaExplainRequest>,
) -> Json<OctaResponse> {
    match s
        .octa
        .explain(&req.text, req.region.as_deref(), req.k)
        .await
    {
        Ok(r) => Json(OctaResponse {
            ok: true,
            result: Some(serde_json::to_value(r).unwrap()),
            error: None,
        }),
        Err(e) => Json(OctaResponse {
            ok: false,
            result: None,
            error: Some(e.to_string()),
        }),
    }
}

async fn octa_stats(State(s): State<AppState>) -> Json<OctaResponse> {
    match s.octa.stats().await {
        Ok(r) => Json(OctaResponse {
            ok: true,
            result: Some(serde_json::to_value(r).unwrap()),
            error: None,
        }),
        Err(e) => Json(OctaResponse {
            ok: false,
            result: None,
            error: Some(e.to_string()),
        }),
    }
}

#[derive(Deserialize)]
struct OctaFeedbackRequest {
    relevant: Option<Vec<String>>,
    irrelevant: Option<Vec<String>>,
}

async fn octa_feedback(
    State(s): State<AppState>,
    Json(req): Json<OctaFeedbackRequest>,
) -> Json<OctaResponse> {
    match s.octa.feedback(req.relevant, req.irrelevant).await {
        Ok(r) => Json(OctaResponse {
            ok: true,
            result: Some(serde_json::to_value(r).unwrap()),
            error: None,
        }),
        Err(e) => Json(OctaResponse {
            ok: false,
            result: None,
            error: Some(e.to_string()),
        }),
    }
}

async fn octa_ping(State(s): State<AppState>) -> Json<OctaResponse> {
    match s.octa.ping().await {
        Ok(true) => Json(OctaResponse {
            ok: true,
            result: Some(serde_json::json!({"alive": true})),
            error: None,
        }),
        _ => Json(OctaResponse {
            ok: false,
            result: None,
            error: Some("OctaSoma not reachable".into()),
        }),
    }
}

// ── WebSocket handler (port 9022) ───────────────────────────────────

async fn ws_handler(
    State(s): State<AppState>,
    ws: axum::extract::ws::WebSocketUpgrade,
) -> axum::response::Response {
    ws.on_upgrade(move |socket| handle_ws(socket, s))
}

async fn handle_ws(mut socket: axum::extract::ws::WebSocket, state: AppState) {
    use axum::extract::ws::Message;
    use futures_util::StreamExt;

    loop {
        match socket.recv().await {
            Some(Ok(Message::Text(text))) => {
                let req: serde_json::Value = match serde_json::from_str(&text) {
                    Ok(v) => v,
                    Err(_) => {
                        let _ = socket
                            .send(Message::Text(
                                serde_json::json!({"error": "invalid JSON"})
                                    .to_string()
                                    .into(),
                            ))
                            .await;
                        continue;
                    }
                };

                let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
                let empty = serde_json::json!({});
                let params = req.get("params").unwrap_or(&empty);
                let id = req.get("id");

                let result = match method {
                    "cervo.spawn" => {
                        let algo = params
                            .get("algorithm")
                            .and_then(|v| v.as_str())
                            .unwrap_or("identity");
                        let factor = params
                            .get("factor")
                            .and_then(|v| v.as_u64())
                            .map(|v| v as usize);
                        let guard = state.cervo.read().await;
                        match guard.as_ref() {
                            Some(c) => c
                                .spawn_unit(algo, factor)
                                .await
                                .map(|id| serde_json::json!({"unit_id": id})),
                            None => Err("CERVO not started".into()),
                        }
                    }
                    "cervo.report" => {
                        let guard = state.cervo.read().await;
                        match guard.as_ref() {
                            Some(c) => c
                                .report()
                                .await
                                .map(|r| serde_json::to_value(r).unwrap_or_default()),
                            None => Err("CERVO not started".into()),
                        }
                    }
                    "ccos.ingest" => {
                        let uri = params.get("uri").and_then(|v| v.as_str()).unwrap_or("");
                        let source = params.get("source").and_then(|v| v.as_str()).unwrap_or("");
                        state
                            .ccos
                            .ingest(uri, source)
                            .await
                            .map(|r| serde_json::to_value(r).unwrap_or_default())
                            .map_err(|e| e.to_string())
                    }
                    "ccos.stats" => state
                        .ccos
                        .stats()
                        .await
                        .map(|r| serde_json::to_value(r).unwrap_or_default())
                        .map_err(|e| e.to_string()),
                    "ccos.recall" => {
                        let strategy = params
                            .get("strategy")
                            .and_then(|v| v.as_str())
                            .unwrap_or("around");
                        let text = params.get("text").and_then(|v| v.as_str());
                        let anchor = params.get("anchor").and_then(|v| v.as_str());
                        let budget = params
                            .get("budget")
                            .and_then(|v| v.as_u64())
                            .map(|v| v as usize);
                        state
                            .ccos
                            .recall(strategy, text, anchor, budget)
                            .await
                            .map(|r| serde_json::to_value(r).unwrap_or_default())
                            .map_err(|e| e.to_string())
                    }
                    "octa.ingest" => {
                        let uri = params.get("uri").and_then(|v| v.as_str()).unwrap_or("");
                        let text = params.get("text").and_then(|v| v.as_str()).unwrap_or("");
                        let region = params.get("region").and_then(|v| v.as_str());
                        state
                            .octa
                            .ingest(uri, text, region)
                            .await
                            .map(|r| serde_json::to_value(r).unwrap_or_default())
                            .map_err(|e| e.to_string())
                    }
                    "octa.recall" => {
                        let text = params.get("text").and_then(|v| v.as_str()).unwrap_or("");
                        let region = params.get("region").and_then(|v| v.as_str());
                        let strategy = params.get("strategy").and_then(|v| v.as_str());
                        let k = params.get("k").and_then(|v| v.as_u64()).map(|v| v as usize);
                        state
                            .octa
                            .recall(text, region, strategy, k)
                            .await
                            .map(|r| serde_json::to_value(r).unwrap_or_default())
                            .map_err(|e| e.to_string())
                    }
                    "octa.stats" => state
                        .octa
                        .stats()
                        .await
                        .map(|r| serde_json::to_value(r).unwrap_or_default())
                        .map_err(|e| e.to_string()),
                    "octa.explain" => {
                        let text = params.get("text").and_then(|v| v.as_str()).unwrap_or("");
                        let region = params.get("region").and_then(|v| v.as_str());
                        let k = params.get("k").and_then(|v| v.as_u64()).map(|v| v as usize);
                        state
                            .octa
                            .explain(text, region, k)
                            .await
                            .map(|r| serde_json::to_value(r).unwrap_or_default())
                            .map_err(|e| e.to_string())
                    }
                    "octa.feedback" => {
                        let relevant = params.get("relevant").and_then(|v| v.as_array()).map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str().map(String::from))
                                .collect()
                        });
                        let irrelevant =
                            params
                                .get("irrelevant")
                                .and_then(|v| v.as_array())
                                .map(|a| {
                                    a.iter()
                                        .filter_map(|x| x.as_str().map(String::from))
                                        .collect()
                                });
                        state
                            .octa
                            .feedback(relevant, irrelevant)
                            .await
                            .map(|r| serde_json::to_value(r).unwrap_or_default())
                            .map_err(|e| e.to_string())
                    }
                    "health" => {
                        let r = state.cervo.read().await;
                        Ok(serde_json::json!({
                            "cervo": r.is_some(),
                            "ccos": state.ccos.ping().await.unwrap_or(false),
                            "octa": state.octa.ping().await.unwrap_or(false),
                        }))
                    }
                    other => Err(format!("Unknown method: {other}")),
                };

                let resp = match result {
                    Ok(data) => {
                        let mut resp = serde_json::json!({"ok": true, "result": data});
                        if let Some(i) = id {
                            resp["id"] = i.clone();
                        }
                        resp
                    }
                    Err(e) => {
                        let mut resp = serde_json::json!({"ok": false, "error": e});
                        if let Some(i) = id {
                            resp["id"] = i.clone();
                        }
                        resp
                    }
                };

                let _ = socket.send(Message::Text(resp.to_string().into())).await;
            }
            Some(Ok(Message::Close(_))) | None => break,
            Some(Ok(Message::Ping(d))) => {
                let _ = socket.send(Message::Pong(d)).await;
            }
            _ => {}
        }
    }
}

// ── Main ────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    tracing::info!("Starting SoulSystem-lite gateway...");

    let ccos = soul_bridge::ccos::init()
        .await
        .map_err(|e| anyhow::anyhow!("CCOS init: {e}"))?;
    tracing::info!("CCOS bridge initialized");

    let octa = soul_bridge::octasoma::init()
        .await
        .map_err(|e| anyhow::anyhow!("OctaSoma init: {e}"))?;
    tracing::info!("OctaSoma bridge initialized");

    let config = cervo::config::CervoConfig::default();
    let bridge = soul_bridge::cervo::CervoBridge::new(config);
    bridge
        .start()
        .await
        .map_err(|e| anyhow::anyhow!("CERVO start: {e}"))?;
    tracing::info!("CERVO bridge initialized");

    let state = AppState {
        cervo: Arc::new(RwLock::new(Some(bridge))),
        ccos,
        octa,
    };

    // REST API on :9023
    let rest_app = Router::new()
        .route("/health", get(health))
        .route("/cervo/spawn", post(cervo_spawn))
        .route("/cervo/mutate", post(cervo_mutate))
        .route("/cervo/process", post(cervo_process))
        .route("/cervo/tick", post(cervo_tick))
        .route("/cervo/report", get(cervo_report))
        .route("/cervo/status", get(cervo_status))
        .route("/ccos/ingest", post(ccos_ingest))
        .route("/ccos/recall", post(ccos_recall))
        .route("/ccos/stats", get(ccos_stats))
        .route("/ccos/verify", get(ccos_verify))
        .route("/ccos/ping", get(ccos_ping))
        .route("/octa/ingest", post(octa_ingest))
        .route("/octa/recall", post(octa_recall))
        .route("/octa/explain", post(octa_explain))
        .route("/octa/stats", get(octa_stats))
        .route("/octa/feedback", post(octa_feedback))
        .route("/octa/ping", get(octa_ping))
        // INV-NET-4: fail closed. The `/octa/*` and `/ccos/*` routes read
        // and write memory state.
        .layer(soul_cors::CorsPolicy::from_env(CORS_ALLOWLIST_VAR).read_write_layer())
        .with_state(state.clone())
        // axum Router<()> can be merged only after applying AppState above.
        .merge(ollama_chat::router()?);

    // WS endpoint on :9022
    let ws_app = Router::new()
        .route("/ws", get(ws_handler))
        .with_state(state);

    let rest_listener = tokio::net::TcpListener::bind("127.0.0.1:9023").await?;
    let ws_listener = tokio::net::TcpListener::bind("127.0.0.1:9022").await?;

    tracing::info!("REST API listening on :9023");
    tracing::info!("WebSocket listening on :9022");

    tokio::select! {
        r = axum::serve(rest_listener, rest_app) => r?,
        r = axum::serve(ws_listener, ws_app) => r?,
    }

    Ok(())
}
