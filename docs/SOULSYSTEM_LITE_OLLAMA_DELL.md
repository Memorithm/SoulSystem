# SoulSystem Lite ↔ Ollama — Dell T430

SoulSystem Lite exposes an optional **authenticated** conversational interface
in its existing loopback REST service, port 9023. It does not launch a second
agent or install a second inference runtime. Ollama remains local to the Dell
on `127.0.0.1:11434`.

## Chosen default model

`ornith:9b` — a model already present in Ollama's on-host model inventory
(2026-11-11). The vendor lists a ~5.6-GB 9B agentic/coding model. This is
a choice for a CPU-only Dell; it is **not** a measured benchmark win over
other installed models. Model loading occurs only on first request; Ollama's
native idle-eviction behavior is preserved.

## Host-local credential

The endpoint is **disabled** unless the SoulSystem Lite *process* has
`SOULSYSTEM_LITE_CHAT_TOKEN` set to a non-empty strong secret (32+ chars).
The value must come from a root-owned host-local environment file or protected
runtime credential and **never** from the repository or GitHub workflow logs.

Optional environment settings:

| Variable | Default | Purpose |
| --- | --- | --- |
| `SOULSYSTEM_LITE_OLLAMA_MODEL` | `ornith:9b` | Change the preferred model if needed |
| `SOULSYSTEM_LITE_OLLAMA_TIMEOUT_SECS` | `600` | Maximum HTTP waiting time; `0` means no client timeout |
| `SOULSYSTEM_LITE_CHAT_MAX_BODY_BYTES` | `33554432` | Maximum request body size for protecting the API |

The listening address remains `127.0.0.1:9023`. Bearer authentication
uses the shared SoulSystem `soul-auth` constant-time credential verifier.
The Ollama client does not use proxy variables or follow redirects to
external hosts.

## Examples (run locally on Dell with an already-provisioned token)

Single question (the selected default model):

```bash
curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer ${SOULSYSTEM_LITE_CHAT_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data '{"prompt":"Bonjour SoulSystem. Décris brièvement ton rôle."}' \
  http://127.0.0.1:9023/v1/ask
```

Extended multi-turn dialogue using Ollama's message and option schema:

```bash
curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer ${SOULSYSTEM_LITE_CHAT_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data '{"messages":[{"role":"system","content":"Tu es SoulSystem."},{"role":"user","content":"Quel est ton rôle ?"}],"options":{"num_ctx":8192},"keep_alive":"5m"}' \
  http://127.0.0.1:9023/v1/chat
```

For native NDJSON streaming, supply `"stream":true` to `/v1/chat`.

No model-specific cap on `num_predict`, `num_ctx`, `num_thread`,
or `keep_alive` is imposed by this bridge. When omitted, Ollama/model
defaults take effect. Larger contexts and models can increase memory use
substantially. `/v1/chat` forwards the caller's native Ollama payload
over the fixed local endpoint; it does not expose OS tools or arbitrary
network targets.

## Acceptance criteria

1. Preflight verifies Dell model tag, physical memory headroom, running
   Ollama and the exact SoulSystem Lite executable/service.
2. Build/test the exact SoulSystem commit and inspect failed tests before
   touching the running service.
3. Back up the existing binary and systemd unit, install with rollback
   on failure, and provision the bearer secret in host-local storage.
4. Confirm unauthenticated `/v1/ask` is denied, legitimate
   `/v1/ask` returns nonempty generated text tagged `ornith:9b`,
   and existing `/health`, CERVO, CCOS, OctaSoma endpoints remain
   responsive.
5. Stop or roll back the new service if real generation cannot be
   confirmed; do **not** report a mere HTTP 200 as working conversation.

This route attaches Ollama inference to **SoulSystem Lite**, the actual
installed service. It does **not** automatically turn that lightweight
service into the complete SoulSystem autonomous coding agent; it does
not yet provide automatic retrieval from the CCOS/OctaSoma bridges.
