//! Opt-in, loopback-only SoulSystem Lite → local Ollama conversational adapter.
//!
//! The caller cannot choose a provider, model, endpoint or tool. Credentials
//! remain local to the SoulSystem Lite process. Each request unloads its model
//! immediately afterwards (Ollama keep_alive=0) and at most one request runs.
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{header, HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use soul_auth::TokenAuth;
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;

const MAX_PROMPT_CHARS: usize = 1_024;
const MODEL_ENV: &str = "SOULSYSTEM_LITE_OLLAMA_MODEL";
const TOKEN_ENV: &str = "SOULSYSTEM_LITE_CHAT_TOKEN";
const SYSTEM_PROMPT: &str = "Tu es l'interface conversationnelle de SoulSystem Lite. Tu réponds de façon concise, exacte et en français. Tu utilises un modèle local Ollama. Tu n'as pas accès à des outils d'exécution et tu ne dois pas prétendre avoir modifié le système ou observé des données que tu ne connais pas.";

#[derive(Clone)]
struct ChatState {
    auth: TokenAuth,
    model: Arc<str>,
    client: reqwest::Client,
    permit: Arc<Semaphore>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AskRequest {
    prompt: String,
}

#[derive(Serialize)]
struct AskResponse {
    response: String,
    model: String,
    prompt_tokens: u64,
    completion_tokens: u64,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
}

type ApiError = (StatusCode, Json<ErrorResponse>);

fn err(code: StatusCode, message: &'static str) -> ApiError {
    (code, Json(ErrorResponse { error: message }))
}

fn model_is_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 160
        && !name.ends_with(":cloud")
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"./_:-".contains(&b))
}

fn validate_prompt(prompt: &str) -> bool {
    !prompt.trim().is_empty() && prompt.chars().count() <= MAX_PROMPT_CHARS
}

fn chat_from_env() -> anyhow::Result<Option<ChatState>> {
    let token = std::env::var(TOKEN_ENV).unwrap_or_default();
    let model = std::env::var(MODEL_ENV).unwrap_or_default();
    if token.is_empty() && model.is_empty() {
        tracing::info!("SoulSystem Lite Ollama chat disabled (no host-local configuration)");
        return Ok(None);
    }
    if token.len() < 32 || !model_is_valid(&model) {
        anyhow::bail!("SoulSystem Lite chat requires a strong local token and an explicit local model");
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(90))
        .build()?;
    tracing::info!(model = %model, "SoulSystem Lite local Ollama chat enabled");
    Ok(Some(ChatState {
        auth: TokenAuth::from_pairs([("remoteops", &token)]),
        model: Arc::from(model),
        client,
        permit: Arc::new(Semaphore::new(1)),
    }))
}

pub fn router() -> anyhow::Result<Router> {
    let Some(state) = chat_from_env()? else {
        return Ok(Router::new());
    };
    Ok(Router::new()
        .route("/v1/ask", post(ask))
        .layer(DefaultBodyLimit::max(4_096))
        .with_state(state))
}

async fn ask(
    State(state): State<ChatState>,
    headers: HeaderMap,
    Json(request): Json<AskRequest>,
) -> Result<Json<AskResponse>, ApiError> {
    let supplied = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok());
    if state.auth.authenticate_header(supplied).is_none() {
        return Err(err(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    if !validate_prompt(&request.prompt) {
        return Err(err(StatusCode::BAD_REQUEST, "invalid_prompt"));
    }
    // Fail fast instead of queueing unbounded inference requests.
    let _permit = state.permit.try_acquire()
        .map_err(|_| err(StatusCode::TOO_MANY_REQUESTS, "inference_busy"))?;

    // Fixed loopback endpoint: the HTTP request cannot be redirected off-host.
    let url = "http://127.0.0.1:11434/api/chat";
    let payload = serde_json::json!({
        "model": state.model.as_ref(),
        "stream": false,
        "keep_alive": 0,
        "messages": [
            { "role": "system", "content": SYSTEM_PROMPT },
            { "role": "user", "content": request.prompt }
        ],
        "options": {
            "num_predict": 160,
            "num_ctx": 2048,
            "num_thread": 8,
            "temperature": 0.2
        }
    });

    let response = state.client.post(url)
        .json(&payload)
        .send().await
        .map_err(|_| err(StatusCode::BAD_GATEWAY, "ollama_unreachable"))?;
    if !response.status().is_success() {
        return Err(err(StatusCode::BAD_GATEWAY, "ollama_model_unavailable"));
    }
    let result: serde_json::Value = response.json().await
        .map_err(|_| err(StatusCode::BAD_GATEWAY, "ollama_invalid_response"))?;
    let answer = result.pointer("/message/content")
        .and_then(serde_json::Value::as_str).unwrap_or("");
    if answer.trim().is_empty() {
        return Err(err(StatusCode::BAD_GATEWAY, "ollama_empty_answer"));
    }
    Ok(Json(AskResponse {
        response: answer.to_owned(),
        model: state.model.to_string(),
        prompt_tokens: result.get("prompt_eval_count").and_then(serde_json::Value::as_u64).unwrap_or(0),
        completion_tokens: result.get("eval_count").and_then(serde_json::Value::as_u64).unwrap_or(0),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_rejects_unsafe_or_cloud_targets() {
        assert!(model_is_valid("gemma4:e2b"));
        assert!(model_is_valid("hf.co/InternScience/Agents-A1-Q4_K_M-GGUF:Q4_K_M"));
        assert!(!model_is_valid("nemotron-3-super:cloud"));
        assert!(!model_is_valid("http://remote-host/model"));
        assert!(!model_is_valid(" model"));
        assert!(!model_is_valid(""));
    }

    #[test]
    fn prompt_is_bounded() {
        assert!(validate_prompt("Bonjour SoulSystem"));
        assert!(!validate_prompt(" "));
        assert!(!validate_prompt(&"x".repeat(MAX_PROMPT_CHARS + 1)));
    }

    #[test]
    fn bearer_is_fail_closed() {
        let auth = TokenAuth::from_pairs([("remoteops", "a".repeat(40))]);
        assert!(auth.authenticate_header(Some(&format!("Bearer {}", "a".repeat(40)))).is_some());
        assert!(auth.authenticate_header(None).is_none());
        assert!(auth.authenticate_header(Some("Bearer wrong")).is_none());
    }
}
