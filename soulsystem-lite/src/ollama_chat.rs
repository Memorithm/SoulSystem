//! Authenticated, opt-in SoulSystem Lite → Ollama conversation bridge.
//!
//! The local Ollama server owns model scheduling, context sizing, decoding,
//! concurrency, and retention. Clients can choose the Ollama model and native
//! options at each request. No forced 160-token, 2K-context, eight-thread or
//! keep_alive=0 policy: omitted options use Ollama/model defaults.
//!
//! Security, not model policy: an explicit host-local bearer credential is
//! mandatory, and requests go to a fixed, non-redirecting loopback endpoint.
use axum::{
    body::Body,
    extract::{DefaultBodyLimit, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use soul_auth::TokenAuth;
use std::time::Duration;

const TOKEN_ENV: &str = "SOULSYSTEM_LITE_CHAT_TOKEN";
const MODEL_ENV: &str = "SOULSYSTEM_LITE_OLLAMA_MODEL";
const TIMEOUT_ENV: &str = "SOULSYSTEM_LITE_OLLAMA_TIMEOUT_SECS";
const BODY_LIMIT_ENV: &str = "SOULSYSTEM_LITE_CHAT_MAX_BODY_BYTES";
const OLLAMA_CHAT_ENDPOINT: &str = "http://127.0.0.1:11434/api/chat";

#[derive(Clone)]
struct ChatState {
    auth: TokenAuth,
    default_model: Option<String>,
    client: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct AskRequest {
    prompt: String,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    system: Option<String>,
    #[serde(default)]
    options: Option<Value>,
    #[serde(default)]
    keep_alive: Option<Value>,
    #[serde(default)]
    think: Option<Value>,
    #[serde(default)]
    format: Option<Value>,
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

fn selected_model(state: &ChatState, requested: Option<&Value>) -> Result<String, ApiError> {
    let name = match requested {
        Some(Value::String(name)) => Some(name.as_str()),
        Some(_) => return Err(err(StatusCode::BAD_REQUEST, "invalid_model")),
        None => state.default_model.as_deref(),
    };
    name.filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "model_required"))
}

fn validate_messages(value: &Value) -> bool {
    value.as_array().is_some_and(|messages| {
        !messages.is_empty()
            && messages.iter().all(|m| {
                m.as_object().is_some_and(|obj| {
                    obj.get("role").and_then(Value::as_str).is_some()
                        && obj.get("content").is_some()
                })
            })
    })
}

fn authorization(state: &ChatState, headers: &HeaderMap) -> Result<(), ApiError> {
    let supplied = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok());
    if state.auth.authenticate_header(supplied).is_some() {
        Ok(())
    } else {
        Err(err(StatusCode::UNAUTHORIZED, "unauthorized"))
    }
}

fn build_payload(state: &ChatState, mut input: Map<String, Value>) -> Result<Value, ApiError> {
    let requested = input.remove("model");
    let model = selected_model(state, requested.as_ref())?;
    let valid = input.get("messages").is_some_and(validate_messages);
    if !valid {
        return Err(err(StatusCode::BAD_REQUEST, "messages_required"));
    }
    // Streaming is optional. Ollama's normal JSON response is the default.
    if let Some(v) = input.get("stream") {
        if !v.is_boolean() {
            return Err(err(StatusCode::BAD_REQUEST, "invalid_stream"));
        }
    } else {
        input.insert("stream".into(), Value::Bool(false));
    }
    input.insert("model".into(), Value::String(model));
    Ok(Value::Object(input))
}

fn configured_router() -> anyhow::Result<Option<(ChatState, usize)>> {
    let token = std::env::var(TOKEN_ENV).unwrap_or_default();
    if token.is_empty() {
        tracing::info!("SoulSystem Lite Ollama chat disabled; no chat token configured");
        return Ok(None);
    }
    if token.trim().len() < 32 {
        anyhow::bail!("SoulSystem Lite chat requires a strong host-local bearer token");
    }
    let default_model = std::env::var(MODEL_ENV).ok().filter(|x| !x.trim().is_empty());
    let timeout = std::env::var(TIMEOUT_ENV)
        .ok().and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(600);
    let body_limit = std::env::var(BODY_LIMIT_ENV)
        .ok().and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(32 * 1024 * 1024);
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5));
    if timeout > 0 {
        builder = builder.timeout(Duration::from_secs(timeout));
    }
    let client = builder.build()?;
    tracing::info!(default_model = ?default_model,
        "SoulSystem Lite Ollama chat enabled; model and decoding controlled by client");
    Ok(Some((
        ChatState {
            auth: TokenAuth::from_pairs([("operator", &token)]),
            default_model,
            client,
        },
        body_limit,
    )))
}

pub fn router() -> anyhow::Result<Router> {
    let Some((state, body_limit)) = configured_router()? else {
        return Ok(Router::new());
    };
    Ok(Router::new()
        .route("/v1/ask", post(ask))
        .route("/v1/chat", post(chat))
        .layer(DefaultBodyLimit::max(body_limit))
        .with_state(state))
}

async fn call_ollama(state: &ChatState, payload: &Value) -> Result<reqwest::Response, ApiError> {
    let response = state.client
        .post(OLLAMA_CHAT_ENDPOINT)
        .json(payload)
        .send()
        .await
        .map_err(|_| err(StatusCode::BAD_GATEWAY, "ollama_unreachable"))?;
    if !response.status().is_success() {
        return Err(err(StatusCode::BAD_GATEWAY, "ollama_request_failed"));
    }
    Ok(response)
}

async fn ask(
    State(state): State<ChatState>,
    headers: HeaderMap,
    Json(request): Json<AskRequest>,
) -> Result<Json<AskResponse>, ApiError> {
    authorization(&state, &headers)?;
    if request.prompt.trim().is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "empty_prompt"));
    }
    let mut messages = Vec::new();
    if let Some(system) = request.system {
        messages.push(json!({"role": "system", "content": system}));
    }
    messages.push(json!({"role": "user", "content": request.prompt}));
    let mut input = Map::new();
    input.insert("messages".into(), Value::Array(messages));
    if let Some(model) = request.model {
        input.insert("model".into(), Value::String(model));
    }
    for (key, opt) in [
        ("options", request.options),
        ("keep_alive", request.keep_alive),
        ("think", request.think),
        ("format", request.format),
    ] {
        if let Some(value) = opt {
            input.insert(key.into(), value);
        }
    }
    let payload = build_payload(&state, input)?;
    let response = call_ollama(&state, &payload).await?;
    let data: Value = response.json().await
        .map_err(|_| err(StatusCode::BAD_GATEWAY, "ollama_invalid_response"))?;
    let answer = data.pointer("/message/content")
        .and_then(Value::as_str).unwrap_or("");
    if answer.is_empty() {
        return Err(err(StatusCode::BAD_GATEWAY, "ollama_empty_answer"));
    }
    Ok(Json(AskResponse {
        response: answer.to_owned(),
        model: data.get("model").and_then(Value::as_str)
            .unwrap_or_default().to_owned(),
        prompt_tokens: data.get("prompt_eval_count").and_then(Value::as_u64).unwrap_or(0),
        completion_tokens: data.get("eval_count").and_then(Value::as_u64).unwrap_or(0),
    }))
}

async fn chat(
    State(state): State<ChatState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    authorization(&state, &headers)?;
    let input = body.as_object().cloned()
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "invalid_chat_body"))?;
    let payload = build_payload(&state, input)?;
    let streaming = payload.get("stream").and_then(Value::as_bool).unwrap_or(false);
    let response = call_ollama(&state, &payload).await?;
    if streaming {
        // Preserve native Ollama NDJSON streaming without buffering tokens.
        return Ok((
            [(header::CONTENT_TYPE, "application/x-ndjson")],
            Body::from_stream(response.bytes_stream()),
        ).into_response());
    }
    let answer: Value = response.json().await
        .map_err(|_| err(StatusCode::BAD_GATEWAY, "ollama_invalid_response"))?;
    Ok(Json(answer).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_state() -> ChatState {
        ChatState {
            auth: TokenAuth::from_pairs([("test", "a".repeat(40))]),
            default_model: Some("gemma4:e2b".into()),
            client: reqwest::Client::new(),
        }
    }

    #[test]
    fn model_override_and_native_options_are_preserved() {
        let state = sample_state();
        let value = build_payload(&state, json!({
            "model": "hf.co/InternScience/Agents-A1-Q4_K_M-GGUF:Q4_K_M",
            "messages": [{"role":"user","content":"bonjour"}],
            "options": {"num_ctx": 131072, "num_predict": -1, "num_thread": 32},
            "keep_alive": "1h",
            "think": true,
            "stream": true
        }).as_object().unwrap().clone()).unwrap();
        assert_eq!(value["options"]["num_ctx"], 131072);
        assert_eq!(value["options"]["num_predict"], -1);
        assert_eq!(value["options"]["num_thread"], 32);
        assert_eq!(value["keep_alive"], "1h");
        assert_eq!(value["stream"], true);
        assert_eq!(value["think"], true);
        assert_eq!(value["model"], "hf.co/InternScience/Agents-A1-Q4_K_M-GGUF:Q4_K_M");
    }

    #[test]
    fn default_model_has_no_forced_inference_limits() {
        let value = build_payload(&sample_state(), json!({
            "messages": [{"role": "user", "content": "bonjour"}]
        }).as_object().unwrap().clone()).unwrap();
        assert_eq!(value["model"], "gemma4:e2b");
        assert_eq!(value["stream"], false);
        assert!(value.get("keep_alive").is_none());
        assert!(value.get("options").is_none());
    }

    #[test]
    fn rejects_only_malformed_requests() {
        let state = sample_state();
        assert!(build_payload(&state, Map::new()).is_err());
        assert!(build_payload(&state, json!({"messages": []})
            .as_object().unwrap().clone()).is_err());
        assert!(build_payload(&state, json!({"model": 10,
            "messages": [{"role":"user","content":"test"}]})
            .as_object().unwrap().clone()).is_err());
        assert!(state.auth.authenticate_header(None).is_none());
    }
}
