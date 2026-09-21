//! Model Context Protocol (MCP) stdio adapter for the canonical coding harness.
//!
//! The adapter deliberately reuses `GitWorkspace`, `SessionStore`,
//! `CodingToolExecutor`, and `CodingRuntime`. MCP clients therefore do not gain
//! a second, less constrained path to the filesystem or command runner.

use crate::{
    coding_tool_schemas, CheckSpec, CodingRuntime, CodingToolExecutor, GitWorkspace,
    SandboxCommandRunner, SessionRecord, SessionStore, TaskSpec,
};
use serde::Deserialize;
use serde_json::{json, Value};
use soul_sandbox::SandboxPolicy;
use soul_tools::PermissionLevel;
use soullink_gate::ExecutionMode;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const MCP_LATEST_PROTOCOL_VERSION: &str = "2025-11-25";
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &[
    "2024-11-05",
    "2025-03-26",
    "2025-06-18",
    MCP_LATEST_PROTOCOL_VERSION,
];

pub struct McpServer {
    repo: PathBuf,
    default_base_revision: String,
    policy: SandboxPolicy,
    store: SessionStore,
    executor: CodingToolExecutor,
    negotiated: bool,
    initialized: bool,
    active: Option<ActiveSession>,
}

struct ActiveSession {
    workspace: GitWorkspace<SandboxCommandRunner>,
    record: SessionRecord,
}

impl McpServer {
    pub fn new(
        repo: impl AsRef<Path>,
        default_base_revision: impl Into<String>,
        mode: ExecutionMode,
        policy: SandboxPolicy,
    ) -> Result<Self, McpServerError> {
        if mode == ExecutionMode::Interactive {
            return Err(McpServerError::InteractiveStdio);
        }
        let default_base_revision = default_base_revision.into();
        if default_base_revision.trim().is_empty() {
            return Err(McpServerError::EmptyBaseRevision);
        }
        let store = SessionStore::new(repo)?;
        let repo = store.root().to_path_buf();
        let executor = CodingToolExecutor::new(policy.clone(), mode);
        Ok(Self {
            repo,
            default_base_revision,
            policy,
            store,
            executor,
            negotiated: false,
            initialized: false,
            active: None,
        })
    }

    pub async fn handle_line(&mut self, line: &str) -> Option<Value> {
        match serde_json::from_str::<Value>(line) {
            Ok(message) => self.handle_value(message).await,
            Err(error) => Some(error_response(
                Value::Null,
                -32700,
                "Parse error",
                Some(json!({"detail": error.to_string()})),
            )),
        }
    }

    pub async fn handle_value(&mut self, message: Value) -> Option<Value> {
        let Some(object) = message.as_object() else {
            return Some(error_response(
                Value::Null,
                -32600,
                "Invalid Request",
                None,
            ));
        };
        let id = object.get("id").cloned();
        let is_notification = id.is_none();
        if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return if is_notification {
                None
            } else {
                Some(error_response(
                    id.unwrap_or(Value::Null),
                    -32600,
                    "Invalid Request",
                    None,
                ))
            };
        }
        let Some(method) = object.get("method").and_then(Value::as_str) else {
            return if is_notification {
                None
            } else {
                Some(error_response(
                    id.unwrap_or(Value::Null),
                    -32600,
                    "Invalid Request",
                    None,
                ))
            };
        };

        match method {
            "initialize" => {
                if is_notification {
                    return None;
                }
                let Some(requested) = message
                    .pointer("/params/protocolVersion")
                    .and_then(Value::as_str)
                else {
                    return Some(error_response(
                        id.unwrap_or(Value::Null),
                        -32602,
                        "Invalid params",
                        Some(json!({"detail": "initialize requires params.protocolVersion"})),
                    ));
                };
                let version = negotiate_protocol_version(requested);
                self.negotiated = true;
                self.initialized = false;
                Some(success_response(
                    id.unwrap_or(Value::Null),
                    json!({
                        "protocolVersion": version,
                        "capabilities": {"tools": {"listChanged": false}},
                        "serverInfo": {
                            "name": "soul-coding",
                            "version": env!("CARGO_PKG_VERSION")
                        },
                        "instructions": "Start or resume a SoulSystem task before using coding tools. All mutations occur in the task's detached Git worktree; call soul_verify_task for evidence-based completion."
                    }),
                ))
            }
            "notifications/initialized" => {
                if self.negotiated {
                    self.initialized = true;
                }
                None
            }
            "ping" => {
                if is_notification {
                    None
                } else {
                    Some(success_response(id.unwrap_or(Value::Null), json!({})))
                }
            }
            "tools/list" => {
                if is_notification {
                    return None;
                }
                let id = id.unwrap_or(Value::Null);
                if !self.initialized {
                    return Some(not_initialized(id));
                }
                Some(success_response(id, json!({"tools": mcp_tool_schemas()})))
            }
            "tools/call" => {
                if is_notification {
                    return None;
                }
                let id = id.unwrap_or(Value::Null);
                if !self.initialized {
                    return Some(not_initialized(id));
                }
                Some(self.handle_tool_call(id, &message).await)
            }
            _ if is_notification => None,
            _ => Some(error_response(
                id.unwrap_or(Value::Null),
                -32601,
                "Method not found",
                Some(json!({"method": method})),
            )),
        }
    }

    async fn handle_tool_call(&mut self, id: Value, message: &Value) -> Value {
        let Some(name) = message.pointer("/params/name").and_then(Value::as_str) else {
            return error_response(
                id,
                -32602,
                "Invalid params",
                Some(json!({"detail": "tools/call requires params.name"})),
            );
        };
        let arguments = message
            .pointer("/params/arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        if !arguments.is_object() {
            return error_response(
                id,
                -32602,
                "Invalid params",
                Some(json!({"detail": "params.arguments must be an object"})),
            );
        }

        let result = match name {
            "soul_start_task" => self.start_task(arguments),
            "soul_resume_task" => self.resume_task(arguments),
            "soul_task_info" => self.task_info(),
            "soul_changes" => self.changes(),
            "soul_verify_task" => self.verify_task(),
            "read_file" | "write_file" | "patch_file" | "execute_shell" => {
                self.execute_coding_tool(name, arguments).await
            }
            _ => {
                return error_response(
                    id,
                    -32602,
                    "Invalid params",
                    Some(json!({"detail": format!("unknown tool: {name}")})),
                )
            }
        };

        success_response(
            id,
            match result {
                Ok(text) => tool_result(text, false),
                Err(error) => tool_result(error, true),
            },
        )
    }

    fn start_task(&mut self, arguments: Value) -> Result<String, String> {
        if self.active.is_some() {
            return Err(
                "an MCP coding session is already active; restart the server or finish the current session"
                    .to_string(),
            );
        }
        let args: StartTaskArgs =
            serde_json::from_value(arguments).map_err(|error| error.to_string())?;
        let checks = args
            .checks
            .into_iter()
            .map(McpCheckSpec::into_check_spec)
            .collect::<Result<Vec<_>, _>>()?;
        let task = TaskSpec::new(args.prompt, checks).map_err(|error| error.to_string())?;
        let session_id = args
            .session_id
            .unwrap_or_else(|| format!("mcp-{}", uuid::Uuid::new_v4()));
        let base_revision = args
            .base_revision
            .unwrap_or_else(|| self.default_base_revision.clone());
        let workspace = GitWorkspace::create(
            &self.repo,
            base_revision,
            session_id,
            self.policy.clone(),
        )
        .map_err(|error| error.to_string())?;
        let mut record = SessionRecord::new(task, workspace.context().clone());
        self.store
            .save(&mut record)
            .map_err(|error| error.to_string())?;
        let payload = session_payload(&record, &workspace, None);
        self.active = Some(ActiveSession { workspace, record });
        serde_json::to_string_pretty(&payload).map_err(|error| error.to_string())
    }

    fn resume_task(&mut self, arguments: Value) -> Result<String, String> {
        if self.active.is_some() {
            return Err(
                "an MCP coding session is already active; restart the server before resuming another session"
                    .to_string(),
            );
        }
        let args: ResumeTaskArgs =
            serde_json::from_value(arguments).map_err(|error| error.to_string())?;
        let record = self
            .store
            .load(&args.session_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("session not found: {}", args.session_id))?;
        let workspace = GitWorkspace::open(
            &self.repo,
            record.workspace().base_revision().to_string(),
            args.session_id,
            self.policy.clone(),
        )
        .map_err(|error| error.to_string())?;
        let payload = session_payload(&record, &workspace, None);
        self.active = Some(ActiveSession { workspace, record });
        serde_json::to_string_pretty(&payload).map_err(|error| error.to_string())
    }

    fn task_info(&self) -> Result<String, String> {
        let session = self.active.as_ref().ok_or_else(no_active_session)?;
        let payload = session_payload(
            &session.record,
            &session.workspace,
            session.record.last_result.as_ref(),
        );
        serde_json::to_string_pretty(&payload).map_err(|error| error.to_string())
    }

    fn changes(&self) -> Result<String, String> {
        let session = self.active.as_ref().ok_or_else(no_active_session)?;
        let changes = session
            .workspace
            .change_set()
            .map_err(|error| error.to_string())?;
        serde_json::to_string_pretty(&changes).map_err(|error| error.to_string())
    }

    fn verify_task(&mut self) -> Result<String, String> {
        let session = self.active.as_mut().ok_or_else(no_active_session)?;
        let task = session.record.task().clone();
        let runtime = CodingRuntime::new(SandboxCommandRunner::new(self.policy.clone()));
        let result = runtime
            .verify_workspace(&task, &session.workspace)
            .map_err(|error| error.to_string())?;
        session.record.record_result(result.clone());
        self.store
            .save(&mut session.record)
            .map_err(|error| error.to_string())?;
        serde_json::to_string_pretty(&result).map_err(|error| error.to_string())
    }

    async fn execute_coding_tool(
        &mut self,
        name: &str,
        arguments: Value,
    ) -> Result<String, String> {
        let session = self.active.as_mut().ok_or_else(no_active_session)?;
        let result = self
            .executor
            .execute(name, arguments, session.workspace.context())
            .await;
        let writes = !matches!(result.permission, PermissionLevel::Read);
        session.record.record_tool_call(writes);
        self.store
            .save(&mut session.record)
            .map_err(|error| error.to_string())?;
        if result.success {
            Ok(result.output)
        } else {
            Err(result.output)
        }
    }
}

pub async fn serve_stdio(mut server: McpServer) -> Result<(), McpServerError> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = io::BufWriter::new(stdout.lock());
    let mut line = String::new();

    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim_end_matches(&['\r', '\n'][..]);
        if let Some(response) = server.handle_line(line).await {
            serde_json::to_writer(&mut writer, &response)?;
            writer.write_all(b"\n")?;
            writer.flush()?;
        }
    }
    Ok(())
}

fn mcp_tool_schemas() -> Vec<Value> {
    let mut tools = vec![
        json!({
            "name": "soul_start_task",
            "description": "Create a persistent SoulSystem coding task in an isolated detached Git worktree. Call this before coding tools.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "prompt": {"type": "string", "minLength": 1},
                    "checks": {
                        "type": "array",
                        "minItems": 1,
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string", "minLength": 1},
                                "command": {"type": "string", "minLength": 1},
                                "required": {"type": "boolean", "default": true},
                                "timeout_secs": {"type": "integer", "minimum": 1, "default": 300}
                            },
                            "required": ["name", "command"],
                            "additionalProperties": false
                        }
                    },
                    "session_id": {"type": "string", "minLength": 1},
                    "base_revision": {"type": "string", "minLength": 1}
                },
                "required": ["prompt", "checks"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "soul_resume_task",
            "description": "Resume a previously persisted SoulSystem MCP coding task and its original detached worktree.",
            "inputSchema": {
                "type": "object",
                "properties": {"session_id": {"type": "string", "minLength": 1}},
                "required": ["session_id"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "soul_task_info",
            "description": "Return the active task, session identity, base revision, worktree, and last verification result.",
            "inputSchema": {"type": "object", "additionalProperties": false}
        }),
        json!({
            "name": "soul_changes",
            "description": "Collect the active worktree change set and reproducible diff hash.",
            "inputSchema": {"type": "object", "additionalProperties": false}
        }),
        json!({
            "name": "soul_verify_task",
            "description": "Run the declared acceptance checks and canonical evidence-based completion gate for the active task.",
            "inputSchema": {"type": "object", "additionalProperties": false}
        }),
    ];
    tools.extend(coding_tool_schemas().into_iter().map(|schema| {
        json!({
            "name": schema.name,
            "description": schema.description,
            "inputSchema": schema.parameters
        })
    }));
    tools
}

fn session_payload(
    record: &SessionRecord,
    workspace: &GitWorkspace<SandboxCommandRunner>,
    last_result: Option<&crate::TaskResult>,
) -> Value {
    json!({
        "session_id": workspace.context().session_id(),
        "task": record.task(),
        "worktree": workspace.context().worktree(),
        "base_revision": workspace.context().base_revision(),
        "last_status": record.last_status.as_ref(),
        "last_result": last_result
    })
}

fn negotiate_protocol_version(requested: &str) -> &str {
    SUPPORTED_PROTOCOL_VERSIONS
        .iter()
        .copied()
        .find(|version| *version == requested)
        .unwrap_or(MCP_LATEST_PROTOCOL_VERSION)
}

fn no_active_session() -> String {
    "no active SoulSystem coding task; call soul_start_task or soul_resume_task first".to_string()
}

fn tool_result(text: String, is_error: bool) -> Value {
    json!({
        "content": [{"type": "text", "text": text}],
        "isError": is_error
    })
}

fn success_response(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn error_response(id: Value, code: i64, message: &str, data: Option<Value>) -> Value {
    let mut error = json!({"code": code, "message": message});
    if let Some(data) = data {
        error["data"] = data;
    }
    json!({"jsonrpc": "2.0", "id": id, "error": error})
}

fn not_initialized(id: Value) -> Value {
    error_response(id, -32002, "Server not initialized", None)
}

#[derive(Debug, Deserialize)]
struct StartTaskArgs {
    prompt: String,
    checks: Vec<McpCheckSpec>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    base_revision: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ResumeTaskArgs {
    session_id: String,
}

#[derive(Debug, Deserialize)]
struct McpCheckSpec {
    name: String,
    command: String,
    #[serde(default = "default_required")]
    required: bool,
    #[serde(default = "default_check_timeout")]
    timeout_secs: u64,
}

impl McpCheckSpec {
    fn into_check_spec(self) -> Result<CheckSpec, String> {
        CheckSpec::new(self.name, self.command, self.required, self.timeout_secs)
            .map_err(|error| error.to_string())
    }
}

fn default_required() -> bool {
    true
}

fn default_check_timeout() -> u64 {
    300
}

#[derive(Debug, Error)]
pub enum McpServerError {
    #[error("MCP stdio cannot use interactive approval because stdin is reserved for JSON-RPC")]
    InteractiveStdio,
    #[error("default base revision cannot be empty")]
    EmptyBaseRevision,
    #[error(transparent)]
    Session(#[from] crate::SessionError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server() -> McpServer {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.keep();
        McpServer::new(
            path,
            "HEAD",
            ExecutionMode::Autonomous,
            SandboxPolicy::default(),
        )
        .unwrap()
    }

    async fn initialize(server: &mut McpServer, version: &str) {
        let response = server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": version,
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"}
                }
            }))
            .await
            .unwrap();
        assert_eq!(response["result"]["protocolVersion"], version);
        assert!(server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            }))
            .await
            .is_none());
    }

    #[tokio::test]
    async fn negotiates_supported_protocol_version() {
        let mut server = server();
        initialize(&mut server, "2025-11-25").await;
        assert!(server.initialized);
    }

    #[tokio::test]
    async fn falls_back_to_latest_for_unknown_protocol_version() {
        let mut server = server();
        let response = server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": "init",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2099-01-01",
                    "capabilities": {},
                    "clientInfo": {"name": "future", "version": "1"}
                }
            }))
            .await
            .unwrap();
        assert_eq!(
            response["result"]["protocolVersion"],
            MCP_LATEST_PROTOCOL_VERSION
        );
    }

    #[tokio::test]
    async fn lists_session_and_coding_tools_after_initialization() {
        let mut server = server();
        initialize(&mut server, MCP_LATEST_PROTOCOL_VERSION).await;
        let response = server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {}
            }))
            .await
            .unwrap();
        let names = response["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect::<Vec<_>>();
        assert!(names.contains(&"soul_start_task"));
        assert!(names.contains(&"soul_verify_task"));
        assert!(names.contains(&"read_file"));
        assert!(names.contains(&"write_file"));
        assert!(names.contains(&"patch_file"));
        assert!(names.contains(&"execute_shell"));
    }

    #[tokio::test]
    async fn coding_tool_requires_active_session() {
        let mut server = server();
        initialize(&mut server, MCP_LATEST_PROTOCOL_VERSION).await;
        let response = server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "README.md"}}
            }))
            .await
            .unwrap();
        assert_eq!(response["result"]["isError"], true);
        assert!(response["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("soul_start_task"));
    }

    #[tokio::test]
    async fn malformed_json_returns_parse_error() {
        let mut server = server();
        let response = server.handle_line("{not-json").await.unwrap();
        assert_eq!(response["error"]["code"], -32700);
        assert_eq!(response["id"], Value::Null);
    }
}
