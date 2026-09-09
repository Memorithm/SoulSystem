//! Contracts for the canonical SoulSystem coding harness.
//!
//! This crate owns the canonical coding-harness path: task contracts, Git
//! worktree identity, typed tool dispatch, sandboxed commands, model turns,
//! and evidence-based finalization. Keeping each side effect behind a small
//! boundary lets callers embed the same runtime in a CLI, daemon, or REPL.

#![deny(unsafe_code)]

pub mod agent;
pub mod command;
pub mod contract;
pub mod feedback;
pub mod git;
pub mod mcp;
pub mod runner;
pub mod runtime;
pub mod session;
pub mod tools;
pub mod verify;
pub mod workspace;

pub use agent::{AgentError, CodingAgent, CodingAgentConfig, CodingAgentEvent};
pub use command::{CommandArg, CommandSpec, CommandSpecError};
pub use contract::{
    ChangeKind, ChangeSet, CheckResult, CheckSpec, CompletionError, TaskResult, TaskSpec,
    TaskStatus,
};
pub use feedback::{CodingFeedback, FeedbackError, FeedbackKind, PreferenceScope};
pub use git::{GitError, GitWorkspace};
pub use runner::{CommandOutput, CommandRunner, RunnerError, SandboxCommandRunner};
pub use runtime::{CodingRuntime, RuntimeError};
pub use session::{SessionError, SessionRecord, SessionStore, SESSION_SCHEMA_VERSION};
pub use soullink_gate::ExecutionMode;
pub use tools::{coding_tool_schemas, ApprovalHandler, CodingToolExecutor, ToolExecutionResult};
pub use verify::{VerificationReport, Verifier};
pub use workspace::{WorkspaceContext, WorkspaceError};

/// Provider hosts used by the coding CLI. The concrete providers append their
/// protocol path (`/v1/...`) themselves, so callers should pass the host root.
pub fn default_provider_base_url(provider: soul_llm::ProviderKind) -> &'static str {
    match provider {
        soul_llm::ProviderKind::Ollama => "http://127.0.0.1:11434",
        soul_llm::ProviderKind::OpenAI => "https://api.openai.com",
        soul_llm::ProviderKind::Anthropic => "https://api.anthropic.com",
    }
}

/// Normalize a user-supplied provider URL to the host-root form expected by
/// the provider adapters. This prevents `/v1/v1/...` when a user copies a
/// conventional OpenAI-compatible base URL from another client.
pub fn normalize_provider_base_url(
    provider: soul_llm::ProviderKind,
    base_url: impl AsRef<str>,
) -> String {
    let mut base_url = base_url.as_ref().trim_end_matches('/').to_string();
    if matches!(
        provider,
        soul_llm::ProviderKind::OpenAI | soul_llm::ProviderKind::Anthropic
    ) && base_url.ends_with("/v1")
    {
        base_url.truncate(base_url.len() - 3);
        base_url = base_url.trim_end_matches('/').to_string();
    }
    base_url
}

#[cfg(test)]
mod provider_url_tests {
    use super::*;

    #[test]
    fn provider_urls_are_host_roots() {
        assert_eq!(
            default_provider_base_url(soul_llm::ProviderKind::OpenAI),
            "https://api.openai.com"
        );
        assert_eq!(
            normalize_provider_base_url(
                soul_llm::ProviderKind::Anthropic,
                "https://api.anthropic.com/v1/"
            ),
            "https://api.anthropic.com"
        );
    }
}
