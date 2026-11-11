//! AsyncTool trait — the interface every tool must implement.

use thiserror::Error;

/// Errors that can occur during tool execution.
#[derive(Debug, Error)]
pub enum ToolError {
    #[error("Validation failed: {0}")]
    ValidationFailed(String),
    #[error("Execution failed: {0}")]
    ExecutionFailed(String),
    #[error("Timeout after {0}s")]
    Timeout(u64),
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    #[error("Tool not found: {0}")]
    NotFound(String),
}

/// Result of a tool execution.
#[derive(Debug, Clone)]
pub struct ToolResult {
    /// Tool name that produced this result.
    pub tool: String,
    /// Exit code (0 = success).
    pub exit_code: i32,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
    /// Duration in milliseconds.
    pub duration_ms: u64,
}

impl ToolResult {
    pub fn success(tool: impl Into<String>, stdout: impl Into<String>) -> Self {
        Self {
            tool: tool.into(),
            exit_code: 0,
            stdout: stdout.into(),
            stderr: String::new(),
            duration_ms: 0,
        }
    }

    pub fn is_success(&self) -> bool {
        self.exit_code == 0
    }
}

/// The AsyncTool trait — every tool implements validate + execute.
// async_trait emits #[must_use] on the generated Future, whose Result output
// already carries #[must_use]. This is a macro expansion false positive in
// Clippy 1.99 (double_must_use), not an ignored Result at a call site.
#[allow(clippy::double_must_use)]
#[async_trait::async_trait]
pub trait AsyncTool: Send + Sync {
    /// Name of the tool.
    fn name(&self) -> &str;

    /// Validate input before execution. Returns Ok(()) or Err with reason.
    fn validate(&self, input: &str) -> Result<(), ToolError>;

    /// Execute the tool asynchronously.
    async fn execute(&self, input: &str) -> Result<ToolResult, ToolError>;
}

/// A simple no-op tool for testing.
pub struct NoOpTool;

#[async_trait::async_trait]
impl AsyncTool for NoOpTool {
    fn name(&self) -> &str {
        "noop"
    }

    fn validate(&self, _input: &str) -> Result<(), ToolError> {
        Ok(())
    }

    async fn execute(&self, input: &str) -> Result<ToolResult, ToolError> {
        Ok(ToolResult::success("noop", input))
    }
}
