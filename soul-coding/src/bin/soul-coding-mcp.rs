//! MCP stdio entry point for Cline, OpenCode, Command Code, and other MCP hosts.

use clap::{Parser, ValueEnum};
use soul_coding::mcp::{serve_stdio, McpServer};
use soul_sandbox::SandboxPolicy;
use soullink_gate::ExecutionMode;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "soul-coding-mcp",
    about = "Expose the canonical SoulSystem coding harness as an MCP stdio server"
)]
struct Args {
    /// Git repository in which isolated SoulSystem worktrees are created.
    #[arg(long, default_value = ".")]
    repo: PathBuf,

    /// Default revision used by soul_start_task when none is supplied.
    #[arg(long, default_value = "HEAD")]
    base_revision: String,

    /// Approval mode for MCP tool execution. Interactive mode is intentionally
    /// unavailable because MCP owns stdin; autonomous blocks critical actions.
    #[arg(long, value_enum, default_value_t = ModeArg::Autonomous)]
    mode: ModeArg,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ModeArg {
    Autonomous,
    Container,
}

impl ModeArg {
    fn execution_mode(self) -> ExecutionMode {
        match self {
            Self::Autonomous => ExecutionMode::Autonomous,
            Self::Container => ExecutionMode::Container,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let server = McpServer::new(
        args.repo,
        args.base_revision,
        args.mode.execution_mode(),
        SandboxPolicy::default(),
    )?;
    serve_stdio(server).await?;
    Ok(())
}
