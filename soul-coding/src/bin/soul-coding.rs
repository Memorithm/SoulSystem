//! Command-line entry point for the canonical SoulSystem coding harness.
//!
//! This binary intentionally exposes one execution path: create a detached
//! Git worktree, run the provider-agnostic coding loop, and print an
//! evidence-bearing result. Provider credentials are read from the existing
//! environment/credential conventions; they are never accepted as a CLI
//! argument that could land in shell history.

use clap::{Parser, ValueEnum};
use soul_coding::{
    CheckSpec, CodingAgent, CodingAgentEvent, CodingTaskEnvelopeV1, GitWorkspace, SessionStore,
    TaskResult, TaskSpec, TaskStatus,
};
use soul_llm::{LlmClient, LlmConfig, ProviderKind};
use soul_sandbox::SandboxPolicy;
use soullink_gate::ExecutionMode;
use soulsystem_common::secrets::SecretString;
use std::{fs, path::PathBuf};
use tokio::sync::mpsc;

#[derive(Debug, Parser)]
#[command(
    name = "soul-coding",
    about = "Run the canonical SoulSystem coding harness in an isolated Git worktree"
)]
struct Args {
    /// Repository to modify. The worktree is created below this directory.
    #[arg(long, default_value = ".")]
    repo: PathBuf,

    /// Revision from which the detached coding worktree is created.
    #[arg(long, default_value = "HEAD")]
    base_revision: String,

    /// Natural-language coding task.
    #[arg(long)]
    prompt: Option<String>,

    /// Versioned provider-neutral task envelope (`soulsystem.coding-task/v1`).
    /// Mutually exclusive with `--prompt` and `--check` for new sessions.
    #[arg(long, value_name = "FILE")]
    task_json: Option<PathBuf>,

    /// Required shell-free acceptance check, repeated as NAME=COMMAND.
    /// Commands are whitespace-separated argv; shell pipes and separators are
    /// rejected by the verifier.
    #[arg(long = "check", value_name = "NAME=COMMAND")]
    checks: Vec<String>,

    /// Optional stable session identity. A UUID is generated when omitted.
    #[arg(long)]
    session_id: Option<String>,

    /// Resume an existing session and its detached worktree.
    #[arg(long)]
    resume: bool,

    /// LLM provider: ollama, openai, or anthropic.
    #[arg(long, default_value = "ollama")]
    provider: String,

    /// Provider model name. Required for OpenAI and Anthropic.
    #[arg(long)]
    model: Option<String>,

    /// Provider host base URL. OpenAI/Anthropic accept an optional trailing /v1.
    #[arg(long)]
    base_url: Option<String>,

    /// Approval/sandbox mode. Autonomous blocks critical operations.
    #[arg(long, value_enum, default_value_t = ModeArg::Autonomous)]
    mode: ModeArg,

    /// Print only the final JSON result on stdout.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ModeArg {
    Interactive,
    Autonomous,
    Container,
}

impl ModeArg {
    fn execution_mode(self) -> ExecutionMode {
        match self {
            Self::Interactive => ExecutionMode::Interactive,
            Self::Autonomous => ExecutionMode::Autonomous,
            Self::Container => ExecutionMode::Container,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let provider: ProviderKind = args.provider.parse()?;
    if provider != ProviderKind::Ollama && args.model.is_none() {
        return Err(format!("--model is required for the {provider} provider").into());
    }
    let store = SessionStore::new(&args.repo)?;
    let (task, workspace) = if args.resume {
        if args.prompt.is_some() || args.task_json.is_some() || !args.checks.is_empty() {
            return Err(
                "--resume cannot be combined with --prompt, --task-json, or --check".into(),
            );
        }
        let session_id = args
            .session_id
            .as_deref()
            .ok_or("--resume requires --session-id")?;
        let record = store
            .load(session_id)?
            .ok_or_else(|| format!("session not found: {session_id}"))?;
        let workspace = GitWorkspace::open(
            &args.repo,
            record.workspace().base_revision().to_string(),
            session_id.to_string(),
            SandboxPolicy::default(),
        )?;
        (record.task().clone(), workspace)
    } else {
        let task = load_new_task(&args)?;
        let session_id = args
            .session_id
            .clone()
            .unwrap_or_else(|| format!("session-{}", uuid::Uuid::new_v4()));
        let workspace = GitWorkspace::create(
            &args.repo,
            args.base_revision.clone(),
            session_id,
            SandboxPolicy::default(),
        )?;
        (task, workspace)
    };

    let mut config = LlmConfig {
        provider,
        base_url: soul_coding::normalize_provider_base_url(
            provider,
            args.base_url
                .as_deref()
                .unwrap_or(soul_coding::default_provider_base_url(provider)),
        ),
        ..LlmConfig::default()
    };
    if let Some(model) = args.model {
        config.model = model;
    }
    config.auth_token = provider_token(provider);
    let client = LlmClient::new(config)?;
    let mut agent = CodingAgent::new(
        client,
        Default::default(),
        SandboxPolicy::default(),
        args.mode.execution_mode(),
    );
    if matches!(args.mode, ModeArg::Interactive) {
        agent.enable_interactive_approval_prompt();
    }
    agent.set_session_store(store);

    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    agent.set_event_sender(event_tx);
    let json_output = args.json;
    let event_task = tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            if !json_output {
                print_event(event);
            }
        }
    });

    let result = agent.run(&task, &workspace).await;
    drop(agent);
    let _ = event_task.await;
    let result = result?;
    print_result(&result, &workspace, args.json)?;

    if result.status != TaskStatus::Completed {
        std::process::exit(2);
    }
    Ok(())
}

fn load_new_task(args: &Args) -> Result<TaskSpec, Box<dyn std::error::Error>> {
    if let Some(path) = &args.task_json {
        if args.prompt.is_some() || !args.checks.is_empty() {
            return Err("--task-json cannot be combined with --prompt or --check".into());
        }
        let payload = fs::read_to_string(path)?;
        return Ok(CodingTaskEnvelopeV1::from_json(&payload)?.into_task_spec()?);
    }

    let prompt = args
        .prompt
        .clone()
        .ok_or("a new session requires exactly one of --prompt or --task-json")?;
    let checks = args
        .checks
        .iter()
        .map(|raw| parse_check(raw))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(TaskSpec::new(prompt, checks)?)
}

fn parse_check(raw: &str) -> Result<CheckSpec, String> {
    let (name, command) = raw
        .split_once('=')
        .ok_or_else(|| format!("check must use NAME=COMMAND syntax: {raw:?}"))?;
    CheckSpec::required(name, command, 300).map_err(|error| error.to_string())
}

fn provider_token(provider: ProviderKind) -> Option<SecretString> {
    let variable = match provider {
        ProviderKind::Ollama => "SOULSYSTEM_LLM_API_KEY",
        ProviderKind::OpenAI => "OPENAI_API_KEY",
        ProviderKind::Anthropic => "ANTHROPIC_API_KEY",
    };
    std::env::var(variable)
        .ok()
        .or_else(|| {
            soulsystem_common::secrets::resolve_llm_secret(&provider.to_string())
                .map(|secret| secret.as_str().to_owned())
        })
        .map(SecretString::new)
}

fn print_event(event: CodingAgentEvent) {
    match event {
        CodingAgentEvent::TurnStarted { turn } => eprintln!("turn {turn}"),
        CodingAgentEvent::ModelResponse { content } => {
            if !content.trim().is_empty() {
                eprintln!("model: {content}");
            }
        }
        CodingAgentEvent::ToolCall { name } => eprintln!("tool: {name}"),
        CodingAgentEvent::ToolResult { name, success } => {
            eprintln!(
                "tool result: {name} ({})",
                if success { "ok" } else { "failed" }
            );
        }
        CodingAgentEvent::Verification { status } => eprintln!("verification: {status:?}"),
    }
}

fn print_result(
    result: &TaskResult,
    workspace: &GitWorkspace<soul_coding::SandboxCommandRunner>,
    json: bool,
) -> Result<(), serde_json::Error> {
    if json {
        println!("{}", serde_json::to_string_pretty(result)?);
        return Ok(());
    }

    println!("status: {:?}", result.status);
    println!("summary: {}", result.summary);
    println!("worktree: {}", workspace.context().worktree().display());
    if let Some(reason) = &result.failure_reason {
        println!("reason: {reason}");
    }
    println!(
        "checks: {}/{} passed",
        result.checks.iter().filter(|check| check.passed).count(),
        result.checks.len()
    );
    Ok(())
}
