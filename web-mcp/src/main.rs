mod callgraph;
mod index;
mod server;
// Not wired into WebMcpServer yet: every tool handler still reads from crate::index's
// batch-built, all-in-memory Workspace. Swapping tools over to LiveWorkspace (so they see
// live edits) is follow-up integration work beyond this phase's per-piece tasks — store
// and watcher are exercised by their own unit/integration tests in the meantime.
#[allow(dead_code)]
mod store;
mod symbol_query;
mod tools;
#[allow(dead_code)]
mod watcher;

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use rmcp::ServiceExt;
use rmcp::transport::stdio;
use server::WebMcpServer;

/// Default location of the built-in CWE rule corpus, resolved relative to this crate's
/// own manifest directory at compile time (`web-mcp/` and `web-ql-queries/` are sibling
/// workspace members) — works regardless of the caller's current directory without
/// requiring `--rules-dir` for the common case of running against this repo's own rules.
const DEFAULT_RULES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../web-ql-queries");

/// web-mcp: a deterministic memory and verification layer for coding agents, exposed
/// over the Model Context Protocol via stdio. See `docs/mcp-server-design.md` in the
/// repo root for the full design.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// Root directory of the codebase this server indexes.
    #[arg(long, default_value = ".")]
    root: PathBuf,

    /// Directory for the on-disk fact store / cache (Phase 2+; unused until then).
    #[arg(long)]
    cache_dir: Option<PathBuf>,

    /// Directory of `.wql` rule files `run_security_scan` runs by default (one
    /// subdirectory per language, or a flat directory of `.wql` files). Missing or
    /// unreadable is non-fatal — the server still starts, with an empty built-in rule
    /// set (custom `rule_source` per call still works).
    #[arg(long, default_value = DEFAULT_RULES_DIR)]
    rules_dir: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber_init();

    let cli = Cli::parse();
    let root = cli.root.canonicalize().unwrap_or(cli.root);
    tracing::info!(root = %root.display(), "indexing workspace");

    let (workspace, reverse_index) = index::build_workspace(&root)?;
    tracing::info!(
        files = workspace.files.len(),
        symbols = reverse_index.symbol_count(),
        "workspace indexed, starting web-mcp"
    );

    let security_rules = index::load_builtin_rules(&cli.rules_dir).unwrap_or_else(|e| {
        tracing::warn!(
            rules_dir = %cli.rules_dir.display(),
            error = %e,
            "failed to load built-in rule corpus; run_security_scan will only support \
             custom rule_source until this is fixed"
        );
        web_ql::RuleSet::merge(Vec::new())
    });
    tracing::info!(
        rules = security_rules.rules.len(),
        "built-in rule corpus loaded"
    );

    let server = WebMcpServer::new(root, workspace, reverse_index, security_rules)
        .serve(stdio())
        .await
        .inspect_err(|e| tracing::error!("serving error: {e:?}"))?;

    server.waiting().await?;
    Ok(())
}

/// stderr-only logging — stdout is the MCP transport and must carry nothing but
/// protocol frames.
fn tracing_subscriber_init() {
    use tracing_subscriber::EnvFilter;
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();
}
