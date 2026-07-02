mod callgraph;
mod index;
mod server;
mod symbol_query;
mod tools;

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use rmcp::ServiceExt;
use rmcp::transport::stdio;
use server::WebMcpServer;

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

    let server = WebMcpServer::new(root, workspace, reverse_index)
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
