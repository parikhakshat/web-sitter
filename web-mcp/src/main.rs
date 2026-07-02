mod callgraph;
mod index;
mod live_index;
mod security;
mod server;
// Several pieces of the storage layer (per-shard revision/lock accessors, snapshot
// save/load, WorkspaceStore's own hot/persisted-length introspection) are reserved public
// API not yet consumed by the live wiring above — e.g. per-tool revision-stamping
// (the original design's "every response carries the revision it was computed against")
// and per-shard-scoped reads are real, deliberate future steps, not oversights. Each
// piece has its own unit/integration test coverage already.
#[allow(dead_code)]
mod store;
mod symbol_query;
mod tools;
mod watcher;

use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use live_index::LiveIndex;
use rmcp::ServiceExt;
use rmcp::transport::stdio;
use server::WebMcpServer;
use store::live_workspace::LiveWorkspace;

/// Default location of the built-in CWE rule corpus, resolved relative to this crate's
/// own manifest directory at compile time (`web-mcp/` and `web-ql-queries/` are sibling
/// workspace members) — works regardless of the caller's current directory without
/// requiring `--rules-dir` for the common case of running against this repo's own rules.
const DEFAULT_RULES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../web-ql-queries");

/// When `--cache-dir` isn't given, derive a stable per-root location under the OS temp
/// directory instead of writing into the scanned repo — same root canonicalizes to the
/// same path every time, so the findings store (and, later, the on-disk fact store)
/// actually persists across restarts as the design requires, without needing the caller
/// to remember to pass a flag.
fn default_cache_dir(root: &std::path::Path) -> PathBuf {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    root.hash(&mut hasher);
    std::env::temp_dir()
        .join("web-mcp")
        .join(format!("{:x}", hasher.finish()))
}

/// web-mcp: a deterministic memory and verification layer for coding agents, exposed
/// over the Model Context Protocol via stdio. See `docs/mcp-server-design.md` in the
/// repo root for the full design.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// Root directory of the codebase this server indexes.
    #[arg(long, default_value = ".")]
    root: PathBuf,

    /// Directory for on-disk state: the findings store and the live-update fact store
    /// (per-file `Cpg` cache + incremental-parse snapshots). Defaults to a stable
    /// per-root location under the OS temp directory (see `default_cache_dir`) when
    /// omitted.
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

    let cache_dir = cli
        .cache_dir
        .clone()
        .unwrap_or_else(|| default_cache_dir(&root));
    std::fs::create_dir_all(&cache_dir)
        .with_context(|| format!("creating cache directory {}", cache_dir.display()))?;
    let findings_store = store::findings::FindingsStore::open(cache_dir.join("findings.redb"))
        .context("opening findings store")?;
    tracing::info!(cache_dir = %cache_dir.display(), "findings store opened");

    let server = WebMcpServer::new(
        root.clone(),
        workspace,
        reverse_index,
        security_rules,
        findings_store,
    );

    // Grab handles to the live-swappable query state *before* handing `server` to
    // `.serve()` — `LiveIndex` publishes new snapshots through these; every clone of
    // `server` (rmcp clones the handler per connection) sees them on its next read.
    let workspace_handle = server.workspace_handle();
    let reverse_index_handle = server.reverse_index_handle();
    let call_graph_handle = server.call_graph_handle();

    let live_workspace = Arc::new(
        LiveWorkspace::open(
            cache_dir.join("live.redb"),
            root.clone(),
            NonZeroUsize::new(store::DEFAULT_HOT_CAPACITY)
                .expect("DEFAULT_HOT_CAPACITY is a nonzero constant"),
            cache_dir.join("snapshots"),
        )
        .context("opening live workspace")?,
    );

    // Warm-restart every file the initial batch build already indexed, so the first edit
    // to any of them can use LiveWorkspace's incremental path instead of a cold full
    // parse (see store::live_workspace's content-hash-equivalent validity check).
    let initial_files: Vec<PathBuf> = workspace_handle
        .read()
        .await
        .files
        .keys()
        .cloned()
        .collect();
    let mut warm_hits = 0usize;
    for file in &initial_files {
        match live_workspace.warm_restart_file(file) {
            Ok(true) => warm_hits += 1,
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(file = %file.display(), error = %e, "warm restart failed for a file already in the batch index");
            }
        }
    }
    tracing::info!(
        files = initial_files.len(),
        warm_hits,
        "live workspace warm-restarted"
    );

    let live_index = Arc::new(LiveIndex::new(
        live_workspace,
        workspace_handle,
        reverse_index_handle,
        call_graph_handle,
    ));

    // Kept alive for the rest of `main` (never dropped early) — dropping the `Debouncer`
    // stops watching. `rx` is moved into the spawned pipeline task below.
    let (_watcher_guard, rx) =
        watcher::watch(&root, watcher::DEFAULT_DEBOUNCE).context("starting file watcher")?;
    tokio::spawn(watcher::run_pipeline(Arc::clone(&live_index), rx));
    tracing::info!(root = %root.display(), "file watcher started; live updates active");

    let server = server
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
