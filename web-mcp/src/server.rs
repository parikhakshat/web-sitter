//! The MCP server: implements `rmcp`'s `ServerHandler` trait over a workspace root.
//!
//! `WebMcpServer` holds the live `Workspace`/`ReverseSymbolIndex`/`SymbolCallGraph` (see
//! `crate::index` for the initial batch build, `crate::live_index::LiveIndex` for how
//! they get atomically republished as file-watcher events come in) and the combined
//! `ToolRouter` assembled from every `tools/*.rs` module's own `#[tool_router]` impl
//! block.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::ArcSwap;
use rmcp::ServerHandler;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};
use rmcp::tool_handler;
use tokio::sync::RwLock;
use web_ql::RuleSet;
use web_ql::Workspace;
use web_ql::symbol_index::ReverseSymbolIndex;

use crate::callgraph::SymbolCallGraph;
use crate::store::findings::FindingsStore;

/// `reverse_index`/`call_graph` are `Arc<ArcSwap<T>>`: a live-update source
/// (`crate::live_index::LiveIndex`, holding clones of the same handles via `*_handle()`
/// below) rebuilds each fresh from scratch on every edit and atomically publishes the new
/// owned value — `ArcSwap` fits perfectly since there's never an existing value to mutate
/// in place. `workspace` is different: `Workspace` isn't (and can't cheaply be) `Clone` —
/// it owns a `HashMap` of every indexed file's full `FileIndex` — so a live update
/// *mutates it in place* (`Workspace::upsert_file`/`build_cross_file_edges`) rather than
/// swapping in a freshly-constructed replacement, which needs a lock, not `ArcSwap`
/// (`ArcSwap` only supports atomically replacing the whole value, not mutating through
/// it). `Arc<RwLock<Workspace>>` gives every tool call concurrent read access (the common
/// case) while `LiveIndex` takes a write lock only for the duration of applying one edit.
///
/// `WebMcpServer` stays cheaply `Clone` (rmcp clones the handler per connection) either
/// way, since cloning any of the three just bumps a refcount.
#[derive(Clone)]
pub struct WebMcpServer {
    pub(crate) workspace_root: PathBuf,
    pub(crate) workspace: Arc<RwLock<Workspace>>,
    pub(crate) reverse_index: Arc<ArcSwap<ReverseSymbolIndex>>,
    pub(crate) call_graph: Arc<ArcSwap<SymbolCallGraph>>,
    /// The built-in CWE rule corpus (`web-ql-queries/`), loaded once at startup —
    /// `run_security_scan` clones out of this `Arc` when no custom `rule_source` is
    /// given, instead of recompiling 52 `.wql` files on every call.
    pub(crate) security_rules: Arc<RuleSet>,
    /// Durable open/fixed/suppressed status tracking for security findings — survives
    /// server restarts (see `store::findings`).
    pub(crate) findings_store: Arc<FindingsStore>,
    /// Monotonic counter stamped onto every `run_security_scan` call as its
    /// `FindingRecord::last_seen_revision` — Phase 1's `Workspace` has no live-update
    /// revision of its own yet (see `crate::index`), so this is a scan-count surrogate
    /// good enough to answer "was this finding seen in the most recent scan."
    pub(crate) scan_revision: Arc<AtomicU64>,
    pub(crate) tool_router: ToolRouter<Self>,
}

impl WebMcpServer {
    /// Resolve a user-supplied file path (as typed into a tool argument) against
    /// `workspace_root`. `Workspace::files` is keyed by the absolute paths produced
    /// during indexing (`crate::index::build_workspace` walks from a canonicalized
    /// root), so a relative path an agent types — the common case — must be joined
    /// against the same root before it can look anything up. Already-absolute paths
    /// pass through unchanged.
    pub(crate) fn resolve_path(&self, file: &str) -> PathBuf {
        let path = PathBuf::from(file);
        if path.is_absolute() {
            path
        } else {
            self.workspace_root.join(path)
        }
    }

    /// Advance and return the scan-count surrogate revision (see `scan_revision`'s doc
    /// comment) — called once per `run_security_scan` invocation.
    pub(crate) fn next_scan_revision(&self) -> u64 {
        self.scan_revision.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn new(
        workspace_root: PathBuf,
        workspace: Workspace,
        reverse_index: ReverseSymbolIndex,
        security_rules: RuleSet,
        findings_store: FindingsStore,
    ) -> Self {
        let call_graph = SymbolCallGraph::build(&workspace, &reverse_index);
        Self {
            workspace_root,
            workspace: Arc::new(RwLock::new(workspace)),
            reverse_index: Arc::new(ArcSwap::new(Arc::new(reverse_index))),
            call_graph: Arc::new(ArcSwap::new(Arc::new(call_graph))),
            security_rules: Arc::new(security_rules),
            findings_store: Arc::new(findings_store),
            scan_revision: Arc::new(AtomicU64::new(0)),
            tool_router: Self::lookup_tool_router()
                + Self::callgraph_tool_router()
                + Self::dataflow_tool_router()
                + Self::impact_tool_router()
                + Self::verify_tool_router()
                + Self::security_tool_router()
                + Self::findings_tool_router()
                + Self::variants_tool_router(),
        }
    }

    /// A clone of the `Arc<RwLock<Workspace>>` handle — for `live_index::LiveIndex` (not
    /// yet constructed from `main()` — hence `#[allow(dead_code)]`, expected to be dropped
    /// once the file-watcher pipeline wiring lands) to mutate in place as edits come in,
    /// visible to every clone of this `WebMcpServer` on its next read.
    #[allow(dead_code)]
    pub(crate) fn workspace_handle(&self) -> Arc<RwLock<Workspace>> {
        Arc::clone(&self.workspace)
    }

    #[allow(dead_code)]
    pub(crate) fn reverse_index_handle(&self) -> Arc<ArcSwap<ReverseSymbolIndex>> {
        Arc::clone(&self.reverse_index)
    }

    #[allow(dead_code)]
    pub(crate) fn call_graph_handle(&self) -> Arc<ArcSwap<SymbolCallGraph>> {
        Arc::clone(&self.call_graph)
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for WebMcpServer {
    fn get_info(&self) -> ServerInfo {
        // Deliberately not `Implementation::from_build_env()`: that helper expands
        // `env!("CARGO_CRATE_NAME")` inside *rmcp's own* source, so it always reports
        // "rmcp" regardless of which crate calls it — not useful for identifying this
        // server to a client.
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(
                "web-mcp: deterministic memory and verification layer for coding agents, \
                 backed by web-sitter/web-ql's incremental CPG and query engine.",
            )
            .with_server_info(Implementation::new("web-mcp", env!("CARGO_PKG_VERSION")))
    }
}
