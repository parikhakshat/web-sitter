//! The MCP server: implements `rmcp`'s `ServerHandler` trait over a workspace root.
//!
//! `WebMcpServer` holds the batch-built `Workspace`/`ReverseSymbolIndex` (see
//! `crate::index`) and the combined `ToolRouter` assembled from every `tools/*.rs`
//! module's own `#[tool_router]` impl block. Phase 1 scope: read-only, single-shard,
//! built once at startup — no live updates yet (Phase 2).

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rmcp::ServerHandler;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};
use rmcp::tool_handler;
use web_ql::RuleSet;
use web_ql::Workspace;
use web_ql::symbol_index::ReverseSymbolIndex;

use crate::callgraph::SymbolCallGraph;
use crate::store::findings::FindingsStore;

/// `workspace`/`reverse_index`/`call_graph` are `Arc`-wrapped so `WebMcpServer` stays
/// cheaply `Clone` (rmcp clones the handler per connection) without deep-copying the
/// whole indexed codebase. Phase 1 never mutates them after startup; Phase 2's
/// live-update system is what will need interior mutability (sharded locks), not this
/// wrapper.
#[derive(Clone)]
pub struct WebMcpServer {
    pub(crate) workspace_root: PathBuf,
    pub(crate) workspace: Arc<Workspace>,
    pub(crate) reverse_index: Arc<ReverseSymbolIndex>,
    pub(crate) call_graph: Arc<SymbolCallGraph>,
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
            workspace: Arc::new(workspace),
            reverse_index: Arc::new(reverse_index),
            call_graph: Arc::new(call_graph),
            security_rules: Arc::new(security_rules),
            findings_store: Arc::new(findings_store),
            scan_revision: Arc::new(AtomicU64::new(0)),
            tool_router: Self::lookup_tool_router()
                + Self::callgraph_tool_router()
                + Self::dataflow_tool_router()
                + Self::impact_tool_router()
                + Self::verify_tool_router()
                + Self::security_tool_router()
                + Self::findings_tool_router(),
        }
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
