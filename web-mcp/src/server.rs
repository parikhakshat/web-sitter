//! The MCP server: implements `rmcp`'s `ServerHandler` trait over a workspace root.
//!
//! `WebMcpServer` holds the batch-built `Workspace`/`ReverseSymbolIndex` (see
//! `crate::index`) and the combined `ToolRouter` assembled from every `tools/*.rs`
//! module's own `#[tool_router]` impl block. Phase 1 scope: read-only, single-shard,
//! built once at startup — no live updates yet (Phase 2).

use std::path::PathBuf;
use std::sync::Arc;

use rmcp::ServerHandler;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};
use rmcp::tool_handler;
use web_ql::Workspace;
use web_ql::symbol_index::ReverseSymbolIndex;

/// `workspace`/`reverse_index` are `Arc`-wrapped so `WebMcpServer` stays cheaply
/// `Clone` (rmcp clones the handler per connection) without deep-copying the whole
/// indexed codebase. Phase 1 never mutates them after startup; Phase 2's live-update
/// system is what will need interior mutability (sharded locks), not this wrapper.
#[derive(Clone)]
pub struct WebMcpServer {
    #[allow(dead_code)]
    pub(crate) workspace_root: PathBuf,
    pub(crate) workspace: Arc<Workspace>,
    pub(crate) reverse_index: Arc<ReverseSymbolIndex>,
    pub(crate) tool_router: ToolRouter<Self>,
}

impl WebMcpServer {
    pub fn new(
        workspace_root: PathBuf,
        workspace: Workspace,
        reverse_index: ReverseSymbolIndex,
    ) -> Self {
        Self {
            workspace_root,
            workspace: Arc::new(workspace),
            reverse_index: Arc::new(reverse_index),
            tool_router: Self::lookup_tool_router(),
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
