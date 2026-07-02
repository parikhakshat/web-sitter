//! The MCP server: implements `rmcp`'s `ServerHandler` trait over a workspace root.
//!
//! This is Phase 1's skeleton — an empty tool registry (`list_tools` uses the default
//! `Ok(ListToolsResult::default())`, i.e. no tools yet) that completes the MCP
//! `initialize` handshake over stdio. Tools (lookup, call-graph, dataflow, change-impact,
//! anonymized-context, verification) are added file-by-file in subsequent tasks; this
//! struct is where their `#[tool]` methods will live.

use std::path::PathBuf;

use rmcp::ServerHandler;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};

/// The MCP server's top-level state. `workspace_root` is the directory this server
/// indexes — currently unused by any tool (there are none yet), but threaded through
/// from `main.rs` now so later tasks don't need to touch the CLI wiring again.
#[derive(Clone)]
pub struct WebMcpServer {
    #[allow(dead_code)]
    workspace_root: PathBuf,
}

impl WebMcpServer {
    pub fn new(workspace_root: PathBuf) -> Self {
        Self { workspace_root }
    }
}

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
