//! Call-graph tools: `get_callers`, `get_callees` (both transitive, bounded by
//! `max_depth`), and `call_path_exists` (boolean + witness path). Backed by
//! `crate::callgraph::SymbolCallGraph`, built once at startup alongside the
//! `ReverseSymbolIndex` (see `crate::index`).

use rmcp::Json;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::server::WebMcpServer;
use crate::symbol_query::resolve_symbol;

fn default_max_depth() -> u32 {
    5
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetCallersRequest {
    /// Same accepted forms as find_definition's `symbol`.
    pub symbol: String,
    /// Maximum number of call-graph hops to traverse. Defaults to 5.
    #[serde(default = "default_max_depth")]
    pub max_depth: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetCalleesRequest {
    /// Same accepted forms as find_definition's `symbol`.
    pub symbol: String,
    /// Maximum number of call-graph hops to traverse. Defaults to 5.
    #[serde(default = "default_max_depth")]
    pub max_depth: u32,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct CallGraphNode {
    pub symbol_id: String,
    /// Number of call-graph hops from the queried symbol.
    pub depth: u32,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct CallGraphResponse {
    pub symbol_id: String,
    pub nodes: Vec<CallGraphNode>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CallPathExistsRequest {
    /// Same accepted forms as find_definition's `symbol`.
    pub from: String,
    /// Same accepted forms as find_definition's `symbol`.
    pub to: String,
    /// Maximum number of call-graph hops to search. Defaults to 5.
    #[serde(default = "default_max_depth")]
    pub max_depth: u32,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct CallPathExistsResponse {
    pub exists: bool,
    /// The shortest witness path from `from` to `to` (inclusive of both endpoints), or
    /// empty if `exists` is false.
    pub path: Vec<String>,
}

#[tool_router(router = callgraph_tool_router, vis = "pub(crate)")]
impl WebMcpServer {
    #[tool(
        name = "get_callers",
        description = "Transitive callers of a symbol, up to max_depth call-graph hops \
                        (default 5). Accepts the same symbol forms as find_definition."
    )]
    pub async fn get_callers(
        &self,
        Parameters(req): Parameters<GetCallersRequest>,
    ) -> Result<Json<CallGraphResponse>, String> {
        let reverse_index = self.reverse_index.load_full();
        let call_graph = self.call_graph.load_full();
        let Some((symbol_id, _def)) = resolve_symbol(&reverse_index, &req.symbol)
            .into_iter()
            .next()
        else {
            return Err(format!("no definition found for '{}'", req.symbol));
        };

        let nodes = call_graph
            .transitive_callers(symbol_id, req.max_depth as usize)
            .into_iter()
            .map(|(id, depth)| CallGraphNode {
                symbol_id: id.as_str().to_string(),
                depth,
            })
            .collect();
        Ok(Json(CallGraphResponse {
            symbol_id: symbol_id.as_str().to_string(),
            nodes,
        }))
    }

    #[tool(
        name = "get_callees",
        description = "Transitive callees of a symbol, up to max_depth call-graph hops \
                        (default 5). Accepts the same symbol forms as find_definition."
    )]
    pub async fn get_callees(
        &self,
        Parameters(req): Parameters<GetCalleesRequest>,
    ) -> Result<Json<CallGraphResponse>, String> {
        let reverse_index = self.reverse_index.load_full();
        let call_graph = self.call_graph.load_full();
        let Some((symbol_id, _def)) = resolve_symbol(&reverse_index, &req.symbol)
            .into_iter()
            .next()
        else {
            return Err(format!("no definition found for '{}'", req.symbol));
        };

        let nodes = call_graph
            .transitive_callees(symbol_id, req.max_depth as usize)
            .into_iter()
            .map(|(id, depth)| CallGraphNode {
                symbol_id: id.as_str().to_string(),
                depth,
            })
            .collect();
        Ok(Json(CallGraphResponse {
            symbol_id: symbol_id.as_str().to_string(),
            nodes,
        }))
    }

    #[tool(
        name = "call_path_exists",
        description = "Check whether `from` can reach `to` via the call graph within \
                        max_depth hops (default 5). Returns a boolean plus the shortest \
                        witness path as evidence — never a bare true/false with no trace."
    )]
    pub async fn call_path_exists(
        &self,
        Parameters(req): Parameters<CallPathExistsRequest>,
    ) -> Result<Json<CallPathExistsResponse>, String> {
        let reverse_index = self.reverse_index.load_full();
        let call_graph = self.call_graph.load_full();
        let Some((from_id, _)) = resolve_symbol(&reverse_index, &req.from).into_iter().next()
        else {
            return Err(format!("no definition found for '{}'", req.from));
        };
        let Some((to_id, _)) = resolve_symbol(&reverse_index, &req.to).into_iter().next() else {
            return Err(format!("no definition found for '{}'", req.to));
        };

        let path = call_graph.shortest_path(from_id, to_id, req.max_depth as usize);
        Ok(Json(CallPathExistsResponse {
            exists: path.is_some(),
            path: path
                .unwrap_or_default()
                .into_iter()
                .map(|id| id.as_str().to_string())
                .collect(),
        }))
    }
}
