//! Claim-checking verification tools (Pillar 2, tier 1): `verify_edge`, `explain_path`,
//! `taint_path`. These answer "is this specific fact true?" against the live CPG/call
//! graph/DFG and always return the concrete evidence (a witness path or edge chain)
//! alongside the boolean — never a bare true/false with no trace, per the design's
//! "verifiable, not inferred" principle.
//!
//! Scope for this task: `verify_edge`/`explain_path` support the `calls` (direct call
//! edge) and `reaches` (transitive call-graph reachability) claim kinds — the two most
//! immediately useful "did I get the call graph right" checks, backed by the already-built
//! `SymbolCallGraph`. `dominates`/`reads`/`writes` claim kinds need CFG dominator-tree
//! and def/use-site plumbing not yet exposed and are left for a follow-up task rather than
//! faked. `taint_path` covers intra-file DFG witness paths (consistent with
//! `dfg_reaches`'s Phase 1 intra-file scope).

use std::collections::{HashMap, HashSet, VecDeque};

use rmcp::Json;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use web_sitter::NodeId;

use crate::server::WebMcpServer;
use crate::symbol_query::resolve_symbol;
use crate::tools::dataflow::Location;

/// Claim kinds `verify_edge`/`explain_path` currently support. `dominates`/`reads`/
/// `writes` are documented gaps (see module docs), not silently ignored.
const SUPPORTED_KINDS: &[&str] = &["calls", "reaches"];

fn default_reaches_depth() -> u32 {
    // "reaches" is meant as an unbounded-feeling claim check ("can A eventually call
    // B?"), unlike call_path_exists's explicit tunable max_depth — 64 hops comfortably
    // exceeds any real call chain without risking runaway BFS cost.
    64
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VerifyEdgeRequest {
    /// "calls" (direct call edge) or "reaches" (transitive call-graph reachability).
    pub kind: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct VerifyEdgeResponse {
    pub exists: bool,
    /// Witness call chain from `from` to `to` (inclusive), empty if `exists` is false.
    pub witness: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExplainPathRequest {
    /// "calls" (direct call edge) or "reaches" (transitive call-graph reachability).
    pub kind: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct PathHop {
    pub symbol_id: String,
    pub file: String,
    pub line: u32,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ExplainPathResponse {
    pub hops: Vec<PathHop>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TaintPathRequest {
    pub from: Location,
    pub to: Location,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct TaintEdgeStep {
    pub variable: String,
    pub from_line: u32,
    pub from_column: u32,
    pub to_line: u32,
    pub to_column: u32,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct TaintPathResponse {
    pub reaches: bool,
    /// The concrete DFG edge chain from `from` to `to`, empty if `reaches` is false.
    pub edges: Vec<TaintEdgeStep>,
}

#[tool_router(router = verify_tool_router, vis = "pub(crate)")]
impl WebMcpServer {
    #[tool(
        name = "verify_edge",
        description = "Check a specific claim against the live call graph: does `from` \
                        directly call `to` (kind=calls), or can `from` transitively reach \
                        `to` (kind=reaches)? Returns the boolean plus a witness call chain \
                        as evidence — never a bare true/false."
    )]
    pub async fn verify_edge(
        &self,
        Parameters(req): Parameters<VerifyEdgeRequest>,
    ) -> Result<Json<VerifyEdgeResponse>, String> {
        if !SUPPORTED_KINDS.contains(&req.kind.as_str()) {
            return Err(format!(
                "unsupported verify_edge kind '{}': only {:?} are implemented",
                req.kind, SUPPORTED_KINDS
            ));
        }
        let from = self.resolve_required(&req.from)?;
        let to = self.resolve_required(&req.to)?;

        let max_depth = if req.kind == "calls" {
            1
        } else {
            default_reaches_depth() as usize
        };
        let witness = self
            .call_graph
            .load_full()
            .shortest_path(&from, &to, max_depth);

        Ok(Json(VerifyEdgeResponse {
            exists: witness.is_some(),
            witness: witness
                .unwrap_or_default()
                .into_iter()
                .map(|id| id.as_str().to_string())
                .collect(),
        }))
    }

    #[tool(
        name = "explain_path",
        description = "Full node-by-node evidence for how `from` reaches `to` in the call \
                        graph (kind=calls for a direct edge, kind=reaches for a transitive \
                        path), including each hop's source location. Errors if no such path \
                        exists — use verify_edge first if existence itself is in question."
    )]
    pub async fn explain_path(
        &self,
        Parameters(req): Parameters<ExplainPathRequest>,
    ) -> Result<Json<ExplainPathResponse>, String> {
        if !SUPPORTED_KINDS.contains(&req.kind.as_str()) {
            return Err(format!(
                "unsupported explain_path kind '{}': only {:?} are implemented",
                req.kind, SUPPORTED_KINDS
            ));
        }
        let from = self.resolve_required(&req.from)?;
        let to = self.resolve_required(&req.to)?;
        let reverse_index = self.reverse_index.load_full();
        let workspace = self.workspace.load_full();

        let max_depth = if req.kind == "calls" {
            1
        } else {
            default_reaches_depth() as usize
        };
        let path = self
            .call_graph
            .load_full()
            .shortest_path(&from, &to, max_depth)
            .ok_or_else(|| format!("no {} path from '{}' to '{}'", req.kind, req.from, req.to))?;

        let hops = path
            .into_iter()
            .filter_map(|symbol_id| {
                let def = reverse_index.definition(&symbol_id)?;
                let node = workspace.files.get(&def.file)?.cpg.ast.get(&def.node_id)?;
                Some(PathHop {
                    symbol_id: symbol_id.as_str().to_string(),
                    file: def.file.display().to_string(),
                    line: node.line,
                })
            })
            .collect();

        Ok(Json(ExplainPathResponse { hops }))
    }

    #[tool(
        name = "taint_path",
        description = "The concrete intra-file DFG edge chain (variable-by-variable) from \
                        one source position to another, if dataflow reaches between them. \
                        Like dfg_reaches but returns the witness path instead of a bare \
                        boolean — evidence for a taint claim, not just a yes/no."
    )]
    pub async fn taint_path(
        &self,
        Parameters(req): Parameters<TaintPathRequest>,
    ) -> Result<Json<TaintPathResponse>, String> {
        if req.from.file != req.to.file {
            return Err(
                "taint_path only supports intra-file queries in Phase 1; from.file and \
                 to.file must match"
                    .to_string(),
            );
        }
        let path = self.resolve_path(&req.from.file);
        let workspace = self.workspace.load_full();
        let idx = workspace
            .files
            .get(&path)
            .ok_or_else(|| format!("file not indexed: {}", req.from.file))?;

        let from_id =
            crate::tools::dataflow::find_node_at(&idx.cpg, req.from.line, req.from.column)
                .ok_or_else(|| {
                    format!(
                        "no node at {}:{}:{}",
                        req.from.file, req.from.line, req.from.column
                    )
                })?;
        let to_id = crate::tools::dataflow::find_node_at(&idx.cpg, req.to.line, req.to.column)
            .ok_or_else(|| {
                format!(
                    "no node at {}:{}:{}",
                    req.to.file, req.to.line, req.to.column
                )
            })?;

        let mut edge_variable: HashMap<(NodeId, NodeId), String> = HashMap::new();
        for edge in &idx.cpg.dataflow.edges {
            edge_variable
                .entry((edge.source, edge.destination))
                .or_insert_with(|| edge.variable.clone());
        }

        let path_nodes = bfs_path(&idx.dfg.forward, from_id, to_id);
        let edges = path_nodes
            .map(|nodes| {
                nodes
                    .windows(2)
                    .filter_map(|pair| {
                        let (from_node, to_node) = (pair[0], pair[1]);
                        let from_ast = idx.cpg.ast.get(&from_node)?;
                        let to_ast = idx.cpg.ast.get(&to_node)?;
                        Some(TaintEdgeStep {
                            variable: edge_variable
                                .get(&(from_node, to_node))
                                .cloned()
                                .unwrap_or_default(),
                            from_line: from_ast.line,
                            from_column: from_ast.column,
                            to_line: to_ast.line,
                            to_column: to_ast.column,
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Ok(Json(TaintPathResponse {
            reaches: !edges.is_empty() || from_id == to_id,
            edges,
        }))
    }
}

impl WebMcpServer {
    fn resolve_required(&self, query: &str) -> Result<web_sitter::symbol_id::SymbolId, String> {
        resolve_symbol(&self.reverse_index.load(), query)
            .into_iter()
            .next()
            .map(|(id, _)| id.clone())
            .ok_or_else(|| format!("no definition found for '{query}'"))
    }
}

/// Plain BFS over a forward adjacency map, returning the shortest node path (inclusive
/// of both endpoints) from `from` to `to`, or `None` if unreachable. `from == to` yields
/// a single-node path.
fn bfs_path(
    forward: &HashMap<NodeId, Vec<NodeId>>,
    from: NodeId,
    to: NodeId,
) -> Option<Vec<NodeId>> {
    if from == to {
        return Some(vec![from]);
    }
    let mut visited: HashSet<NodeId> = HashSet::from([from]);
    let mut queue: VecDeque<NodeId> = VecDeque::from([from]);
    let mut predecessor: HashMap<NodeId, NodeId> = HashMap::new();

    while let Some(current) = queue.pop_front() {
        let Some(neighbors) = forward.get(&current) else {
            continue;
        };
        for &neighbor in neighbors {
            if !visited.insert(neighbor) {
                continue;
            }
            predecessor.insert(neighbor, current);
            if neighbor == to {
                let mut path = vec![to];
                let mut cursor = to;
                while let Some(&pred) = predecessor.get(&cursor) {
                    path.push(pred);
                    cursor = pred;
                }
                path.reverse();
                return Some(path);
            }
            queue.push_back(neighbor);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bfs_path_finds_shortest_route() {
        let mut forward = HashMap::new();
        forward.insert(1, vec![2]);
        forward.insert(2, vec![3]);
        assert_eq!(bfs_path(&forward, 1, 3), Some(vec![1, 2, 3]));
    }

    #[test]
    fn bfs_path_none_when_unreachable() {
        let mut forward = HashMap::new();
        forward.insert(1, vec![2]);
        assert_eq!(bfs_path(&forward, 1, 99), None);
    }

    #[test]
    fn bfs_path_trivial_for_same_node() {
        let forward = HashMap::new();
        assert_eq!(bfs_path(&forward, 5, 5), Some(vec![5]));
    }
}
