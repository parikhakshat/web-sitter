//! Dataflow/structural tools: `dfg_reaches` (intra-file DFG reachability between two
//! source positions) and `query` (general ScuzzQL passthrough for ad-hoc structural
//! queries over the whole indexed workspace).

use rmcp::Json;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use web_sitter::{Cpg, NodeId};

use crate::server::WebMcpServer;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Location {
    pub file: String,
    pub line: u32,
    pub column: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DfgReachesRequest {
    pub from: Location,
    pub to: Location,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DfgReachesResponse {
    pub reaches: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct QueryRequest {
    /// ScuzzQL rule-file source text — one or more `rule "id" { ... }` blocks. See
    /// `web-ql-queries/` in the repo for real-world examples.
    pub rule_source: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct QueryFinding {
    pub rule_id: String,
    pub severity: String,
    pub message: String,
    pub tags: Vec<String>,
    pub file: String,
    pub line: u32,
    pub column: u32,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct QueryResponse {
    pub findings: Vec<QueryFinding>,
}

#[tool_router(router = dataflow_tool_router, vis = "pub(crate)")]
impl WebMcpServer {
    #[tool(
        name = "dfg_reaches",
        description = "Check whether dataflow reaches from one source position to another \
                        within the same file. Phase 1 scope: intra-file only — for \
                        cross-file interprocedural taint, use taint_path once verification \
                        tools land."
    )]
    pub async fn dfg_reaches(
        &self,
        Parameters(req): Parameters<DfgReachesRequest>,
    ) -> Result<Json<DfgReachesResponse>, String> {
        if req.from.file != req.to.file {
            return Err(
                "dfg_reaches only supports intra-file queries in Phase 1; from.file and \
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

        let from_id = find_node_at(&idx.cpg, req.from.line, req.from.column).ok_or_else(|| {
            format!(
                "no node at {}:{}:{}",
                req.from.file, req.from.line, req.from.column
            )
        })?;
        let to_id = find_node_at(&idx.cpg, req.to.line, req.to.column).ok_or_else(|| {
            format!(
                "no node at {}:{}:{}",
                req.to.file, req.to.line, req.to.column
            )
        })?;

        Ok(Json(DfgReachesResponse {
            reaches: idx.dfg.reaches(from_id, to_id),
        }))
    }

    #[tool(
        name = "query",
        description = "Run an ad-hoc ScuzzQL rule against the whole indexed workspace and \
                        return its findings. General structural/dataflow query passthrough \
                        for questions no fixed tool covers."
    )]
    pub async fn query(
        &self,
        Parameters(req): Parameters<QueryRequest>,
    ) -> Result<Json<QueryResponse>, String> {
        let rule_set = web_ql::compile_rules(&req.rule_source)
            .map_err(|e| format!("rule compile error: {e:#}"))?;
        let findings = self
            .workspace
            .load_full()
            .scan(&rule_set)
            .into_iter()
            .map(|f| {
                let severity = f.severity_str().to_string();
                QueryFinding {
                    rule_id: f.rule_id,
                    severity,
                    message: f.message,
                    tags: f.tags,
                    file: f.location.file,
                    line: f.location.line,
                    column: f.location.column,
                }
            })
            .collect();
        Ok(Json(QueryResponse { findings }))
    }
}

/// Find the most specific (smallest-span) AST node whose start position is exactly
/// `(line, column)`. Multiple nodes can share a start position (e.g. an identifier
/// nested at the start of a larger expression) — the smallest span is the closest
/// analogue to an LSP "node at cursor" query.
pub(crate) fn find_node_at(cpg: &Cpg, line: u32, column: u32) -> Option<NodeId> {
    cpg.ast
        .iter()
        .filter(|(_, node)| node.line == line && node.column == column)
        .min_by_key(|(_, node)| {
            let lines = node.end_line.saturating_sub(node.line);
            let cols = node.end_column.saturating_sub(node.column);
            (lines, cols)
        })
        .map(|(&id, _)| id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use web_sitter::cpg_generator::{GraphBuildOptions, SourceLanguage};
    use web_sitter::incremental::IncrementalCpgGenerator;

    fn parse(src: &str) -> Cpg {
        let mut generator = IncrementalCpgGenerator::new_for_language(
            SourceLanguage::Cpp,
            GraphBuildOptions::default(),
        )
        .expect("generator");
        generator.parse_full(src.as_bytes()).expect("parse").clone()
    }

    #[test]
    fn finds_the_innermost_node_at_a_shared_start_position() {
        // At column 15 (the 'y' in the param list), both the ParamDef and its nested
        // identifier start at the exact same position — the identifier is smaller-span
        // and must win.
        let cpg = parse("int helper(int y) { return y; }");
        let node_id = find_node_at(&cpg, 1, 15).expect("a node must be found at 1:15");
        let node = cpg.ast.get(&node_id).unwrap();
        assert_eq!(
            node.end_column - node.column,
            1,
            "must resolve to the 1-char identifier, not its enclosing ParamDef"
        );
    }

    #[test]
    fn returns_none_when_no_node_starts_at_the_position() {
        let cpg = parse("int helper(int y) { return y; }");
        assert!(find_node_at(&cpg, 1, 999).is_none());
    }
}
