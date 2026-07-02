//! Variant analysis tools: `find_variants`/`explain_variant` — the MCP surface over
//! `crate::security::generalize`. `find_variants` takes one known bug instance (a code
//! range pinpointing the anchor call), generalizes it into a ScuzzQL rule, and runs that
//! rule over a scope to find structurally similar instances elsewhere in the codebase.
//! `explain_variant` re-locates one match by its stable id and returns its evidence
//! (enclosing symbol, source snippet) — same "verifiable, not inferred" contract as the
//! claim-checking tools in `verify.rs`.

use std::collections::HashSet;
use std::path::PathBuf;

use rmcp::Json;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use web_sitter::symbol_id::build_symbol_table;
use web_sitter::{Cpg, IrNodeKind, NodeId};

use crate::security::generalize::generalize_call_pattern;
use crate::server::WebMcpServer;
use crate::tools::dataflow::{Location, find_node_at};

const SUPPORTED_SCOPES: &[&str] = &["workspace", "file", "directory"];

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindVariantsRequest {
    /// Source position of the known bug instance's anchor call — the example to
    /// generalize from.
    pub location: Location,
    /// "workspace" (default) | "file" | "directory" — where to search for variants.
    #[serde(default = "default_scope")]
    pub scope: String,
    /// Required for scope=file/directory.
    pub path: Option<String>,
}

fn default_scope() -> String {
    "workspace".to_string()
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct VariantMatch {
    /// Stable id — pass to `explain_variant` to get this match's full evidence.
    pub match_id: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub callee: String,
    /// True for the match at `location` itself (the example echoed back, not a distinct
    /// variant) — included rather than filtered out so a caller can see the generalized
    /// rule really does match its own source instance.
    pub is_example: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct FindVariantsResponse {
    pub rule_id: String,
    pub rule_source: String,
    pub anchor_callees: Vec<String>,
    pub matches: Vec<VariantMatch>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExplainVariantRequest {
    pub match_id: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ExplainVariantResponse {
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub callee: String,
    /// The `SymbolId` of the enclosing function, if one could be resolved.
    pub enclosing_symbol: Option<String>,
    pub snippet: Option<String>,
}

#[tool_router(router = variants_tool_router, vis = "pub(crate)")]
impl WebMcpServer {
    #[tool(
        name = "find_variants",
        description = "Generalize one known bug instance (the call at `location`) into a \
                        ScuzzQL rule and run it over `scope` to find structurally similar \
                        instances elsewhere in the codebase — query by example. \
                        Structural-only first pass: generalizes past the specific \
                        variable/argument identifiers, anchored on the called function's \
                        name."
    )]
    pub async fn find_variants(
        &self,
        Parameters(req): Parameters<FindVariantsRequest>,
    ) -> Result<Json<FindVariantsResponse>, String> {
        let example_path = self.resolve_path(&req.location.file);
        let workspace = self.workspace.load_full();
        let example_idx = workspace
            .files
            .get(&example_path)
            .ok_or_else(|| format!("file not indexed: {}", req.location.file))?;

        let anchor_node = find_node_at(&example_idx.cpg, req.location.line, req.location.column)
            .and_then(|node_id| find_enclosing_call(&example_idx.cpg, node_id))
            .ok_or_else(|| {
                format!(
                    "no call expression at or enclosing {}:{}:{}",
                    req.location.file, req.location.line, req.location.column
                )
            })?;

        let generalized = generalize_call_pattern(
            &example_idx.cpg,
            &example_idx.kind_index,
            &[anchor_node],
            "variant-search",
            "medium",
            "query-by-example variant search",
        )
        .ok_or_else(|| {
            "the node at this location isn't a call expression — structural-only \
             generalization can't anchor on it yet"
                .to_string()
        })?;

        let scope = self.resolve_variant_scope(&workspace, &req.scope, req.path.as_deref())?;
        let rule_set = web_ql::compile_rules(&generalized.rule_source)
            .map_err(|e| format!("generated rule failed to compile: {e:#}"))?;
        let findings = match &scope {
            Some(files) => workspace.scan_scoped(&rule_set, files),
            None => workspace.scan(&rule_set),
        };

        let anchor = example_idx
            .cpg
            .ast
            .get(&anchor_node)
            .ok_or_else(|| "anchor call node vanished from the indexed CPG".to_string())?;
        let example_key = (
            example_path.display().to_string(),
            anchor.line,
            anchor.column,
        );
        let matches = findings
            .into_iter()
            .map(|f| {
                let match_id = format!(
                    "{}#{}:{}:{}",
                    generalized.rule_id, f.location.file, f.location.line, f.location.column
                );
                let callee = resolve_finding_callee(&workspace, &f).unwrap_or_default();
                let is_example =
                    (f.location.file.clone(), f.location.line, f.location.column) == example_key;
                VariantMatch {
                    match_id,
                    file: f.location.file,
                    line: f.location.line,
                    column: f.location.column,
                    callee,
                    is_example,
                }
            })
            .collect();

        Ok(Json(FindVariantsResponse {
            rule_id: generalized.rule_id,
            rule_source: generalized.rule_source,
            anchor_callees: generalized.anchor_callees,
            matches,
        }))
    }

    #[tool(
        name = "explain_variant",
        description = "Re-locate a match_id returned by find_variants and return its \
                        evidence: enclosing symbol and source snippet — the same \
                        verifiable-not-inferred contract as explain_path/taint_path."
    )]
    pub async fn explain_variant(
        &self,
        Parameters(req): Parameters<ExplainVariantRequest>,
    ) -> Result<Json<ExplainVariantResponse>, String> {
        let (file, line, column) = parse_match_id(&req.match_id)
            .ok_or_else(|| format!("malformed match_id: '{}'", req.match_id))?;

        let path = self.resolve_path(&file);
        let workspace = self.workspace.load_full();
        let idx = workspace
            .files
            .get(&path)
            .ok_or_else(|| format!("file not indexed: {file}"))?;

        let node_id = find_node_at(&idx.cpg, line, column)
            .and_then(|id| find_enclosing_call(&idx.cpg, id))
            .ok_or_else(|| format!("no call expression at {file}:{line}:{column}"))?;
        let node = idx
            .cpg
            .ast
            .get(&node_id)
            .ok_or_else(|| format!("node {node_id} no longer present in the indexed CPG"))?;

        let callee = idx
            .kind_index
            .call_site_for_node(node_id)
            .map(|cs| cs.callee.clone())
            .unwrap_or_default();

        let enclosing_symbol = node
            .function_id
            .and_then(|fid| build_symbol_table(&idx.cpg).get(&fid).cloned())
            .map(|id| id.as_str().to_string());

        Ok(Json(ExplainVariantResponse {
            file,
            line,
            column,
            callee,
            enclosing_symbol,
            snippet: node.text.clone(),
        }))
    }
}

impl WebMcpServer {
    fn resolve_variant_scope(
        &self,
        workspace: &web_ql::Workspace,
        scope: &str,
        path: Option<&str>,
    ) -> Result<Option<HashSet<PathBuf>>, String> {
        if !SUPPORTED_SCOPES.contains(&scope) {
            return Err(format!(
                "unsupported find_variants scope '{scope}': only {SUPPORTED_SCOPES:?} are implemented"
            ));
        }
        match scope {
            "workspace" => Ok(None),
            "file" => {
                let path = path.ok_or_else(|| "scope=file requires path".to_string())?;
                let resolved = self.resolve_path(path);
                if !workspace.files.contains_key(&resolved) {
                    return Err(format!("file not indexed: {path}"));
                }
                Ok(Some(HashSet::from([resolved])))
            }
            "directory" => {
                let path = path.ok_or_else(|| "scope=directory requires path".to_string())?;
                let resolved = self.resolve_path(path);
                let files: HashSet<PathBuf> = workspace
                    .files
                    .keys()
                    .filter(|f| f.starts_with(&resolved))
                    .cloned()
                    .collect();
                if files.is_empty() {
                    return Err(format!("no indexed files under directory: {path}"));
                }
                Ok(Some(files))
            }
            other => {
                unreachable!("validated against SUPPORTED_SCOPES before reaching here: {other}")
            }
        }
    }
}

/// The callee name for a `Finding` produced by a `generalize_call_pattern`-generated
/// rule — its primary matched node is always the anchor `Call` node itself, resolved back
/// through that node's own file's `KindIndex` (a `Finding`'s `NodeId`s are only meaningful
/// relative to the `Cpg` they came from, not portable across files).
fn resolve_finding_callee(
    workspace: &web_ql::Workspace,
    finding: &web_ql::Finding,
) -> Option<String> {
    let file = PathBuf::from(&finding.location.file);
    let idx = workspace.files.get(&file)?;
    let node_id = *finding.matched_nodes.first()?;
    idx.kind_index
        .call_site_for_node(node_id)
        .map(|cs| cs.callee.clone())
}

/// Walk up from `node_id` (inclusive) looking for the nearest enclosing `Call` node —
/// `find_node_at` resolves to the smallest node at an exact position, which is often an
/// identifier/argument nested inside the call the caller actually means.
fn find_enclosing_call(cpg: &Cpg, mut node_id: NodeId) -> Option<NodeId> {
    for _ in 0..64 {
        let node = cpg.ast.get(&node_id)?;
        if node.kind == IrNodeKind::Call {
            return Some(node_id);
        }
        node_id = node.parent_id?;
    }
    None
}

/// Split a `match_id` of the form `"{rule_id}#{file}:{line}:{column}"` back into its
/// location — `rsplitn` from the right handles file paths that (rarely, but legally on
/// POSIX) contain a `:` themselves; `rule_id` is discarded, `explain_variant` re-derives
/// everything it needs from the location alone.
fn parse_match_id(match_id: &str) -> Option<(String, u32, u32)> {
    let (_rule_id, location) = match_id.split_once('#')?;
    let mut parts = location.rsplitn(3, ':');
    let column: u32 = parts.next()?.parse().ok()?;
    let line: u32 = parts.next()?.parse().ok()?;
    let file = parts.next()?.to_string();
    Some((file, line, column))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_match_id_splits_rule_id_and_location() {
        let (file, line, column) = parse_match_id("cwe-78-variant#src/a.cpp:10:5").unwrap();
        assert_eq!(file, "src/a.cpp");
        assert_eq!(line, 10);
        assert_eq!(column, 5);
    }

    #[test]
    fn parse_match_id_handles_a_colon_inside_the_file_path() {
        // Unusual but legal on POSIX filesystems.
        let (file, line, column) = parse_match_id("r#weird:path/a.cpp:3:1").unwrap();
        assert_eq!(file, "weird:path/a.cpp");
        assert_eq!(line, 3);
        assert_eq!(column, 1);
    }

    #[test]
    fn parse_match_id_rejects_malformed_input() {
        assert!(parse_match_id("no-hash-separator").is_none());
        assert!(parse_match_id("rule#not-enough-parts").is_none());
    }
}
