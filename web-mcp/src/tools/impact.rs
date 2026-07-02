//! Change-impact tool: `impact_of_change(file, new_source)` — given a proposed new
//! version of a file's source, determine which functions/classes structurally changed
//! and the transitive blast radius (existing callers) that needs re-verification,
//! *before* the patch is actually applied to the index.
//!
//! Phase 1 scope: this diffs against the on-disk source at the already-indexed path
//! (read fresh, not the batch-built `Cpg`'s own text — `GraphBuildOptions::minimal_text`
//! means node text isn't reliably retained) and re-parses `new_source` standalone. It
//! does not touch `IncrementalCpgGenerator`'s private `try_targeted_update` machinery —
//! that's an edit-driven, single-generator API not exposed for a read-only "what would
//! change" query, and Phase 1's `Workspace` isn't built from `IncrementalCpgGenerator`
//! in the first place (see `crate::index`).

use std::collections::BTreeSet;

use rmcp::Json;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use web_sitter::symbol_id::build_symbol_table;
use web_sitter::{CpgGenerator, GraphBuildOptions};

use crate::server::WebMcpServer;

fn default_max_depth() -> u32 {
    5
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ImpactOfChangeRequest {
    pub file: String,
    /// The proposed full new source text for `file` — not a diff/patch, the whole file
    /// as it would read after the edit.
    pub new_source: String,
    /// How far to traverse the call graph for the blast radius. Defaults to 5.
    #[serde(default = "default_max_depth")]
    pub max_depth: u32,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ChangedSymbol {
    pub symbol_id: String,
    /// "added" | "removed" | "modified"
    pub change_kind: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ImpactOfChangeResponse {
    pub changed_symbols: Vec<ChangedSymbol>,
    /// Every changed/removed symbol plus its transitive callers (up to max_depth),
    /// deduplicated — the set that needs re-verification before this patch lands.
    /// Newly `added` symbols contribute nothing here (nothing calls them yet).
    pub blast_radius: Vec<String>,
}

#[tool_router(router = impact_tool_router, vis = "pub(crate)")]
impl WebMcpServer {
    #[tool(
        name = "impact_of_change",
        description = "Given a proposed new version of a file's source, report which \
                        functions/classes structurally changed and the transitive set of \
                        existing callers that needs re-verification — before the patch is \
                        actually applied."
    )]
    pub async fn impact_of_change(
        &self,
        Parameters(req): Parameters<ImpactOfChangeRequest>,
    ) -> Result<Json<ImpactOfChangeResponse>, String> {
        let path = self.resolve_path(&req.file);
        let idx = self
            .workspace
            .files
            .get(&path)
            .ok_or_else(|| format!("file not indexed: {}", req.file))?;

        let old_source = std::fs::read(&path)
            .map_err(|e| format!("reading current contents of {}: {e}", req.file))?;
        let new_source = req.new_source.as_bytes();

        let language = web_sitter::language_from_path(&req.file);
        let mut generator = CpgGenerator::new_for_language(language)
            .map_err(|e| format!("creating parser: {e}"))?;
        let new_cpg = generator
            .generate_from_source_with_options(new_source, GraphBuildOptions::default())
            .map_err(|e| format!("parsing new_source: {e}"))?;

        let old_symbols = build_symbol_table(&idx.cpg);
        let new_symbols = build_symbol_table(&new_cpg);

        let mut old_by_id = std::collections::HashMap::new();
        for (&node_id, symbol_id) in &old_symbols {
            if let Some(node) = idx.cpg.ast.get(&node_id)
                && let (Some(s), Some(e)) = (node.start_byte, node.end_byte)
            {
                old_by_id.insert(symbol_id.clone(), (s as usize, e as usize));
            }
        }
        let mut new_by_id = std::collections::HashMap::new();
        for (&node_id, symbol_id) in &new_symbols {
            if let Some(node) = new_cpg.ast.get(&node_id)
                && let (Some(s), Some(e)) = (node.start_byte, node.end_byte)
            {
                new_by_id.insert(symbol_id.clone(), (s as usize, e as usize));
            }
        }

        let mut changed = Vec::new();
        let all_ids: BTreeSet<_> = old_by_id.keys().chain(new_by_id.keys()).cloned().collect();
        for symbol_id in all_ids {
            match (old_by_id.get(&symbol_id), new_by_id.get(&symbol_id)) {
                (Some(_), None) => changed.push((symbol_id, "removed")),
                (None, Some(_)) => changed.push((symbol_id, "added")),
                (Some(&(os, oe)), Some(&(ns, ne))) => {
                    let old_text = old_source.get(os..oe);
                    let new_text = new_source.get(ns..ne);
                    if old_text != new_text {
                        changed.push((symbol_id, "modified"));
                    }
                }
                (None, None) => unreachable!("symbol_id came from one of the two maps"),
            }
        }

        let mut blast_radius: BTreeSet<String> = BTreeSet::new();
        for (symbol_id, kind) in &changed {
            if *kind == "added" {
                continue;
            }
            blast_radius.insert(symbol_id.as_str().to_string());
            for (caller, _depth) in self
                .call_graph
                .transitive_callers(symbol_id, req.max_depth as usize)
            {
                blast_radius.insert(caller.as_str().to_string());
            }
        }

        Ok(Json(ImpactOfChangeResponse {
            changed_symbols: changed
                .into_iter()
                .map(|(symbol_id, kind)| ChangedSymbol {
                    symbol_id: symbol_id.as_str().to_string(),
                    change_kind: kind.to_string(),
                })
                .collect(),
            blast_radius: blast_radius.into_iter().collect(),
        }))
    }
}
