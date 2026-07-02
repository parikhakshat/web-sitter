//! Lookup/navigation tools: `find_definition`, `find_references`, `symbol_summary`.
//!
//! All three resolve a human-typed query (simple name, `Class::method`, or a full
//! `SymbolId` string like `"cpp:Foo::run"`) against the workspace's
//! [`ReverseSymbolIndex`] built at startup (see `crate::index`), then answer from real
//! CPG data — never from re-deriving structure via text search.

use rmcp::Json;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use web_ql::symbol_index::{ReverseSymbolIndex, SymbolDefinition};
use web_sitter::IrNode;
use web_sitter::symbol_id::SymbolId;

use crate::server::WebMcpServer;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindDefinitionRequest {
    /// Symbol to look up: a simple name ("helper"), a class-qualified name
    /// ("Foo::run" / "Foo.run"), or a full SymbolId ("cpp:Foo::run").
    pub symbol: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DefinitionLocation {
    /// Stable cross-session symbol identifier — cite this in follow-up tool calls.
    pub symbol_id: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct FindDefinitionResponse {
    /// Usually one entry; more than one means `symbol` was ambiguous (e.g. an
    /// overloaded or same-named method in different classes) — disambiguate by
    /// re-querying with the returned `symbol_id`.
    pub definitions: Vec<DefinitionLocation>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindReferencesRequest {
    /// Same accepted forms as `find_definition`'s `symbol`.
    pub symbol: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ReferenceLocation {
    pub file: String,
    pub line: u32,
    pub column: u32,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct FindReferencesResponse {
    pub symbol_id: String,
    pub references: Vec<ReferenceLocation>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SymbolSummaryRequest {
    /// Same accepted forms as `find_definition`'s `symbol`.
    pub symbol: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SymbolSummaryResponse {
    pub symbol_id: String,
    pub file: String,
    pub line: u32,
    /// Full signature text (return type + params), when the lifter recorded one.
    pub signature: Option<String>,
    pub qualified_name: Option<String>,
    pub class_context: Option<String>,
    pub namespace: Option<String>,
    pub is_constructor: bool,
    pub is_destructor: bool,
    /// Parameter names, in declaration order, if an interprocedural summary exists.
    pub parameters: Vec<String>,
    /// Human-readable param effects (e.g. "param 0: sink", "param 1: taints return"),
    /// from `FunctionSummary::param_effects` — empty if no effects were inferred.
    pub param_effects: Vec<String>,
}

#[tool_router(router = lookup_tool_router, vis = "pub(crate)")]
impl WebMcpServer {
    #[tool(
        name = "find_definition",
        description = "Find where a symbol (function/class/method) is defined. Accepts a \
                        simple name, a class-qualified name, or a full SymbolId."
    )]
    pub async fn find_definition(
        &self,
        Parameters(req): Parameters<FindDefinitionRequest>,
    ) -> Json<FindDefinitionResponse> {
        let matches = resolve_symbol(&self.reverse_index, &req.symbol);
        let definitions = matches
            .into_iter()
            .filter_map(|(id, def)| definition_location(&self.workspace, id, def))
            .collect();
        Json(FindDefinitionResponse { definitions })
    }

    #[tool(
        name = "find_references",
        description = "Find call sites that reference a symbol, across the whole workspace. \
                        Accepts the same symbol forms as find_definition. If the symbol is \
                        ambiguous, resolves to its first match — re-query with an exact \
                        SymbolId (from find_definition) to disambiguate."
    )]
    pub async fn find_references(
        &self,
        Parameters(req): Parameters<FindReferencesRequest>,
    ) -> Json<FindReferencesResponse> {
        let Some((symbol_id, _def)) = resolve_symbol(&self.reverse_index, &req.symbol)
            .into_iter()
            .next()
        else {
            return Json(FindReferencesResponse {
                symbol_id: req.symbol,
                references: Vec::new(),
            });
        };

        let references = find_references_for(&self.workspace, &self.reverse_index, symbol_id);
        Json(FindReferencesResponse {
            symbol_id: symbol_id.as_str().to_string(),
            references,
        })
    }

    #[tool(
        name = "symbol_summary",
        description = "Dense fact card for a symbol: signature, qualifiers, and \
                        interprocedural parameter effects (sink/frees/taints), backed by \
                        FunctionSummary — for context-budget-efficient agent lookups."
    )]
    pub async fn symbol_summary(
        &self,
        Parameters(req): Parameters<SymbolSummaryRequest>,
    ) -> Result<Json<SymbolSummaryResponse>, String> {
        let Some((symbol_id, def)) = resolve_symbol(&self.reverse_index, &req.symbol)
            .into_iter()
            .next()
        else {
            return Err(format!("no definition found for '{}'", req.symbol));
        };

        build_symbol_summary(&self.workspace, symbol_id, def)
            .map(Json)
            .ok_or_else(|| format!("definition site for '{}' has no CPG node", req.symbol))
    }
}

/// Resolve a human-typed query against every known definition. Matches, in order of
/// preference: exact full `SymbolId` string, exact qualified path (SymbolId minus its
/// `<lang>:` prefix and `#<n>` disambiguator), or exact simple name (the qualified
/// path's last `::`/`.`-separated segment). Returns every match, not just the first —
/// callers decide how to handle ambiguity.
fn resolve_symbol<'a>(
    reverse_index: &'a ReverseSymbolIndex,
    query: &str,
) -> Vec<(&'a SymbolId, &'a SymbolDefinition)> {
    let exact: Vec<_> = reverse_index
        .definitions()
        .filter(|(id, _)| id.as_str() == query)
        .collect();
    if !exact.is_empty() {
        return exact;
    }

    let qualified: Vec<_> = reverse_index
        .definitions()
        .filter(|(id, _)| qualified_path(id) == query)
        .collect();
    if !qualified.is_empty() {
        return qualified;
    }

    reverse_index
        .definitions()
        .filter(|(id, _)| simple_name(id) == query)
        .collect()
}

/// Strip the `<lang>:` prefix and any `#<n>` disambiguator suffix from a `SymbolId`,
/// e.g. `"cpp:Foo::run#2"` -> `"Foo::run"`.
fn qualified_path(id: &SymbolId) -> &str {
    let without_lang = id
        .as_str()
        .split_once(':')
        .map(|(_, rest)| rest)
        .unwrap_or(id.as_str());
    without_lang.split('#').next().unwrap_or(without_lang)
}

/// The last `::`/`.`-separated segment of a `SymbolId`'s qualified path, e.g.
/// `"cpp:Foo::run#2"` -> `"run"`.
fn simple_name(id: &SymbolId) -> &str {
    let path = qualified_path(id);
    path.rsplit("::")
        .next()
        .unwrap_or(path)
        .rsplit('.')
        .next()
        .unwrap_or(path)
}

fn definition_location(
    workspace: &web_ql::Workspace,
    id: &SymbolId,
    def: &SymbolDefinition,
) -> Option<DefinitionLocation> {
    let node = workspace.files.get(&def.file)?.cpg.ast.get(&def.node_id)?;
    Some(DefinitionLocation {
        symbol_id: id.as_str().to_string(),
        file: def.file.display().to_string(),
        line: node.line,
        column: node.column,
    })
}

/// Concrete call-site locations resolving to `symbol_id`: scans `cpg.call_graph`'s
/// `CallSite`s (which carry qualified/simple callee names, not just a boolean edge) in
/// every candidate file — the symbol's own defining file (for recursive/self-calls) plus
/// every file `ReverseSymbolIndex` already knows references it.
fn find_references_for(
    workspace: &web_ql::Workspace,
    reverse_index: &ReverseSymbolIndex,
    symbol_id: &SymbolId,
) -> Vec<ReferenceLocation> {
    let Some(def) = reverse_index.definition(symbol_id) else {
        return Vec::new();
    };
    let qualified = qualified_path(symbol_id);
    let simple = simple_name(symbol_id);

    let mut candidate_files: Vec<_> = reverse_index
        .referencing_files(symbol_id)
        .cloned()
        .collect();
    candidate_files.push(def.file.clone());
    candidate_files.sort();
    candidate_files.dedup();

    let mut references = Vec::new();
    for file in candidate_files {
        let Some(idx) = workspace.files.get(&file) else {
            continue;
        };
        for entry in idx.cpg.call_graph.values() {
            for call_site in &entry.calls {
                let matches = call_site.qualified_callee.as_deref() == Some(qualified)
                    || call_site.callee == simple
                    || call_site.callee == qualified;
                if !matches {
                    continue;
                }
                if let Some(call_node_id) = call_site.call_site
                    && let Some(node) = idx.cpg.ast.get(&call_node_id)
                {
                    references.push(ReferenceLocation {
                        file: file.display().to_string(),
                        line: node.line,
                        column: node.column,
                    });
                }
            }
        }
    }
    references
}

fn build_symbol_summary(
    workspace: &web_ql::Workspace,
    symbol_id: &SymbolId,
    def: &SymbolDefinition,
) -> Option<SymbolSummaryResponse> {
    let cpg = &workspace.files.get(&def.file)?.cpg;
    let node: &IrNode = cpg.ast.get(&def.node_id)?;

    let summary = cpg.workspace.function_summaries.get(&def.node_id);
    let parameters = summary.map(|s| s.parameters.clone()).unwrap_or_default();
    let param_effects = summary
        .map(|s| s.param_effects.iter().map(describe_effect).collect())
        .unwrap_or_default();

    Some(SymbolSummaryResponse {
        symbol_id: symbol_id.as_str().to_string(),
        file: def.file.display().to_string(),
        line: node.line,
        signature: node.signature.clone(),
        qualified_name: node.qualified_name.clone(),
        class_context: node.class_context.clone(),
        namespace: node.namespace.clone(),
        is_constructor: node.is_constructor.unwrap_or(false),
        is_destructor: node.is_destructor.unwrap_or(false),
        parameters,
        param_effects,
    })
}

fn describe_effect(effect: &web_sitter::function_summary::ParamEffect) -> String {
    use web_sitter::function_summary::ParamEffect;
    match effect {
        ParamEffect::Sink(i) => format!("param {i}: sink"),
        ParamEffect::Frees(i) => format!("param {i}: frees"),
        ParamEffect::TaintOut(i) => format!("param {i}: taints on output"),
        ParamEffect::TaintReturn(i) => format!("param {i}: taints return value"),
    }
}
