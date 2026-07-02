//! Shared symbol-resolution logic: turn a human-typed query (simple name,
//! `Class::method`, or a full `SymbolId` string) into concrete `SymbolId`s, resolve a
//! `CallSite`'s callee name against them, and locate call sites for a resolved symbol.
//! Used by every tool module that accepts a `symbol` string argument
//! (`tools/lookup.rs`, `tools/callgraph.rs`, ...).

use web_ql::Workspace;
use web_ql::symbol_index::{ReverseSymbolIndex, SymbolDefinition};
use web_sitter::symbol_id::SymbolId;

/// Resolve a human-typed query against every known definition. Matches, in order of
/// preference: exact full `SymbolId` string, exact qualified path (`SymbolId` minus its
/// `<lang>:` prefix and `#<n>` disambiguator), or exact simple name (the qualified
/// path's last `::`/`.`-separated segment). Returns every match, not just the first —
/// callers decide how to handle ambiguity.
pub fn resolve_symbol<'a>(
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
pub fn qualified_path(id: &SymbolId) -> &str {
    let without_lang = id
        .as_str()
        .split_once(':')
        .map(|(_, rest)| rest)
        .unwrap_or(id.as_str());
    without_lang.split('#').next().unwrap_or(without_lang)
}

/// The last `::`/`.`-separated segment of a `SymbolId`'s qualified path, e.g.
/// `"cpp:Foo::run#2"` -> `"run"`.
pub fn simple_name(id: &SymbolId) -> &str {
    let path = qualified_path(id);
    path.rsplit("::")
        .next()
        .unwrap_or(path)
        .rsplit('.')
        .next()
        .unwrap_or(path)
}

/// True when a `CallSite`'s recorded callee name/qualified-name could refer to
/// `symbol_id` — the same matching `find_references`/the call-graph builder use to
/// connect a call site back to a `SymbolId`.
pub fn call_site_matches_symbol(
    qualified_callee: Option<&str>,
    callee_name: &str,
    symbol_id: &SymbolId,
) -> bool {
    let qualified = qualified_path(symbol_id);
    let simple = simple_name(symbol_id);
    qualified_callee == Some(qualified) || callee_name == simple || callee_name == qualified
}

/// Concrete call-site (file, line, column) locations resolving to `symbol_id`: scans
/// `cpg.call_graph`'s `CallSite`s (which carry qualified/simple callee names, not just a
/// boolean edge) in every candidate file — the symbol's own defining file (for
/// recursive/self-calls) plus every file `ReverseSymbolIndex` already knows references it.
pub fn call_sites_for<'a>(
    workspace: &'a Workspace,
    reverse_index: &ReverseSymbolIndex,
    symbol_id: &SymbolId,
) -> Vec<(&'a std::path::Path, &'a web_sitter::IrNode)> {
    let Some(def) = reverse_index.definition(symbol_id) else {
        return Vec::new();
    };

    let mut candidate_files: Vec<_> = reverse_index
        .referencing_files(symbol_id)
        .cloned()
        .collect();
    candidate_files.push(def.file.clone());
    candidate_files.sort();
    candidate_files.dedup();

    let mut sites = Vec::new();
    for file in candidate_files {
        let Some((path, idx)) = workspace.files.get_key_value(&file) else {
            continue;
        };
        for entry in idx.cpg.call_graph.values() {
            for call_site in &entry.calls {
                if !call_site_matches_symbol(
                    call_site.qualified_callee.as_deref(),
                    &call_site.callee,
                    symbol_id,
                ) {
                    continue;
                }
                if let Some(call_node_id) = call_site.call_site
                    && let Some(node) = idx.cpg.ast.get(&call_node_id)
                {
                    sites.push((path.as_path(), node));
                }
            }
        }
    }
    sites
}

#[cfg(test)]
mod tests {
    use super::*;
    use web_sitter::cpg_generator::{GraphBuildOptions, SourceLanguage};
    use web_sitter::incremental::IncrementalCpgGenerator;
    use web_sitter::symbol_id::build_symbol_table;

    /// Mint a real `SymbolId` from real source, matching `symbol_id.rs`'s own test
    /// pattern — there is deliberately no public "construct from a raw string"
    /// constructor, since a `SymbolId` should only ever come from real analysis.
    fn symbol_id_for(lang: SourceLanguage, src: &str, name: &str) -> SymbolId {
        let mut generator =
            IncrementalCpgGenerator::new_for_language(lang, GraphBuildOptions::default())
                .expect("generator");
        let cpg = generator.parse_full(src.as_bytes()).expect("parse").clone();
        build_symbol_table(&cpg)
            .into_values()
            .find(|s| simple_name(s) == name)
            .unwrap_or_else(|| panic!("no symbol named {name} in parsed fixture"))
    }

    #[test]
    fn qualified_path_strips_language_prefix_and_disambiguator() {
        let id = symbol_id_for(
            SourceLanguage::Cpp,
            "struct Foo { int run() { return 1; } };",
            "run",
        );
        assert_eq!(qualified_path(&id), "Foo::run");
    }

    #[test]
    fn simple_name_takes_last_segment() {
        let id = symbol_id_for(
            SourceLanguage::Cpp,
            "struct Foo { int run() { return 1; } };",
            "run",
        );
        assert_eq!(simple_name(&id), "run");
        let plain = symbol_id_for(SourceLanguage::Cpp, "int helper() { return 1; }", "helper");
        assert_eq!(simple_name(&plain), "helper");
    }

    #[test]
    fn call_site_matches_symbol_checks_all_three_forms() {
        let id = symbol_id_for(
            SourceLanguage::Cpp,
            "struct Foo { int run() { return 1; } };",
            "run",
        );
        assert!(call_site_matches_symbol(Some("Foo::run"), "run", &id));
        assert!(call_site_matches_symbol(None, "run", &id));
        assert!(!call_site_matches_symbol(None, "other", &id));
    }
}
