//! Stable, human-readable, cross-file symbol identifiers.
//!
//! `NodeId` (see [`crate::NodeId`]) is only unique *within a single file's* `Cpg` — the
//! same integer routinely refers to unrelated nodes in different files, which is why
//! callers that need to address a node across files wrap it in a `(PathBuf, NodeId)`
//! pair (see `web-ql`'s `NodeRef`). That pair is stable for the lifetime of one loaded
//! `Cpg`, but it is *not* stable across a reparse: `NodeId`s are minted positionally
//! during parsing/lifting and can shift when unrelated code earlier in the file changes.
//!
//! [`SymbolId`] is a second, independent addressing scheme: a string derived purely from
//! a symbol's *name* (fully-qualified name, class/namespace context, language, and — for
//! disambiguation among same-named siblings — declaration order), never from its `NodeId`.
//! Two reparses of unchanged source therefore mint the identical `SymbolId` for the
//! identical symbol, which is what makes it usable as a durable cross-session /
//! cross-restart key (MCP tool responses, the reverse-symbol-index, persistent finding
//! fingerprints) — unlike `NodeId`, which is only an efficient in-process handle.
//!
//! Format: `<language>:<qualified-path>[#<disambiguator>]`, e.g.:
//!   - `cpp:std::string::append`
//!   - `java:com.example.Foo.bar`
//!   - `go:encoding/json.Marshal`
//!   - `python:helpers.parse#2` (third `parse` sharing this qualified path in this file)

use std::collections::BTreeMap;
use std::fmt;

use crate::{Cpg, IrNodeKind, NodeId};

/// A stable, human-readable symbol identifier. See module docs for the format and
/// the stability guarantee it provides over raw [`NodeId`]s.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymbolId(String);

impl SymbolId {
    /// Borrow the underlying string, e.g. for use as a map key or serialized form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SymbolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<SymbolId> for String {
    fn from(id: SymbolId) -> String {
        id.0
    }
}

/// The best-available qualified name for a symbol-bearing node, independent of
/// disambiguation. Returns `None` for nodes that aren't named declarations, or that
/// have no name at all (anonymous functions etc. are addressed via `NodeRef`, not
/// `SymbolId`).
///
/// Precedence mirrors `web_ql::workspace::Workspace::build_cross_file_edges`'s existing
/// multi-key resolution order (most specific wins): fully-qualified name (including
/// per-language Java/Go metadata) > class-qualified > namespace-qualified > simple name.
fn qualified_path(cpg: &Cpg, node_id: NodeId, node: &crate::IrNode) -> Option<String> {
    let name = node.name.as_ref()?;

    if let Some(fqc) = cpg
        .java_metadata
        .get(&node_id)
        .and_then(|m| m.fully_qualified_class.as_ref())
    {
        return Some(format!("{fqc}.{name}"));
    }
    if let Some(qname) = cpg
        .go_metadata
        .get(&node_id)
        .and_then(|m| m.qualified_name.as_ref())
    {
        return Some(qname.clone());
    }
    if let Some(qname) = &node.qualified_name {
        return Some(qname.clone());
    }
    if let Some(cls) = &node.class_context {
        return Some(format!("{cls}::{name}"));
    }
    if let Some(ns) = &node.namespace {
        return Some(format!("{ns}::{name}"));
    }
    Some(name.clone())
}

/// True for node kinds that get a `SymbolId` — currently function/method and class/type
/// declarations, the two kinds `web-mcp`'s tool surface (lookup, call graph, verification)
/// needs to address durably. Extend as new tools need to cite other symbol kinds.
fn is_addressable(kind: IrNodeKind) -> bool {
    matches!(kind, IrNodeKind::MethodDef | IrNodeKind::ClassDef)
}

/// Compute the `SymbolId` for a single node, if it's addressable. Prefer
/// [`build_symbol_table`] when minting IDs for many nodes in one `Cpg` — it resolves
/// disambiguators consistently in one pass instead of re-scanning the whole file per call.
pub fn compute_symbol_id(cpg: &Cpg, node_id: NodeId) -> Option<SymbolId> {
    build_symbol_table(cpg).remove(&node_id)
}

/// Mint a `SymbolId` for every addressable node in `cpg`, keyed by its (file-local,
/// reparse-unstable) `NodeId`. Rebuild this table after every reparse; the `NodeId` keys
/// change, but each symbol's `SymbolId` value is stable as long as its qualified name and
/// declaration order relative to same-named siblings are unchanged.
///
/// Disambiguation: when two addressable nodes share an identical qualified path (e.g.
/// overloads, or duplicate definitions across `#ifdef` branches), the *n*-th occurrence in
/// AST node-id order gets `#<n>` appended (n >= 1, so the first occurrence's SymbolId has
/// no suffix — keeps the common case's IDs short). Ordering by `NodeId` is deterministic
/// for a given parse and, since it follows source order, is unaffected by edits elsewhere
/// in the file.
pub fn build_symbol_table(cpg: &Cpg) -> BTreeMap<NodeId, SymbolId> {
    let lang = &cpg.language;

    // First pass: collect (node_id, qualified_path) for every addressable node, in
    // ascending NodeId (== source-order) so disambiguator assignment is deterministic.
    let mut candidates: Vec<(NodeId, String)> = cpg
        .ast
        .iter()
        .filter(|(_, node)| is_addressable(node.kind))
        .filter_map(|(&node_id, node)| {
            qualified_path(cpg, node_id, node).map(|path| (node_id, path))
        })
        .collect();
    candidates.sort_by_key(|(node_id, _)| *node_id);

    // Second pass: assign disambiguators per distinct qualified path.
    let mut seen: BTreeMap<&str, u32> = BTreeMap::new();
    let mut table = BTreeMap::new();
    for (node_id, path) in &candidates {
        let count = seen.entry(path.as_str()).or_insert(0);
        *count += 1;
        let id_str = if *count == 1 {
            format!("{lang}:{path}")
        } else {
            format!("{lang}:{path}#{count}")
        };
        table.insert(*node_id, SymbolId(id_str));
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpg_generator::{GraphBuildOptions, SourceLanguage};
    use crate::incremental::IncrementalCpgGenerator;

    fn parse(lang: SourceLanguage, src: &str) -> Cpg {
        let mut generator =
            IncrementalCpgGenerator::new_for_language(lang, GraphBuildOptions::default())
                .expect("generator");
        generator.parse_full(src.as_bytes()).expect("parse").clone()
    }

    #[test]
    fn stable_across_noop_reparse() {
        let src = r#"
            struct Foo {
                int bar(int x) { return x + 1; }
            };
            int helper(int y) { return y * 2; }
        "#;
        let cpg1 = parse(SourceLanguage::Cpp, src);
        let cpg2 = parse(SourceLanguage::Cpp, src);

        let t1 = build_symbol_table(&cpg1);
        let t2 = build_symbol_table(&cpg2);

        let ids1: std::collections::BTreeSet<&SymbolId> = t1.values().collect();
        let ids2: std::collections::BTreeSet<&SymbolId> = t2.values().collect();
        assert!(!ids1.is_empty());
        assert_eq!(
            ids1, ids2,
            "identical source must mint identical SymbolId sets"
        );
    }

    #[test]
    fn stable_when_unrelated_code_shifts_node_ids() {
        let before = r#"
            int helper(int y) { return y * 2; }
        "#;
        let after = r#"
            int padding_fn(int z) { return z; }
            int another_pad(int z) { return z + z; }
            int helper(int y) { return y * 2; }
        "#;
        let cpg_before = parse(SourceLanguage::Cpp, before);
        let cpg_after = parse(SourceLanguage::Cpp, after);

        let t_before = build_symbol_table(&cpg_before);
        let t_after = build_symbol_table(&cpg_after);

        let helper_id_before = t_before.values().find(|s| s.as_str() == "cpp:helper");
        let helper_id_after = t_after.values().find(|s| s.as_str() == "cpp:helper");
        assert!(helper_id_before.is_some());
        assert_eq!(helper_id_before, helper_id_after);
    }

    #[test]
    fn class_qualified_name_used_over_simple_name() {
        let src = r#"
            struct Foo {
                int run() { return 1; }
            };
            struct Bar {
                int run() { return 2; }
            };
        "#;
        let cpg = parse(SourceLanguage::Cpp, src);
        let table = build_symbol_table(&cpg);
        let ids: Vec<&str> = table.values().map(|s| s.as_str()).collect();
        assert!(ids.contains(&"cpp:Foo::run"), "{ids:?}");
        assert!(ids.contains(&"cpp:Bar::run"), "{ids:?}");
    }

    #[test]
    fn duplicate_qualified_paths_get_disambiguated() {
        // Two free functions can't legally share a name in one C++ TU without being
        // overloads (different signature) or a redefinition error; simulate the
        // disambiguation path directly against a hand-built Cpg instead of relying on
        // parser output, since tree-sitter alone won't produce two MethodDefs with an
        // identical qualified_name from valid single-language source in this test setup.
        let mut cpg = Cpg::default();
        cpg.language = "test".to_string();
        for i in 0..3u32 {
            let node = crate::IrNode {
                kind: IrNodeKind::MethodDef,
                name: Some("overload".to_string()),
                node_type: "function_definition".to_string(),
                ..Default::default()
            };
            cpg.ast.insert(i, node);
        }
        let table = build_symbol_table(&cpg);
        let mut ids: Vec<&str> = table.values().map(|s| s.as_str()).collect();
        ids.sort();
        assert_eq!(
            ids,
            vec!["test:overload", "test:overload#2", "test:overload#3"]
        );
    }

    #[test]
    fn non_addressable_nodes_get_no_symbol_id() {
        let src = "int helper(int y) { int local = y; return local; }";
        let cpg = parse(SourceLanguage::Cpp, src);
        let table = build_symbol_table(&cpg);
        // Only the one MethodDef ("helper") should be addressable; locals/params aren't.
        assert_eq!(table.len(), 1);
    }
}
