//! Reverse symbol index: for a given [`SymbolId`], which files define it and which
//! files hold a call site that (potentially) references it.
//!
//! This is what turns cross-file invalidation from O(all files) into O(affected files):
//! today `Workspace::build_cross_file_edges` rebuilds its whole `fn_to_params`/
//! `cross_file_callee_params` map from scratch on every call — fine for a full initial
//! index, but not something a live-update server can afford to redo on every edit in a
//! 100k-file monorepo. `ReverseSymbolIndex` lets a watcher ask "which other files need
//! their cross-file edges re-resolved after this file changed?" and get back only the
//! files that actually reference the symbols that changed.
//!
//! Resolution mirrors `Workspace::build_cross_file_edges`'s existing multi-key precedence
//! (most specific wins): fully-qualified name > class-qualified > namespace-qualified >
//! simple name. A call site is matched against this index the same way it would be
//! matched during cross-file edge resolution.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use web_sitter::symbol_id::{SymbolId, build_symbol_table};
use web_sitter::{Cpg, IrNodeKind, NodeId};

/// Where a symbol is defined: which file, and its (reparse-unstable) `NodeId` in that
/// file's current `Cpg`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymbolDefinition {
    pub file: PathBuf,
    pub node_id: NodeId,
}

/// Reverse index over a set of files' CPGs: symbol -> definition site, and symbol ->
/// files holding a call site that resolves to it.
#[derive(Default)]
pub struct ReverseSymbolIndex {
    definitions: HashMap<SymbolId, SymbolDefinition>,
    references: HashMap<SymbolId, HashSet<PathBuf>>,
    /// Cumulative multi-key name index across every indexed file (simple name,
    /// namespace::name, class::name, fully-qualified name -> defining SymbolId),
    /// used to resolve a call site's `callee_name`/`qualified_callee` the same way
    /// `Workspace::build_cross_file_edges` does. Unlike a per-file index, this must be
    /// global — a call site names a symbol *defined in a different file*, so resolving
    /// it against only the caller's own file would never find the callee.
    name_index: HashMap<String, SymbolId>,
    /// Which name-index keys each symbol registered, so `remove_file` can retract
    /// exactly those keys instead of rescanning `name_index`.
    keys_by_symbol: HashMap<SymbolId, Vec<String>>,
    /// Per-file set of symbols that file defines — lets `remove_file`/`upsert_file`
    /// undo a file's contribution without rescanning every other file.
    defined_by_file: HashMap<PathBuf, Vec<SymbolId>>,
    /// Per-file set of symbols that file references — same purpose, for the reference side.
    referenced_by_file: HashMap<PathBuf, Vec<SymbolId>>,
}

impl ReverseSymbolIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a fresh index from a full set of files. Two passes: register every file's
    /// definitions first, *then* resolve every file's references against the now-complete
    /// name index. This ordering matters and is not optional — `files` is commonly a
    /// `HashMap` iterator with no defined order, so a single-pass "define + resolve as
    /// you go" approach (what `upsert_file` alone does) would silently drop any reference
    /// whose defining file happens to be visited after the referencing file.
    pub fn build<'a>(files: impl IntoIterator<Item = (&'a Path, &'a Cpg)>) -> Self {
        let mut index = Self::new();
        let files: Vec<(&Path, &Cpg)> = files.into_iter().collect();
        for (path, cpg) in &files {
            index.remove_file(path);
            index.register_definitions(path, cpg);
        }
        for (path, cpg) in &files {
            index.resolve_references(path, cpg);
        }
        index
    }

    /// (Re)index a single file: replaces any prior contribution this file made to both
    /// the definitions and references maps, then re-derives its contribution from `cpg`.
    /// This is the operation a live watcher calls after a single-file reparse — it never
    /// touches other files' entries, only the reverse-mapped sets that pointed at this
    /// file's old symbols.
    ///
    /// Unlike [`build`](Self::build), this only re-resolves `path`'s own outgoing
    /// references — appropriate for incremental maintenance of an *already-complete*
    /// index (every other file's definitions are already registered), but not for
    /// building one from scratch in arbitrary order — use `build` for that.
    pub fn upsert_file(&mut self, path: &Path, cpg: &Cpg) {
        self.remove_file(path);
        self.register_definitions(path, cpg);
        self.resolve_references(path, cpg);
    }

    /// Register `path`'s definitions and their name-index keys. Keys are registered into
    /// the *global* `name_index` (weak/simple-name keys: first registration wins;
    /// strong/qualified-name keys: always overwrite) so that call sites in other files,
    /// which name a callee defined elsewhere, can resolve against it.
    fn register_definitions(&mut self, path: &Path, cpg: &Cpg) {
        let symbol_table = build_symbol_table(cpg);

        let mut defined_here = Vec::with_capacity(symbol_table.len());
        for (&node_id, symbol_id) in &symbol_table {
            self.definitions.insert(
                symbol_id.clone(),
                SymbolDefinition {
                    file: path.to_path_buf(),
                    node_id,
                },
            );
            defined_here.push(symbol_id.clone());

            if let Some(node) = cpg.ast.get(&node_id)
                && node.kind == IrNodeKind::MethodDef
                && let Some(fn_name) = &node.name
            {
                self.register_keys(symbol_id, name_keys(cpg, node_id, node, fn_name));
            }
        }
        self.defined_by_file
            .insert(path.to_path_buf(), defined_here);
    }

    /// Resolve `path`'s outgoing call-site references against the name index as it
    /// currently stands. Callers building a fresh index from arbitrary-order input must
    /// call this only after every file's `register_definitions` has already run (see
    /// `build`) or references to not-yet-registered definitions will be silently missed.
    fn resolve_references(&mut self, path: &Path, cpg: &Cpg) {
        self.resolve_references_with_fallback(path, cpg, None);
    }

    /// Same as [`resolve_references`](Self::resolve_references), but when a call site's
    /// callee can't be resolved against this index's own `name_index`, also tries
    /// `fallback`'s name index before giving up. This is what lets a thin overlay index
    /// (only a handful of actively-edited files) resolve calls into symbols that only the
    /// stable base layer knows about, without copying the base layer's entire name index
    /// into the overlay — see [`crate::layered_symbol_index::LayeredSymbolIndex`].
    pub fn resolve_references_with_fallback(
        &mut self,
        path: &Path,
        cpg: &Cpg,
        fallback: Option<&ReverseSymbolIndex>,
    ) {
        let mut referenced_here = Vec::new();
        for edge in &cpg.workspace.cross_file_calls {
            let resolved = edge
                .qualified_callee
                .as_deref()
                .and_then(|q| self.name_index.get(q))
                .or_else(|| self.name_index.get(edge.callee_name.as_str()))
                .or_else(|| {
                    fallback.and_then(|f| {
                        edge.qualified_callee
                            .as_deref()
                            .and_then(|q| f.name_lookup(q))
                            .or_else(|| f.name_lookup(edge.callee_name.as_str()))
                    })
                });
            if let Some(symbol_id) = resolved {
                self.references
                    .entry(symbol_id.clone())
                    .or_default()
                    .insert(path.to_path_buf());
                referenced_here.push(symbol_id.clone());
            }
        }
        self.referenced_by_file
            .insert(path.to_path_buf(), referenced_here);
    }

    /// Same as [`upsert_file`](Self::upsert_file), but resolves references against
    /// `fallback`'s name index too when this index's own doesn't have the callee.
    pub fn upsert_file_with_fallback(
        &mut self,
        path: &Path,
        cpg: &Cpg,
        fallback: &ReverseSymbolIndex,
    ) {
        self.remove_file(path);
        self.register_definitions(path, cpg);
        self.resolve_references_with_fallback(path, cpg, Some(fallback));
    }

    /// Look up a raw name-index key (simple/qualified name -> defining `SymbolId`).
    /// Exposed for `LayeredSymbolIndex`'s fallback resolution; not otherwise part of the
    /// public query surface (prefer `definition`/`referencing_files`).
    pub fn name_lookup(&self, key: &str) -> Option<&SymbolId> {
        self.name_index.get(key)
    }

    /// Register one symbol's name-index keys, respecting the same "weak keys: first
    /// wins, strong keys: always overwrite" precedence as
    /// `Workspace::build_cross_file_edges`.
    fn register_keys(&mut self, symbol_id: &SymbolId, keys: Vec<(String, bool)>) {
        let mut registered = Vec::with_capacity(keys.len());
        for (key, strong) in keys {
            if strong || !self.name_index.contains_key(&key) {
                self.name_index.insert(key.clone(), symbol_id.clone());
                registered.push(key);
            }
        }
        self.keys_by_symbol
            .entry(symbol_id.clone())
            .or_default()
            .extend(registered);
    }

    /// Remove all of `path`'s contributions to every map. Safe to call on a file that
    /// was never indexed (no-op).
    pub fn remove_file(&mut self, path: &Path) {
        if let Some(symbols) = self.defined_by_file.remove(path) {
            for symbol_id in symbols {
                if self
                    .definitions
                    .get(&symbol_id)
                    .is_some_and(|def| def.file == path)
                {
                    self.definitions.remove(&symbol_id);
                }
                // Retract only the keys this symbol itself registered, and only where
                // they still point at this symbol (a later file may have legitimately
                // overwritten a strong key with a different symbol in the meantime).
                if let Some(keys) = self.keys_by_symbol.remove(&symbol_id) {
                    for key in keys {
                        if self.name_index.get(&key) == Some(&symbol_id) {
                            self.name_index.remove(&key);
                        }
                    }
                }
            }
        }
        if let Some(symbols) = self.referenced_by_file.remove(path) {
            for symbol_id in symbols {
                if let Some(files) = self.references.get_mut(&symbol_id) {
                    files.remove(path);
                    if files.is_empty() {
                        self.references.remove(&symbol_id);
                    }
                }
            }
        }
    }

    pub fn definition(&self, symbol: &SymbolId) -> Option<&SymbolDefinition> {
        self.definitions.get(symbol)
    }

    pub fn referencing_files(&self, symbol: &SymbolId) -> impl Iterator<Item = &PathBuf> {
        self.references.get(symbol).into_iter().flatten()
    }

    /// The minimal set of files whose cross-file edges need re-resolving after
    /// `changed_symbols` (typically: every symbol defined or referenced in a just-edited
    /// file) changed — every file that references any of them, plus the defining file(s)
    /// themselves. This is the scoped alternative to
    /// `Workspace::build_cross_file_edges`'s O(all files) rebuild.
    pub fn affected_files(&self, changed_symbols: &[SymbolId]) -> HashSet<PathBuf> {
        let mut affected = HashSet::new();
        for symbol in changed_symbols {
            if let Some(def) = self.definitions.get(symbol) {
                affected.insert(def.file.clone());
            }
            affected.extend(self.referencing_files(symbol).cloned());
        }
        affected
    }

    pub fn symbol_count(&self) -> usize {
        self.definitions.len()
    }

    /// Iterate every known (symbol, definition site) pair. Used by callers that need to
    /// search by name rather than look up an exact `SymbolId` — e.g. an MCP `find_definition`
    /// tool resolving a human-typed simple/qualified name against the whole workspace.
    pub fn definitions(&self) -> impl Iterator<Item = (&SymbolId, &SymbolDefinition)> {
        self.definitions.iter()
    }
}

/// The candidate name-index keys for one `MethodDef` node, paired with whether each is
/// a "strong" (always-overwrite) or "weak" (first-registration-wins) key. Mirrors
/// `Workspace::build_cross_file_edges`'s precedence: simple name (weak) < namespace::name
/// (weak) < class::name (weak) < fully-qualified name incl. per-language Java/Go
/// metadata (strong).
fn name_keys(
    cpg: &Cpg,
    node_id: NodeId,
    node: &web_sitter::IrNode,
    fn_name: &str,
) -> Vec<(String, bool)> {
    let mut keys = vec![(fn_name.to_string(), false)];

    if let Some(ns) = &node.namespace {
        keys.push((format!("{ns}::{fn_name}"), false));
    }
    if let Some(cls) = &node.class_context {
        keys.push((format!("{cls}::{fn_name}"), false));
    }
    if let Some(qname) = &node.qualified_name {
        keys.push((qname.clone(), true));
    }
    if let Some(fqc) = cpg
        .java_metadata
        .get(&node_id)
        .and_then(|m| m.fully_qualified_class.as_ref())
    {
        keys.push((format!("{fqc}.{fn_name}"), true));
    }
    if let Some(qname) = cpg
        .go_metadata
        .get(&node_id)
        .and_then(|m| m.qualified_name.as_ref())
    {
        keys.push((qname.clone(), true));
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use web_sitter::cpg_generator::{GraphBuildOptions, SourceLanguage};
    use web_sitter::incremental::IncrementalCpgGenerator;

    fn parse(lang: SourceLanguage, src: &str) -> Cpg {
        let mut generator =
            IncrementalCpgGenerator::new_for_language(lang, GraphBuildOptions::default())
                .expect("generator");
        generator.parse_full(src.as_bytes()).expect("parse").clone()
    }

    fn symbol(cpg: &Cpg, qualified: &str) -> SymbolId {
        build_symbol_table(cpg)
            .into_values()
            .find(|s| s.as_str() == format!("{}:{}", cpg.language, qualified))
            .unwrap_or_else(|| panic!("no symbol {qualified} in {:?}", cpg.language))
    }

    #[test]
    fn definitions_are_indexed_per_file() {
        let cpg = parse(SourceLanguage::Cpp, "int helper(int y) { return y; }");
        let path = PathBuf::from("a.cpp");
        let index = ReverseSymbolIndex::build([(path.as_path(), &cpg)]);

        let sym = symbol(&cpg, "helper");
        let def = index.definition(&sym).expect("definition present");
        assert_eq!(def.file, path);
    }

    #[test]
    fn cross_file_reference_is_indexed() {
        let callee_cpg = parse(SourceLanguage::Cpp, "int helper(int y) { return y; }");

        let mut caller_cpg = parse(SourceLanguage::Cpp, "int caller() { return helper(1); }");
        // Simulate what Workspace::build_cross_file_edges' upstream pass (parsing +
        // call-edge extraction) already populates on `cpg.workspace.cross_file_calls`
        // for an unresolved call — this module consumes that field, it doesn't produce it.
        let call_node_id = caller_cpg
            .ast
            .iter()
            .find(|(_, n)| n.kind == IrNodeKind::Call)
            .map(|(id, _)| *id)
            .expect("call node");
        caller_cpg
            .workspace
            .cross_file_calls
            .push(web_sitter::CrossFileCallEdge {
                call_node: call_node_id,
                caller_fn: 0,
                callee_name: "helper".to_string(),
                qualified_callee: None,
                arg_positions: vec![],
            });

        let callee_path = PathBuf::from("callee.cpp");
        let caller_path = PathBuf::from("caller.cpp");
        let index = ReverseSymbolIndex::build([
            (callee_path.as_path(), &callee_cpg),
            (caller_path.as_path(), &caller_cpg),
        ]);

        let sym = symbol(&callee_cpg, "helper");
        let referencing: Vec<&PathBuf> = index.referencing_files(&sym).collect();
        assert_eq!(referencing, vec![&caller_path]);
    }

    /// Regression test: `build`'s input is commonly a `HashMap` iterator with no defined
    /// order. This is the exact case that was previously broken — a naive "define +
    /// resolve as you go" single pass (what `build` used to do, delegating straight to
    /// `upsert_file` per file) drops any reference whose defining file is visited *after*
    /// the referencing file, because the name index doesn't have that definition's key
    /// registered yet at resolution time. Feeding the caller before the callee here
    /// reproduces that exact ordering.
    #[test]
    fn cross_file_reference_is_indexed_even_when_caller_is_processed_before_callee() {
        let callee_cpg = parse(SourceLanguage::Cpp, "int helper(int y) { return y; }");

        let mut caller_cpg = parse(SourceLanguage::Cpp, "int caller() { return helper(1); }");
        let call_node_id = caller_cpg
            .ast
            .iter()
            .find(|(_, n)| n.kind == IrNodeKind::Call)
            .map(|(id, _)| *id)
            .expect("call node");
        caller_cpg
            .workspace
            .cross_file_calls
            .push(web_sitter::CrossFileCallEdge {
                call_node: call_node_id,
                caller_fn: 0,
                callee_name: "helper".to_string(),
                qualified_callee: None,
                arg_positions: vec![],
            });

        let callee_path = PathBuf::from("callee.cpp");
        let caller_path = PathBuf::from("caller.cpp");
        // Caller listed *first* — the ordering that used to silently lose the edge.
        let index = ReverseSymbolIndex::build([
            (caller_path.as_path(), &caller_cpg),
            (callee_path.as_path(), &callee_cpg),
        ]);

        let sym = symbol(&callee_cpg, "helper");
        let referencing: Vec<&PathBuf> = index.referencing_files(&sym).collect();
        assert_eq!(referencing, vec![&caller_path]);
    }

    #[test]
    fn affected_files_includes_definition_and_references() {
        let callee_cpg = parse(SourceLanguage::Cpp, "int helper(int y) { return y; }");
        let mut caller_cpg = parse(SourceLanguage::Cpp, "int caller() { return helper(1); }");
        let call_node_id = caller_cpg
            .ast
            .iter()
            .find(|(_, n)| n.kind == IrNodeKind::Call)
            .map(|(id, _)| *id)
            .expect("call node");
        caller_cpg
            .workspace
            .cross_file_calls
            .push(web_sitter::CrossFileCallEdge {
                call_node: call_node_id,
                caller_fn: 0,
                callee_name: "helper".to_string(),
                qualified_callee: None,
                arg_positions: vec![],
            });

        let callee_path = PathBuf::from("callee.cpp");
        let caller_path = PathBuf::from("caller.cpp");
        let index = ReverseSymbolIndex::build([
            (callee_path.as_path(), &callee_cpg),
            (caller_path.as_path(), &caller_cpg),
        ]);

        let sym = symbol(&callee_cpg, "helper");
        let affected = index.affected_files(&[sym]);
        assert_eq!(
            affected,
            HashSet::from([callee_path, caller_path]),
            "changing the definition must invalidate both its own file and every referencing file"
        );
    }

    #[test]
    fn upsert_file_clears_stale_references_before_reindexing() {
        let callee_cpg = parse(SourceLanguage::Cpp, "int helper(int y) { return y; }");
        let mut caller_cpg = parse(SourceLanguage::Cpp, "int caller() { return helper(1); }");
        let call_node_id = caller_cpg
            .ast
            .iter()
            .find(|(_, n)| n.kind == IrNodeKind::Call)
            .map(|(id, _)| *id)
            .expect("call node");
        caller_cpg
            .workspace
            .cross_file_calls
            .push(web_sitter::CrossFileCallEdge {
                call_node: call_node_id,
                caller_fn: 0,
                callee_name: "helper".to_string(),
                qualified_callee: None,
                arg_positions: vec![],
            });

        let callee_path = PathBuf::from("callee.cpp");
        let caller_path = PathBuf::from("caller.cpp");
        let mut index = ReverseSymbolIndex::build([
            (callee_path.as_path(), &callee_cpg),
            (caller_path.as_path(), &caller_cpg),
        ]);

        let sym = symbol(&callee_cpg, "helper");
        assert_eq!(index.referencing_files(&sym).count(), 1);

        // Re-edit caller.cpp to no longer call helper — upsert must drop the stale edge.
        let edited_caller_cpg = parse(SourceLanguage::Cpp, "int caller() { return 0; }");
        index.upsert_file(&caller_path, &edited_caller_cpg);

        assert_eq!(
            index.referencing_files(&sym).count(),
            0,
            "stale reference from the old version of caller.cpp must be gone after upsert"
        );
    }

    #[test]
    fn remove_file_drops_its_definitions() {
        let cpg = parse(SourceLanguage::Cpp, "int helper(int y) { return y; }");
        let path = PathBuf::from("a.cpp");
        let mut index = ReverseSymbolIndex::build([(path.as_path(), &cpg)]);
        let sym = symbol(&cpg, "helper");
        assert!(index.definition(&sym).is_some());

        index.remove_file(&path);
        assert!(index.definition(&sym).is_none());
        assert_eq!(index.symbol_count(), 0);
    }

    #[test]
    fn definitions_iterates_every_indexed_symbol() {
        let a = parse(SourceLanguage::Cpp, "int helper(int y) { return y; }");
        let b = parse(SourceLanguage::Cpp, "int other(int z) { return z; }");
        let index = ReverseSymbolIndex::build([
            (PathBuf::from("a.cpp").as_path(), &a),
            (PathBuf::from("b.cpp").as_path(), &b),
        ]);

        let names: std::collections::BTreeSet<&str> =
            index.definitions().map(|(id, _)| id.as_str()).collect();
        assert_eq!(
            names,
            std::collections::BTreeSet::from(["cpp:helper", "cpp:other"])
        );
    }

    /// Differential test: `ReverseSymbolIndex::referencing_files` (scoped, incremental)
    /// must agree with `Workspace::build_cross_file_edges` (full, O(all files) rebuild)
    /// about which files call a given function — using real parses, so `cross_file_calls`
    /// is populated by the actual CFG/DFG pipeline rather than hand-injected.
    #[test]
    fn matches_full_workspace_rebuild_for_a_real_cross_file_call() {
        use crate::taint::EndpointRegistry;
        use crate::workspace::Workspace;

        let callee_src = "int helper(int y) { return y * 2; }";
        let caller_src = "int caller(int x) { return helper(x); }";
        let unrelated_src = "int unrelated(int z) { return z + 1; }";

        let callee_cpg = parse(SourceLanguage::Cpp, callee_src);
        let caller_cpg = parse(SourceLanguage::Cpp, caller_src);
        let unrelated_cpg = parse(SourceLanguage::Cpp, unrelated_src);

        let callee_path = PathBuf::from("callee.cpp");
        let caller_path = PathBuf::from("caller.cpp");
        let unrelated_path = PathBuf::from("unrelated.cpp");

        // Full rebuild via the existing Workspace path.
        let mut workspace = Workspace::new(EndpointRegistry::new());
        workspace.upsert_file(callee_path.clone(), callee_cpg.clone(), 1);
        workspace.upsert_file(caller_path.clone(), caller_cpg.clone(), 1);
        workspace.upsert_file(unrelated_path.clone(), unrelated_cpg.clone(), 1);
        workspace.build_cross_file_edges();

        let workspace_referencing_files: HashSet<PathBuf> = workspace
            .cross_file_callee_params
            .iter()
            .filter(|(_, resolutions)| resolutions.iter().any(|(f, _)| f == &callee_path))
            .map(|(call_site, _)| call_site.file.clone())
            .collect();
        assert_eq!(
            workspace_referencing_files,
            HashSet::from([caller_path.clone()]),
            "sanity check: the full Workspace rebuild must itself find the real call edge"
        );

        // Scoped rebuild via ReverseSymbolIndex.
        let index = ReverseSymbolIndex::build([
            (callee_path.as_path(), &callee_cpg),
            (caller_path.as_path(), &caller_cpg),
            (unrelated_path.as_path(), &unrelated_cpg),
        ]);
        let sym = symbol(&callee_cpg, "helper");
        let index_referencing_files: HashSet<PathBuf> =
            index.referencing_files(&sym).cloned().collect();

        assert_eq!(
            index_referencing_files, workspace_referencing_files,
            "ReverseSymbolIndex must agree with a full Workspace::build_cross_file_edges rebuild"
        );
    }
}
