//! Glean-style layered facts over [`ReverseSymbolIndex`]: a stable **base** layer (built
//! once from the bulk of a monorepo — third-party/vendor code, rarely-touched modules)
//! plus a thin **overlay** layer holding only the files that have actually been edited
//! since the base was built. Queries merge the two at read time: overlay wins where it
//! has an opinion, base fills in everywhere else.
//!
//! Why this exists (see `docs/mcp-server-design.md`'s Monorepo-Scale Storage section):
//! `ReverseSymbolIndex::upsert_file` is already O(1 file) to *apply*, but every apply
//! mutates one shared structure — at 100k+ files, periodically re-deriving that whole
//! structure (e.g. to reclaim memory, or to hand a consistent snapshot to a new reader)
//! means walking every file again, including the 99% that were never touched. Splitting
//! into base + overlay means only the overlay — bounded by how many files are *currently*
//! being edited, not by repo size — needs to be rebuilt or walked for those operations;
//! the base layer is untouched.
//!
//! Overlay files may reference symbols that only the base layer defines (a normal,
//! common case — most call sites in an edited file point at unedited code). Resolving
//! those needs `ReverseSymbolIndex::upsert_file_with_fallback`, not the plain
//! `upsert_file` a standalone index would use.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use web_sitter::Cpg;
use web_sitter::symbol_id::SymbolId;

use crate::symbol_index::{ReverseSymbolIndex, SymbolDefinition};

/// A stable base layer plus a thin overlay of actively-edited files, queried as one
/// merged index.
pub struct LayeredSymbolIndex {
    base: ReverseSymbolIndex,
    overlay: ReverseSymbolIndex,
    /// Every file the overlay has an opinion about (edited or removed since the base was
    /// built) — lets queries know when the base layer's data for a file is stale and must
    /// be ignored in favor of (possibly empty) overlay data.
    overlaid_files: HashSet<PathBuf>,
}

impl LayeredSymbolIndex {
    /// Start a new layered index from an already-built base layer, with an empty overlay.
    pub fn new(base: ReverseSymbolIndex) -> Self {
        Self {
            base,
            overlay: ReverseSymbolIndex::new(),
            overlaid_files: HashSet::new(),
        }
    }

    /// Apply a file's current contents to the overlay layer — the operation a live
    /// watcher calls after each incremental reparse. Never touches the base layer.
    pub fn apply_file_update(&mut self, path: &Path, cpg: &Cpg) {
        self.overlay
            .upsert_file_with_fallback(path, cpg, &self.base);
        self.overlaid_files.insert(path.to_path_buf());
    }

    /// Record that `path` no longer exists. Like `apply_file_update`, this only touches
    /// the overlay: the base layer's stale contribution for `path` is masked (not
    /// deleted) by `overlaid_files` from now on.
    pub fn remove_file(&mut self, path: &Path) {
        self.overlay.remove_file(path);
        self.overlaid_files.insert(path.to_path_buf());
    }

    /// Fold the overlay into a fresh base layer and drop it — the operation a periodic
    /// compaction pass calls once the overlay has grown large enough that per-query
    /// merging costs more than a one-time re-flatten. `files` must supply the *current*
    /// CPG for every overlaid file (and only those need to be re-supplied — untouched
    /// base-layer files are carried over as-is via `remove_file`'s masking already being
    /// reflected in `base`... in practice callers pass the same file set they'd use to
    /// answer `overlaid_files()`).
    pub fn rebase<'a>(
        mut self,
        files: impl IntoIterator<Item = (&'a Path, &'a Cpg)>,
    ) -> ReverseSymbolIndex {
        for path in &self.overlaid_files {
            self.base.remove_file(path);
        }
        for (path, cpg) in files {
            self.base.upsert_file(path, cpg);
        }
        self.base
    }

    pub fn definition(&self, symbol: &SymbolId) -> Option<&SymbolDefinition> {
        if let Some(def) = self.overlay.definition(symbol) {
            return Some(def);
        }
        match self.base.definition(symbol) {
            Some(def) if !self.overlaid_files.contains(&def.file) => Some(def),
            _ => None,
        }
    }

    /// Merged set of files referencing `symbol`: base-layer references minus any file
    /// the overlay now has an opinion about, unioned with the overlay's own references.
    pub fn referencing_files(&self, symbol: &SymbolId) -> HashSet<PathBuf> {
        let mut files: HashSet<PathBuf> = self
            .base
            .referencing_files(symbol)
            .filter(|f| !self.overlaid_files.contains(*f))
            .cloned()
            .collect();
        files.extend(self.overlay.referencing_files(symbol).cloned());
        files
    }

    /// Merged scoped-invalidation set — see `ReverseSymbolIndex::affected_files`.
    pub fn affected_files(&self, changed_symbols: &[SymbolId]) -> HashSet<PathBuf> {
        let mut affected = HashSet::new();
        for symbol in changed_symbols {
            if let Some(def) = self.definition(symbol) {
                affected.insert(def.file.clone());
            }
            affected.extend(self.referencing_files(symbol));
        }
        affected
    }

    /// Files the overlay currently has an opinion about (edited or removed since the
    /// base was built) — the input a compaction pass needs to know what to re-supply to
    /// `rebase`.
    pub fn overlaid_files(&self) -> impl Iterator<Item = &PathBuf> {
        self.overlaid_files.iter()
    }

    pub fn overlay_len(&self) -> usize {
        self.overlaid_files.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet as StdHashSet;
    use web_sitter::IrNodeKind;
    use web_sitter::cpg_generator::{GraphBuildOptions, SourceLanguage};
    use web_sitter::incremental::IncrementalCpgGenerator;
    use web_sitter::symbol_id::build_symbol_table;

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

    fn cross_file_call(caller_cpg: &mut Cpg, callee_name: &str) {
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
                callee_name: callee_name.to_string(),
                qualified_callee: None,
                arg_positions: vec![],
            });
    }

    #[test]
    fn unedited_symbols_are_answered_from_the_base_layer() {
        let cpg = parse(SourceLanguage::Cpp, "int helper(int y) { return y; }");
        let path = PathBuf::from("a.cpp");
        let base = ReverseSymbolIndex::build([(path.as_path(), &cpg)]);
        let layered = LayeredSymbolIndex::new(base);

        let sym = symbol(&cpg, "helper");
        assert_eq!(layered.definition(&sym).unwrap().file, path);
    }

    #[test]
    fn editing_a_file_moves_its_facts_to_the_overlay_and_masks_the_stale_base_entry() {
        let cpg = parse(SourceLanguage::Cpp, "int helper(int y) { return y; }");
        let path = PathBuf::from("a.cpp");
        let base = ReverseSymbolIndex::build([(path.as_path(), &cpg)]);
        let mut layered = LayeredSymbolIndex::new(base);

        let old_sym = symbol(&cpg, "helper");
        let renamed_cpg = parse(SourceLanguage::Cpp, "int renamed(int y) { return y; }");
        layered.apply_file_update(&path, &renamed_cpg);

        assert!(
            layered.definition(&old_sym).is_none(),
            "the old symbol must no longer resolve once its file has been overlaid"
        );
        let new_sym = symbol(&renamed_cpg, "renamed");
        assert_eq!(layered.definition(&new_sym).unwrap().file, path);
    }

    #[test]
    fn overlay_file_resolves_a_call_into_a_base_only_symbol() {
        let callee_cpg = parse(SourceLanguage::Cpp, "int helper(int y) { return y; }");
        let callee_path = PathBuf::from("callee.cpp");
        let caller_path = PathBuf::from("caller.cpp");

        // Base layer only knows about the callee — the caller is being introduced live,
        // through the overlay, and its call site must still resolve against the base's
        // name index.
        let base = ReverseSymbolIndex::build([(callee_path.as_path(), &callee_cpg)]);
        let mut layered = LayeredSymbolIndex::new(base);

        let mut caller_cpg = parse(SourceLanguage::Cpp, "int caller() { return helper(1); }");
        cross_file_call(&mut caller_cpg, "helper");
        layered.apply_file_update(&caller_path, &caller_cpg);

        let sym = symbol(&callee_cpg, "helper");
        assert_eq!(
            layered.referencing_files(&sym),
            StdHashSet::from([caller_path])
        );
    }

    #[test]
    fn re_editing_an_overlay_file_drops_its_stale_reference() {
        let callee_cpg = parse(SourceLanguage::Cpp, "int helper(int y) { return y; }");
        let callee_path = PathBuf::from("callee.cpp");
        let caller_path = PathBuf::from("caller.cpp");

        let base = ReverseSymbolIndex::build([(callee_path.as_path(), &callee_cpg)]);
        let mut layered = LayeredSymbolIndex::new(base);

        let mut caller_cpg = parse(SourceLanguage::Cpp, "int caller() { return helper(1); }");
        cross_file_call(&mut caller_cpg, "helper");
        layered.apply_file_update(&caller_path, &caller_cpg);

        let sym = symbol(&callee_cpg, "helper");
        assert_eq!(layered.referencing_files(&sym).len(), 1);

        let edited_caller_cpg = parse(SourceLanguage::Cpp, "int caller() { return 0; }");
        layered.apply_file_update(&caller_path, &edited_caller_cpg);
        assert!(layered.referencing_files(&sym).is_empty());
    }

    #[test]
    fn removing_a_file_masks_its_base_layer_references_too() {
        let callee_cpg = parse(SourceLanguage::Cpp, "int helper(int y) { return y; }");
        let mut caller_cpg = parse(SourceLanguage::Cpp, "int caller() { return helper(1); }");
        cross_file_call(&mut caller_cpg, "helper");
        let callee_path = PathBuf::from("callee.cpp");
        let caller_path = PathBuf::from("caller.cpp");

        let base = ReverseSymbolIndex::build([
            (callee_path.as_path(), &callee_cpg),
            (caller_path.as_path(), &caller_cpg),
        ]);
        let mut layered = LayeredSymbolIndex::new(base);

        let sym = symbol(&callee_cpg, "helper");
        assert_eq!(layered.referencing_files(&sym).len(), 1);

        layered.remove_file(&caller_path);
        assert!(layered.referencing_files(&sym).is_empty());
    }

    #[test]
    fn affected_files_merges_base_and_overlay_across_a_live_edit() {
        let callee_cpg = parse(SourceLanguage::Cpp, "int helper(int y) { return y; }");
        let callee_path = PathBuf::from("callee.cpp");
        let base = ReverseSymbolIndex::build([(callee_path.as_path(), &callee_cpg)]);
        let mut layered = LayeredSymbolIndex::new(base);

        let mut caller_cpg = parse(SourceLanguage::Cpp, "int caller() { return helper(1); }");
        cross_file_call(&mut caller_cpg, "helper");
        let caller_path = PathBuf::from("caller.cpp");
        layered.apply_file_update(&caller_path, &caller_cpg);

        let sym = symbol(&callee_cpg, "helper");
        let affected = layered.affected_files(&[sym]);
        assert_eq!(
            affected,
            StdHashSet::from([callee_path, caller_path]),
            "affected_files must include the definition's file (base layer) and the \
             referencing file (overlay layer)"
        );
    }

    #[test]
    fn rebase_folds_the_overlay_into_a_fresh_base_with_no_stale_entries() {
        let cpg = parse(SourceLanguage::Cpp, "int helper(int y) { return y; }");
        let path = PathBuf::from("a.cpp");
        let base = ReverseSymbolIndex::build([(path.as_path(), &cpg)]);
        let mut layered = LayeredSymbolIndex::new(base);

        let old_sym = symbol(&cpg, "helper");
        let renamed_cpg = parse(SourceLanguage::Cpp, "int renamed(int y) { return y; }");
        layered.apply_file_update(&path, &renamed_cpg);
        assert_eq!(layered.overlay_len(), 1);

        let rebased = layered.rebase([(path.as_path(), &renamed_cpg)]);
        assert!(rebased.definition(&old_sym).is_none());
        let new_sym = symbol(&renamed_cpg, "renamed");
        assert_eq!(rebased.definition(&new_sym).unwrap().file, path);
    }
}
