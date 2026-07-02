//! `IncrementalFileState`: the bridge between `web-sitter`'s per-file, edit-driven
//! `IncrementalCpgGenerator` and the workspace/reverse-index layer, which today only
//! knows how to consume a whole freshly-parsed `Cpg` (see `crate::index::build_workspace`,
//! which calls the *batch* `CpgGenerator`, never the incremental one). This is the
//! specific gap the design's "Incremental-System Unification" section calls out:
//! `Workspace::upsert_file` never calls into `IncrementalCpgGenerator`'s edit machinery —
//! `IncrementalFileState::apply_edit` is that missing call, plus the piece neither side
//! had before: turning an applied edit directly into the set of `SymbolId`s it affected,
//! so a caller (the file watcher, task #14) can feed that straight into
//! `ReverseSymbolIndex`'s scoped invalidation instead of re-diffing two full `Cpg`s
//! (which is what `impact_of_change`, built before this existed, still does).
//!
//! Scope for this task: the bridge type itself, standalone and tested against real
//! tree-sitter incremental reparses. Wiring a live `Workspace`/shard to hold one of these
//! per file, and having the file watcher (task #14) drive it, are the next two tasks —
//! this is the primitive they'll both build on.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::Result;
use web_sitter::Cpg;
use web_sitter::cpg_generator::{GraphBuildOptions, SourceLanguage};
use web_sitter::incremental::{IncrementalCpgGenerator, TextEdit, compute_edit};
use web_sitter::symbol_id::{SymbolId, build_symbol_table};

/// One file's live, edit-driven CPG state, plus enough bookkeeping to report exactly
/// which symbols an applied edit changed.
pub struct IncrementalFileState {
    generator: IncrementalCpgGenerator,
    source: Vec<u8>,
}

impl IncrementalFileState {
    /// Build the initial state from a full parse of `source`.
    pub fn from_source(language: SourceLanguage, source: &[u8]) -> Result<Self> {
        let mut generator =
            IncrementalCpgGenerator::new_for_language(language, GraphBuildOptions::default())?;
        generator.parse_full(source)?;
        Ok(Self {
            generator,
            source: source.to_vec(),
        })
    }

    /// The current `Cpg`, reflecting every edit applied so far.
    pub fn cpg(&self) -> &Cpg {
        self.generator
            .state
            .cpg
            .as_ref()
            .expect("IncrementalFileState always has a Cpg after from_source/apply_edit")
    }

    /// Apply the edit implied by `new_source` (the whole file's proposed new contents,
    /// not a pre-computed diff — mirrors `impact_of_change`'s request shape, which is the
    /// natural unit an MCP tool caller has: "here's what the file should read after this
    /// change") and return the `SymbolId`s whose definition changed (added, removed, or
    /// whose byte range moved/mutated). Returns an empty set for a no-op edit.
    pub fn apply_edit(&mut self, new_source: &[u8]) -> Result<BTreeSet<SymbolId>> {
        let Some(edit) = compute_edit(&self.source, new_source) else {
            return Ok(BTreeSet::new());
        };
        self.apply_text_edit(&edit, new_source)
    }

    /// Lower-level entry point for a caller that already has a `TextEdit` (e.g. from a
    /// real editor's change event rather than a full before/after source diff).
    pub fn apply_text_edit(
        &mut self,
        edit: &TextEdit,
        new_source: &[u8],
    ) -> Result<BTreeSet<SymbolId>> {
        let old_symbols = symbol_byte_ranges(self.cpg());
        let old_source = std::mem::replace(&mut self.source, new_source.to_vec());

        self.generator.apply_edit(edit, new_source)?;

        let new_symbols = symbol_byte_ranges(self.cpg());
        Ok(diff_symbols(
            &old_symbols,
            &new_symbols,
            &old_source,
            new_source,
        ))
    }

    /// The exact source bytes this state was last built/edited against — the warm-restart
    /// validity check compares this directly to a file's current on-disk bytes rather than
    /// maintaining a separate hash: `load_snapshot` already has to read this back in full
    /// to restore the generator's state, so a fresh hash of it buys nothing a direct
    /// `==` doesn't already give for free.
    pub fn source_bytes(&self) -> &[u8] {
        &self.source
    }

    /// Persist this file's full incremental state (source, `Cpg`, and every derived index
    /// `IncrementalCpgGenerator` maintains) to `path`, via `IncrementalCpgGenerator::
    /// save_state`. Pair with `load_snapshot` on the next process start to skip a full
    /// tree-sitter reparse for files whose on-disk content hasn't changed since the
    /// snapshot was taken.
    pub fn save_snapshot(&self, path: impl AsRef<Path>) -> Result<()> {
        self.generator.save_state(path)
    }

    /// Load a previously `save_snapshot`-ed state for `language`. Returns `Ok(None)` (not
    /// an error) when `path` doesn't exist or the snapshot's format version is stale —
    /// both are ordinary "cold start" outcomes, not failures; the caller falls back to
    /// `from_source`.
    pub fn load_snapshot(language: SourceLanguage, path: impl AsRef<Path>) -> Result<Option<Self>> {
        let mut generator =
            IncrementalCpgGenerator::new_for_language(language, GraphBuildOptions::default())?;
        if !generator.load_state(path)? {
            return Ok(None);
        }
        let source = generator.state.source_code.clone();
        Ok(Some(Self { generator, source }))
    }
}

fn symbol_byte_ranges(cpg: &Cpg) -> std::collections::HashMap<SymbolId, (usize, usize)> {
    let table = build_symbol_table(cpg);
    let mut ranges = std::collections::HashMap::new();
    for (node_id, symbol_id) in table {
        if let Some(node) = cpg.ast.get(&node_id)
            && let (Some(s), Some(e)) = (node.start_byte, node.end_byte)
        {
            ranges.insert(symbol_id, (s as usize, e as usize));
        }
    }
    ranges
}

fn diff_symbols(
    old: &std::collections::HashMap<SymbolId, (usize, usize)>,
    new: &std::collections::HashMap<SymbolId, (usize, usize)>,
    old_source: &[u8],
    new_source: &[u8],
) -> BTreeSet<SymbolId> {
    let mut changed = BTreeSet::new();
    let all_ids: BTreeSet<&SymbolId> = old.keys().chain(new.keys()).collect();
    for symbol_id in all_ids {
        match (old.get(symbol_id), new.get(symbol_id)) {
            (Some(_), None) | (None, Some(_)) => {
                changed.insert(symbol_id.clone());
            }
            (Some(&(os, oe)), Some(&(ns, ne))) => {
                let old_text = old_source.get(os..oe);
                let new_text = new_source.get(ns..ne);
                if old_text != new_text {
                    changed.insert(symbol_id.clone());
                }
            }
            (None, None) => unreachable!("symbol_id came from one of the two maps"),
        }
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_op_edit_reports_no_changed_symbols() {
        let src = "int helper(int y) { return y; }";
        let mut state =
            IncrementalFileState::from_source(SourceLanguage::Cpp, src.as_bytes()).unwrap();
        let changed = state.apply_edit(src.as_bytes()).unwrap();
        assert!(changed.is_empty(), "{changed:?}");
    }

    #[test]
    fn modifying_a_function_body_reports_it_changed() {
        let before = "int helper(int y) { return y; }\n";
        let after = "int helper(int y) { return y + 1; }\n";
        let mut state =
            IncrementalFileState::from_source(SourceLanguage::Cpp, before.as_bytes()).unwrap();

        let changed = state.apply_edit(after.as_bytes()).unwrap();
        let names: BTreeSet<&str> = changed.iter().map(|s| s.as_str()).collect();
        assert_eq!(names, BTreeSet::from(["cpp:helper"]), "{names:?}");

        // The generator's own Cpg must reflect the new source too, not just report the
        // diff — this is what makes it usable as the live state a caller keeps around.
        // Compare against the raw new-source bytes (not node.text, which
        // GraphBuildOptions::default()'s minimal_text setting doesn't reliably retain
        // for larger nodes) via each node's own byte range.
        let after_bytes = after.as_bytes();
        let contains_new_body = state.cpg().ast.values().any(|n| {
            matches!(
                (n.start_byte, n.end_byte),
                (Some(s), Some(e)) if after_bytes.get(s as usize..e as usize) == Some(b"y + 1")
            )
        });
        assert!(contains_new_body, "Cpg must reflect the edited body text");
    }

    #[test]
    fn adding_a_function_reports_it_added() {
        let before = "int a() { return 1; }\n";
        let after = "int a() { return 1; }\nint b() { return 2; }\n";
        let mut state =
            IncrementalFileState::from_source(SourceLanguage::Cpp, before.as_bytes()).unwrap();

        let changed = state.apply_edit(after.as_bytes()).unwrap();
        let names: BTreeSet<&str> = changed.iter().map(|s| s.as_str()).collect();
        assert_eq!(names, BTreeSet::from(["cpp:b"]), "{names:?}");
    }

    #[test]
    fn removing_a_function_reports_it_removed() {
        let before = "int a() { return 1; }\nint b() { return 2; }\n";
        let after = "int a() { return 1; }\n";
        let mut state =
            IncrementalFileState::from_source(SourceLanguage::Cpp, before.as_bytes()).unwrap();

        let changed = state.apply_edit(after.as_bytes()).unwrap();
        let names: BTreeSet<&str> = changed.iter().map(|s| s.as_str()).collect();
        assert_eq!(names, BTreeSet::from(["cpp:b"]), "{names:?}");
    }

    #[test]
    fn editing_one_function_does_not_report_an_unrelated_sibling_as_changed() {
        let before = "int a() { return 1; }\nint b() { return 2; }\n";
        let after = "int a() { return 100; }\nint b() { return 2; }\n";
        let mut state =
            IncrementalFileState::from_source(SourceLanguage::Cpp, before.as_bytes()).unwrap();

        let changed = state.apply_edit(after.as_bytes()).unwrap();
        let names: BTreeSet<&str> = changed.iter().map(|s| s.as_str()).collect();
        assert_eq!(names, BTreeSet::from(["cpp:a"]), "{names:?}");
    }

    #[test]
    fn cpg_reflects_the_latest_edit() {
        let before = "int a() { return 1; }\n";
        let after = "int a() { return 1; }\nint b() { return 2; }\n";
        let mut state =
            IncrementalFileState::from_source(SourceLanguage::Cpp, before.as_bytes()).unwrap();
        state.apply_edit(after.as_bytes()).unwrap();

        let names: BTreeSet<String> = build_symbol_table(state.cpg())
            .into_values()
            .map(|s| s.as_str().to_string())
            .collect();
        assert_eq!(
            names,
            BTreeSet::from(["cpp:a".to_string(), "cpp:b".to_string()])
        );
    }

    /// Differential test: after an edit, the incrementally-updated `Cpg`'s symbol set
    /// must match what a from-scratch full parse of the same final source produces.
    /// `apply_edit`'s job is to report *which* symbols changed cheaply, not to produce a
    /// structurally different result than a full rebuild would — this is the parity
    /// guarantee the design's Phase 2 test plan calls for.
    #[test]
    fn incremental_result_matches_a_fresh_full_parse() {
        let before = "int a() { return 1; }\nint b() { return 2; }\n";
        let after = "int a() { return 100; }\nint b() { return 2; }\nint c() { return 3; }\n";

        let mut incremental =
            IncrementalFileState::from_source(SourceLanguage::Cpp, before.as_bytes()).unwrap();
        incremental.apply_edit(after.as_bytes()).unwrap();
        let incremental_names: BTreeSet<String> = build_symbol_table(incremental.cpg())
            .into_values()
            .map(|s| s.as_str().to_string())
            .collect();

        let full =
            IncrementalFileState::from_source(SourceLanguage::Cpp, after.as_bytes()).unwrap();
        let full_names: BTreeSet<String> = build_symbol_table(full.cpg())
            .into_values()
            .map(|s| s.as_str().to_string())
            .collect();

        assert_eq!(incremental_names, full_names);
    }
}
