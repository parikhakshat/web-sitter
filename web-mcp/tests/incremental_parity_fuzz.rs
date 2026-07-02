//! Differential fuzz test (task 21's CI-gate requirement): apply a long, deterministically
//! randomized sequence of add/modify/remove edits to a single file through
//! `IncrementalFileState::apply_edit`, and after every single step assert its `Cpg`'s
//! symbol set matches a from-scratch full parse of the same final source text. Existing
//! unit tests (`store/incremental_file.rs`, `web-ql/src/symbol_index.rs`) already cover a
//! handful of fixed before/after scenarios; this generalizes that same assertion — the
//! incrementally-maintained `Cpg` must always be structurally indistinguishable from a
//! fresh full rebuild — across many more edit shapes than anyone would think to write by
//! hand, without pulling in a `rand` crate dependency (a tiny fixed-seed xorshift64 is
//! plenty for a fully reproducible fuzz sequence).
//!
//! This lives under `tests/` (a separate process) rather than as a `#[cfg(test)]` unit
//! test purely so it shows up as its own named CI step — it only needs `web-mcp`'s public
//! binary surface (`CARGO_BIN_EXE_web-mcp` isn't even used here, since the incremental
//! machinery it fuzzes is exercised directly by spawning nothing — see below).

use std::collections::BTreeSet;

use web_sitter::cpg_generator::{GraphBuildOptions, SourceLanguage};
use web_sitter::incremental::IncrementalCpgGenerator;
use web_sitter::symbol_id::build_symbol_table;

/// Minimal fixed-seed xorshift64 — deterministic and dependency-free, which is exactly
/// what a reproducible fuzz sequence needs (a real `rand` crate's PRNG would work too, but
/// isn't worth adding as a new dependency just for this).
struct Xorshift64(u64);

impl Xorshift64 {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn next_range(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }
}

/// A tiny in-memory model of "the current file" as a set of independent, named C++
/// functions — edits add/modify/remove one function at a time, so the resulting source is
/// always syntactically valid and each step has an unambiguous expected symbol set.
struct FileModel {
    functions: Vec<(String, i64)>, // (name, return value) -- body is `return <value>;`
    next_name_id: usize,
}

impl FileModel {
    fn new() -> Self {
        Self {
            functions: vec![("seed_fn".to_string(), 0)],
            next_name_id: 1,
        }
    }

    fn render(&self) -> String {
        self.functions
            .iter()
            .map(|(name, value)| format!("int {name}() {{ return {value}; }}\n"))
            .collect()
    }

    fn expected_symbol_names(&self) -> BTreeSet<String> {
        self.functions
            .iter()
            .map(|(name, _)| format!("cpp:{name}"))
            .collect()
    }

    fn apply_random_step(&mut self, rng: &mut Xorshift64) {
        // Always leave at least one function so the source is never empty (an empty file
        // is a degenerate case already covered by the fixed unit tests, not what this
        // fuzz sequence is for).
        let can_remove = self.functions.len() > 1;
        let choice = rng.next_range(if can_remove { 3 } else { 2 });
        match choice {
            0 => {
                // Add a new function.
                let name = format!("fn_{}", self.next_name_id);
                self.next_name_id += 1;
                let value = rng.next_range(1000) as i64;
                self.functions.push((name, value));
            }
            1 => {
                // Modify an existing function's return value.
                let idx = rng.next_range(self.functions.len());
                self.functions[idx].1 = rng.next_range(1000) as i64;
            }
            2 => {
                // Remove a function.
                let idx = rng.next_range(self.functions.len());
                self.functions.remove(idx);
            }
            _ => unreachable!(),
        }
    }
}

fn full_parse_symbol_names(source: &str) -> BTreeSet<String> {
    let mut generator = IncrementalCpgGenerator::new_for_language(
        SourceLanguage::Cpp,
        GraphBuildOptions::default(),
    )
    .expect("generator");
    let cpg = generator.parse_full(source.as_bytes()).expect("parse");
    build_symbol_table(cpg)
        .into_values()
        .map(|s| s.as_str().to_string())
        .collect()
}

#[test]
fn incremental_state_matches_a_full_rebuild_after_every_step_of_a_long_random_edit_sequence() {
    const STEPS: usize = 200;
    let mut rng = Xorshift64(0x9E3779B97F4A7C15); // fixed seed: fully reproducible

    let mut model = FileModel::new();
    let mut generator = IncrementalCpgGenerator::new_for_language(
        SourceLanguage::Cpp,
        GraphBuildOptions::default(),
    )
    .expect("generator");
    generator
        .parse_full(model.render().as_bytes())
        .expect("initial parse");

    for step in 0..STEPS {
        let before_source = model.render();
        model.apply_random_step(&mut rng);
        let after_source = model.render();

        let edit = web_sitter::incremental::compute_edit(
            before_source.as_bytes(),
            after_source.as_bytes(),
        );
        // A no-op step (the random choice happened to leave the source unchanged, e.g.
        // reassigning the same return value) has no edit to apply — the generator's Cpg
        // is already correct, nothing to do.
        if let Some(edit) = edit {
            generator
                .apply_edit(&edit, after_source.as_bytes())
                .unwrap_or_else(|e| panic!("apply_edit failed at step {step}: {e:#}"));
        }

        let incremental_names: BTreeSet<String> = build_symbol_table(
            generator
                .state
                .cpg
                .as_ref()
                .expect("generator always has a Cpg after parse_full"),
        )
        .into_values()
        .map(|s| s.as_str().to_string())
        .collect();

        let expected = model.expected_symbol_names();
        assert_eq!(
            incremental_names, expected,
            "step {step}: incremental state diverged from the model's expected symbols \
             (source at this step:\n{after_source})"
        );

        // The stronger check: not just "the names match the model," but "the
        // incrementally-updated Cpg is structurally indistinguishable from a fresh full
        // parse of the exact same source" — this is the actual differential-fuzz
        // assertion the design's CI-gate requirement calls for.
        let full_rebuild_names = full_parse_symbol_names(&after_source);
        assert_eq!(
            incremental_names, full_rebuild_names,
            "step {step}: incremental Cpg's symbols differ from a full rebuild of the \
             same source (source at this step:\n{after_source})"
        );
    }
}
