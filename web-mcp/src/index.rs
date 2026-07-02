//! Batch workspace indexing: walk `--root`, build every file's CPG, and derive the two
//! indexes every tool needs (`Workspace` for call-graph/DFG/rule-eval facts,
//! `ReverseSymbolIndex` for symbol -> definition/reference lookups).
//!
//! Phase 1 scope: single-shard, in-memory, built once at startup — mirrors the batch
//! pipeline `web-scan/src/main.rs` already uses (walk -> parse -> `Workspace::upsert_file`
//! -> `build_cross_file_edges`), not yet the incremental/live-update system Phase 2 adds.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rayon::prelude::*;
use web_ql::symbol_index::ReverseSymbolIndex;
use web_ql::workspace::Workspace;
use web_sitter::{CpgGenerator, GraphBuildOptions, language_from_path};

/// Walk `root`, parse every recognized source file, and build the batch `Workspace` plus
/// its `ReverseSymbolIndex`. Errors from individual files are swallowed (best-effort,
/// matching `web-scan`'s behavior) — a single unparseable file shouldn't take down
/// indexing for the rest of a large repo; only I/O errors walking the tree itself
/// propagate.
pub fn build_workspace(root: &Path) -> Result<(Workspace, ReverseSymbolIndex)> {
    let files = discover_files(root)?;

    let registry = web_ql::security_patterns::builtin_endpoint_registry();
    let mut workspace = Workspace::new(registry);

    let parsed: Vec<(PathBuf, Result<web_sitter::Cpg>)> = files
        .par_iter()
        .map(|path| (path.clone(), build_cpg(path)))
        .collect();

    for (path, result) in parsed {
        match result {
            Ok(cpg) => {
                workspace.upsert_file(path, cpg, 0);
            }
            Err(e) => {
                tracing::debug!(file = %path.display(), error = %e, "skipping unparseable file");
            }
        }
    }

    workspace.build_cross_file_edges();

    let reverse_index = ReverseSymbolIndex::build(
        workspace
            .files
            .iter()
            .map(|(path, idx)| (path.as_path(), idx.cpg.as_ref())),
    );

    Ok((workspace, reverse_index))
}

fn build_cpg(path: &Path) -> Result<web_sitter::Cpg> {
    let language = language_from_path(path.to_str().unwrap_or(""));
    let mut generator = CpgGenerator::new_for_language(language)
        .with_context(|| format!("creating CPG generator for {}", path.display()))?;
    generator
        .generate_from_file_with_options(path, GraphBuildOptions::default())
        .with_context(|| format!("generating CPG for {}", path.display()))
}

fn discover_files(root: &Path) -> Result<Vec<PathBuf>> {
    let known_extensions: HashSet<&str> = [
        "c", "h", "cpp", "cc", "cxx", "hpp", "go", "py", "java", "js", "mjs", "ts", "tsx", "rs",
    ]
    .into_iter()
    .collect();

    let mut files = Vec::new();
    walk_dir(root, &known_extensions, &mut files)?;
    files.sort();
    Ok(files)
}

fn walk_dir(dir: &Path, extensions: &HashSet<&str>, out: &mut Vec<PathBuf>) -> Result<()> {
    let entries =
        std::fs::read_dir(dir).with_context(|| format!("reading directory {}", dir.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.')
                || matches!(name.as_ref(), "target" | "node_modules" | "vendor" | ".git")
            {
                continue;
            }
            walk_dir(&path, extensions, out)?;
        } else if file_type.is_file()
            && let Some(ext) = path.extension().and_then(|e| e.to_str())
            && extensions.contains(ext)
        {
            out.push(path);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexes_a_small_fixture_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("callee.cpp"),
            "int helper(int y) { return y * 2; }",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("caller.cpp"),
            "int caller(int x) { return helper(x); }",
        )
        .unwrap();
        // Non-source files must be skipped, not error the walk.
        std::fs::write(dir.path().join("README.md"), "not code").unwrap();

        let (workspace, reverse_index) = build_workspace(dir.path()).expect("build_workspace");

        assert_eq!(
            workspace.files.len(),
            2,
            "only the two .cpp files should be indexed"
        );
        assert!(
            reverse_index.symbol_count() >= 2,
            "helper and caller must both be defined symbols"
        );
    }

    #[test]
    fn skips_excluded_directories() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join("node_modules")).unwrap();
        std::fs::write(
            dir.path().join("node_modules/vendored.js"),
            "function shouldNotBeIndexed() {}",
        )
        .unwrap();
        std::fs::write(dir.path().join("real.js"), "function real() {}").unwrap();

        let (workspace, _) = build_workspace(dir.path()).expect("build_workspace");
        assert_eq!(workspace.files.len(), 1);
        assert!(workspace.files.keys().next().unwrap().ends_with("real.js"));
    }
}
