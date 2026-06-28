use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use web_sitter::Cpg;
use crate::ast::RuleFile;
use crate::ir::RuleSet;
use crate::parser::parse_rule_file;
use crate::planner::Planner;

// ── CPG loader ────────────────────────────────────────────────────────────────

/// Load a CPG from a JSON file on disk.
pub fn load_cpg(path: &Path) -> Result<Cpg> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading CPG file {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("parsing CPG JSON from {}", path.display()))
}

// ── Rule loader ───────────────────────────────────────────────────────────────

/// Parse and compile a ScuzzQL rule file from source text.
pub fn compile_rules(source: &str) -> Result<RuleSet> {
    let ast: RuleFile = parse_rule_file(source)
        .map_err(|e| anyhow::anyhow!("parse error: {e}"))?;

    let mut planner = Planner::new();
    let rule_set = planner
        .compile(&ast)
        .map_err(|e| anyhow::anyhow!("planning error: {e}"))?;

    Ok(rule_set)
}

/// Parse and compile rules from a file on disk.
pub fn load_rules(path: &Path) -> Result<RuleSet> {
    let source = std::fs::read_to_string(path)
        .with_context(|| format!("reading rule file {}", path.display()))?;
    compile_rules(&source)
        .with_context(|| format!("compiling rules from {}", path.display()))
}

/// Load all `.wql` rule files from a directory (non-recursive).
pub fn load_rules_dir(dir: &Path) -> Result<Vec<RuleSet>> {
    let mut rule_sets = Vec::new();
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("reading rules directory {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("wql") {
            let rs = load_rules(&path)?;
            rule_sets.push(rs);
        }
    }
    Ok(rule_sets)
}

// ── Content hashing ───────────────────────────────────────────────────────────

/// Compute a fast content hash for a file to detect changes during incremental scans.
pub fn file_hash(path: &Path) -> Result<u64> {
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;

    let meta = std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?;

    let mut hasher = DefaultHasher::new();
    // Hash mtime + file size for a cheap "has this changed" check
    if let Ok(mtime) = meta.modified() {
        mtime.hash(&mut hasher);
    }
    meta.len().hash(&mut hasher);
    Ok(hasher.finish())
}
