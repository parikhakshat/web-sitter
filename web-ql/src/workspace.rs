use std::collections::HashMap;
use std::path::{Path, PathBuf};
use web_sitter::{Cpg, FunctionSummary, NodeId};
use crate::cfg::FunctionCfg;
use crate::dfg::DfgIndex;
use crate::finding::Finding;
use crate::ir::RuleSet;
use crate::taint::EndpointRegistry;
use crate::engine::{EvalContext, RuleRunner};

// ── Workspace index ───────────────────────────────────────────────────────────

/// Per-file analysis artifacts cached across incremental scans.
pub struct FileIndex {
    pub path: PathBuf,
    pub cpg: Cpg,
    pub dfg: DfgIndex,
    pub cfg_cache: HashMap<NodeId, FunctionCfg>,
    /// Content hash (SHA-256 / file mtime) for invalidation.
    pub content_hash: u64,
}

impl FileIndex {
    /// Build all analysis artifacts from a freshly loaded CPG.
    pub fn build(path: PathBuf, cpg: Cpg, content_hash: u64) -> Self {
        let dfg = DfgIndex::build(&cpg);
        let cfg_cache = build_cfg_cache(&cpg);
        Self { path, cpg, dfg, cfg_cache, content_hash }
    }
}

/// Build CFG analysis for every function in the CPG.
fn build_cfg_cache(cpg: &Cpg) -> HashMap<NodeId, FunctionCfg> {
    use web_sitter::IrNodeKind;
    let mut cache = HashMap::new();
    for (node_id, node) in &cpg.ast {
        if node.kind == IrNodeKind::MethodDef || node.kind == IrNodeKind::LambdaDef {
            let cfg = FunctionCfg::build_for_function(cpg, *node_id);
            cache.insert(*node_id, cfg);
        }
    }
    cache
}

// ── Workspace ─────────────────────────────────────────────────────────────────

/// The scanning workspace: manages per-file indexes and orchestrates evaluation.
pub struct Workspace {
    /// File path → analysis index
    pub files: HashMap<PathBuf, FileIndex>,
    /// Merged function summaries across all files.
    pub summaries: HashMap<String, FunctionSummary>,
    pub registry: EndpointRegistry,
}

impl Workspace {
    pub fn new(registry: EndpointRegistry) -> Self {
        Self {
            files: HashMap::new(),
            summaries: HashMap::new(),
            registry,
        }
    }

    /// Add or update a single file's CPG. Returns true if the file was new or changed.
    pub fn upsert_file(&mut self, path: PathBuf, cpg: Cpg, content_hash: u64) -> bool {
        if let Some(existing) = self.files.get(&path) {
            if existing.content_hash == content_hash {
                return false; // unchanged
            }
        }

        // Merge function summaries from this CPG
        for (_node_id, summary) in &cpg.function_summaries {
            self.summaries.insert(summary.name.clone(), summary.clone());
        }

        let idx = FileIndex::build(path.clone(), cpg, content_hash);
        self.files.insert(path, idx);
        true
    }

    /// Remove a file from the index (e.g. it was deleted).
    pub fn remove_file(&mut self, path: &Path) {
        self.files.remove(path);
    }

    /// Run the rule set over all indexed files, returning all findings.
    pub fn scan(&self, rule_set: &RuleSet) -> Vec<Finding> {
        let predicate_plans = HashMap::new();
        let mut findings = Vec::new();

        for (_path, file_idx) in &self.files {
            let ctx = EvalContext {
                cpg: &file_idx.cpg,
                dfg: &file_idx.dfg,
                cfg_cache: &file_idx.cfg_cache,
                summaries: &self.summaries,
                registry: &self.registry,
                predicate_plans: &predicate_plans,
            };
            let runner = RuleRunner::new(ctx);
            findings.extend(runner.run(rule_set));
        }

        findings
    }
}
