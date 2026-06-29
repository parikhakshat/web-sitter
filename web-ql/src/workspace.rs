use std::collections::HashMap;
use std::path::{Path, PathBuf};
use rayon::prelude::*;
use web_sitter::{Cpg, FunctionSummary, IrNodeKind, NodeId};
use web_profiler as prof;

use crate::cfg::FunctionCfg;
use crate::dfg::DfgIndex;
use crate::finding::Finding;
use crate::ir::RuleSet;
use crate::taint::EndpointRegistry;
use crate::engine::{EvalContext, RuleRunner};

// ── File index ────────────────────────────────────────────────────────────────

/// Per-file analysis artifacts cached across incremental scans.
pub struct FileIndex {
    pub path: PathBuf,
    pub cpg: Cpg,
    pub dfg: DfgIndex,
    pub cfg_cache: HashMap<NodeId, FunctionCfg>,
    /// Content hash (mtime + size) for invalidation.
    pub content_hash: u64,
    /// Approximate memory footprint in bytes (for profiler cache tracking).
    pub size_estimate: u64,
}

impl FileIndex {
    /// Build all analysis artifacts from a freshly loaded CPG.
    pub fn build(path: PathBuf, cpg: Cpg, content_hash: u64) -> Self {
        let _span = prof::span("query.index_file");

        let size_estimate = estimate_cpg_bytes(&cpg);

        let dfg = {
            let _s = prof::span("query.build_dfg_index");
            DfgIndex::build(&cpg)
        };

        let cfg_cache = {
            let _s = prof::span("query.build_cfg_cache");
            build_cfg_cache(&cpg)
        };

        prof::cache_insert("file_index", size_estimate);
        prof::count("cfg_functions_cached", cfg_cache.len() as u64);

        Self { path, cpg, dfg, cfg_cache, content_hash, size_estimate }
    }
}

fn build_cfg_cache(cpg: &Cpg) -> HashMap<NodeId, FunctionCfg> {
    let fn_ids: Vec<NodeId> = cpg
        .ast
        .iter()
        .filter(|(_, n)| {
            matches!(n.kind, IrNodeKind::MethodDef | IrNodeKind::LambdaDef)
        })
        .map(|(id, _)| *id)
        .collect();

    // Build CFGs in parallel — each function is independent.
    fn_ids
        .par_iter()
        .map(|&fn_id| {
            let cfg = FunctionCfg::build_for_function(cpg, fn_id);
            (fn_id, cfg)
        })
        .collect()
}

/// Rough byte-size estimate for a CPG (used for cache reporting).
fn estimate_cpg_bytes(cpg: &Cpg) -> u64 {
    let ast_bytes = cpg.ast.len() as u64 * 256; // ~256 bytes per IrNode
    let bb_bytes = cpg.basic_blocks.len() as u64 * 128;
    let dfg_bytes = cpg.dataflow.edges.len() as u64 * 32;
    ast_bytes + bb_bytes + dfg_bytes
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
                prof::cache_hit("file_index");
                return false; // unchanged
            }
            prof::cache_miss("file_index");
        } else {
            prof::cache_miss("file_index");
        }

        // Merge function summaries from this CPG.
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

    /// Run the rule set over all indexed files in parallel, returning all findings.
    ///
    /// Files are evaluated concurrently via rayon — each file gets its own
    /// independent [`EvalContext`] so there is no cross-file shared mutable state.
    pub fn scan(&self, rule_set: &RuleSet) -> Vec<Finding> {
        let _span = prof::span("query.scan_total");
        let predicate_plans = HashMap::new();

        let findings: Vec<Finding> = self
            .files
            .par_iter()
            .flat_map(|(path, file_idx)| {
                let _task = prof::task();
                let _span = prof::span("query.scan_file");

                let ctx = EvalContext {
                    cpg: &file_idx.cpg,
                    dfg: &file_idx.dfg,
                    cfg_cache: &file_idx.cfg_cache,
                    summaries: &self.summaries,
                    registry: &self.registry,
                    predicate_plans: &predicate_plans,
                };

                let runner = RuleRunner::new(ctx);
                let file_findings = runner.run(rule_set);

                prof::count("files_scanned", 1);
                prof::count("findings_emitted", file_findings.len() as u64);

                file_findings
            })
            .collect();

        findings
    }

    /// Run the rule set over all files using a custom rayon pool for isolation.
    /// This lets you control thread count independently of the global rayon pool.
    pub fn scan_with_pool(
        &self,
        rule_set: &RuleSet,
        pool: &web_profiler::ProfiledPool,
    ) -> Vec<Finding> {
        pool.install(|| self.scan(rule_set))
    }

    /// Total number of indexed nodes across all files.
    pub fn total_nodes(&self) -> usize {
        self.files.values().map(|f| f.cpg.ast.len()).sum()
    }

    /// Total estimated memory footprint of all file indexes.
    pub fn total_size_bytes(&self) -> u64 {
        self.files.values().map(|f| f.size_estimate).sum()
    }
}
