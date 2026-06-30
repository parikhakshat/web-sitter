use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use rayon::prelude::*;
use web_sitter::{Cpg, FunctionSummary, IrNodeKind, NodeId};
use web_profiler as prof;

use crate::alias::AliasIndex;
use crate::cfg::FunctionCfg;
use crate::dfg::DfgIndex;
use crate::finding::Finding;
use crate::ir::RuleSet;
use crate::kind_index::KindIndex;
use crate::nullability::NullabilityIndex;
use crate::size_tracking::AllocSizeIndex;
use crate::taint::{CrossFileTaintCtx, EndpointRegistry};
use crate::engine::{EvalContext, RuleRunner};

// ── File index ────────────────────────────────────────────────────────────────

/// Per-file analysis artifacts cached across incremental scans.
pub struct FileIndex {
    pub path: PathBuf,
    pub cpg: Cpg,
    pub dfg: DfgIndex,
    pub cfg_cache: HashMap<NodeId, FunctionCfg>,
    /// Node-kind / raw-node-type / call-site index — replaces repeated full-AST and
    /// full-call-graph scans during rule evaluation.
    pub kind_index: KindIndex,
    /// Pointer alias index (POINTS_TO edges).
    pub alias: AliasIndex,
    /// Buffer / allocation size index.
    pub sizes: AllocSizeIndex,
    /// Null-value propagation index.
    pub nullability: NullabilityIndex,
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

        let kind_index = {
            let _s = prof::span("query.build_kind_index");
            KindIndex::build(&cpg)
        };

        let dfg = {
            let _s = prof::span("query.build_dfg_index");
            DfgIndex::build(&cpg)
        };

        let cfg_cache = {
            let _s = prof::span("query.build_cfg_cache");
            build_cfg_cache(&cpg)
        };

        let alias = {
            let _s = prof::span("query.build_alias_index");
            AliasIndex::build(&cpg)
        };
        let sizes = {
            let _s = prof::span("query.build_size_index");
            AllocSizeIndex::build(&cpg)
        };
        let nullability = {
            let _s = prof::span("query.build_nullability_index");
            NullabilityIndex::build(&cpg, &kind_index)
        };

        prof::cache_insert("file_index", size_estimate);
        prof::count("cfg_functions_cached", cfg_cache.len() as u64);

        Self {
            path,
            cpg,
            dfg,
            cfg_cache,
            kind_index,
            alias,
            sizes,
            nullability,
            content_hash,
            size_estimate,
        }
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

/// Cheap change-detection signature for a `RuleSet`, used to invalidate
/// `Workspace::findings_cache` when a different rule set is scanned. Hashes the ordered
/// set of rule ids plus a per-rule clause count — enough to catch rules being added,
/// removed, or reordered. It does *not* hash clause bodies, so editing a rule's logic
/// in place while keeping the same id and clause count would not be detected; callers
/// that hot-reload rule bodies under a stable id should treat that as a "new rule set"
/// (e.g. by reconstructing the `RuleSet`) rather than relying on this signature alone.
fn rule_set_signature(rule_set: &RuleSet) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    rule_set.rules.len().hash(&mut hasher);
    for rule in &rule_set.rules {
        rule.id.hash(&mut hasher);
        rule.clauses.len().hash(&mut hasher);
    }
    hasher.finish()
}

// ── Workspace ─────────────────────────────────────────────────────────────────

/// The scanning workspace: manages per-file indexes and orchestrates evaluation.
pub struct Workspace {
    /// File path → analysis index
    pub files: HashMap<PathBuf, FileIndex>,
    /// Merged function summaries across all files.
    pub summaries: HashMap<String, FunctionSummary>,
    /// Which file contributed each summary (for incremental removal).
    summary_source: HashMap<String, PathBuf>,
    pub registry: EndpointRegistry,
    /// Maps a call_node_id (in a caller file) → list of (callee_file, callee_param_node_ids).
    /// Built by `build_cross_file_edges()` after all files are indexed.
    pub cross_file_callee_params: HashMap<NodeId, Vec<(PathBuf, Vec<NodeId>)>>,
    /// Flat map of (file_path) → (DfgIndex, Cpg) for cross-file taint traversal.
    /// Built by `build_cross_file_edges()` alongside `cross_file_callee_params`.
    pub cross_file_dfgs: HashMap<PathBuf, (DfgIndex, Cpg)>,
    /// Files that have been added/changed since the last scan. Used by
    /// `scan_incremental` to skip re-evaluating unchanged files.
    dirty_files: HashSet<PathBuf>,
    /// Per-file finding cache for incremental scans: the full result of the last
    /// `RuleRunner::run` for a clean file, reused as-is until that file is marked dirty.
    findings_cache: HashMap<PathBuf, Vec<Finding>>,
    /// Identity of the rule set used to populate `findings_cache`, so a scan with a
    /// different rule set (e.g. rules hot-reloaded) invalidates the whole cache instead
    /// of serving findings computed under a stale rule set.
    findings_cache_rule_set_sig: Option<u64>,
}

impl Workspace {
    pub fn new(registry: EndpointRegistry) -> Self {
        Self {
            files: HashMap::new(),
            summaries: HashMap::new(),
            summary_source: HashMap::new(),
            registry,
            cross_file_callee_params: HashMap::new(),
            cross_file_dfgs: HashMap::new(),
            dirty_files: HashSet::new(),
            findings_cache: HashMap::new(),
            findings_cache_rule_set_sig: None,
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

        // Remove stale summaries contributed by the previous version of this file.
        self.evict_summaries_for_file(&path);

        // When a file changes, cross-file edge caches are stale — clear them so
        // `build_cross_file_edges` must be called again before the next scan.
        self.cross_file_callee_params.clear();
        self.cross_file_dfgs.clear();

        // Invalidate the cached findings for this file.
        self.findings_cache.remove(&path);

        // Merge function summaries from this CPG.
        for (_node_id, summary) in &cpg.workspace.function_summaries {
            self.summary_source.insert(summary.name.clone(), path.clone());
            self.summaries.insert(summary.name.clone(), summary.clone());
        }

        let idx = FileIndex::build(path.clone(), cpg, content_hash);
        self.files.insert(path.clone(), idx);
        self.dirty_files.insert(path);
        true
    }

    /// Remove a file from the index (e.g. it was deleted).
    pub fn remove_file(&mut self, path: &Path) {
        self.files.remove(path);
        self.cross_file_dfgs.remove(path);
        // Clear cross-file edges entirely since other files may have referenced this one.
        self.cross_file_callee_params.clear();
        // Remove summaries that came from this file.
        self.evict_summaries_for_file(path);
        // Invalidate the cached findings for this file.
        self.findings_cache.remove(path);
        // All remaining files may now have stale cross-file results.
        for p in self.files.keys() {
            self.dirty_files.insert(p.clone());
        }
    }

    /// Remove all summaries that were contributed by `file`.
    fn evict_summaries_for_file(&mut self, file: &Path) {
        let stale: Vec<String> = self
            .summary_source
            .iter()
            .filter(|(_, src)| src.as_path() == file)
            .map(|(name, _)| name.clone())
            .collect();
        for name in stale {
            self.summary_source.remove(&name);
            self.summaries.remove(&name);
        }
    }

    /// Resolve cross-file call edges across all indexed files.
    ///
    /// Must be called after all files have been indexed via `upsert_file`.
    /// Builds `cross_file_callee_params` (caller call_node → callee file + param nodes)
    /// and `cross_file_dfgs` (callee file → DfgIndex + Cpg) so `TaintEngine`
    /// can propagate taint into callee files for full interprocedural accuracy.
    ///
    /// Uses fully-qualified names (qualified_name, class_context::name, namespace::name)
    /// to avoid collisions when multiple classes/namespaces define methods with the same
    /// simple name.
    pub fn build_cross_file_edges(&mut self) {
        let _span = prof::span("query.build_cross_file_edges");

        // Build a multi-key name → (file, param_node_ids) index from all function defs.
        // Each function is registered under up to four keys (most-specific first wins):
        //   1. fully-qualified name  (e.g. "std::string::append" or "com.example.Foo.bar")
        //   2. class_context::name   (e.g. "Foo::bar")
        //   3. namespace::name       (e.g. "myns::helper")
        //   4. simple name           (e.g. "bar")
        let mut fn_to_params: HashMap<String, (PathBuf, Vec<NodeId>)> = HashMap::new();

        for (path, idx) in &self.files {
            for (node_id, node) in &idx.cpg.ast {
                if node.kind != IrNodeKind::MethodDef {
                    continue;
                }
                let Some(fn_name) = &node.name else { continue };

                // Collect ParamDef children in order.
                let params: Vec<NodeId> = node
                    .children
                    .iter()
                    .filter(|&&child_id| {
                        idx.cpg
                            .ast
                            .get(&child_id)
                            .map(|n| n.kind == IrNodeKind::ParamDef)
                            .unwrap_or(false)
                    })
                    .copied()
                    .collect();

                let entry = (path.clone(), params);

                // Register under simple name (lowest priority — may be overwritten).
                fn_to_params.entry(fn_name.clone()).or_insert_with(|| entry.clone());

                // Register under namespace-qualified name (e.g. "myns::helper").
                if let Some(ns) = &node.namespace {
                    let ns_key = format!("{}::{}", ns, fn_name);
                    fn_to_params.entry(ns_key).or_insert_with(|| entry.clone());
                }

                // Register under class-qualified name (e.g. "Foo::bar").
                if let Some(cls) = &node.class_context {
                    let cls_key = format!("{}::{}", cls, fn_name);
                    fn_to_params.entry(cls_key).or_insert_with(|| entry.clone());
                }

                // Register under fully-qualified name (highest specificity).
                if let Some(qname) = &node.qualified_name {
                    // Fully-qualified name overrides everything — use insert directly.
                    fn_to_params.insert(qname.clone(), entry.clone());
                }

                // Also check the language-specific metadata side-tables for Java FQNs.
                if let Some(java_meta) = idx.cpg.java_metadata.get(node_id) {
                    if let Some(fqc) = &java_meta.fully_qualified_class {
                        let java_key = format!("{}.{}", fqc, fn_name);
                        fn_to_params.insert(java_key, entry.clone());
                    }
                }

                // Go: package-qualified name (e.g. "encoding/json.Marshal").
                if let Some(go_meta) = idx.cpg.go_metadata.get(node_id) {
                    if let Some(pkg) = &go_meta.package_name {
                        let go_key = format!("{}.{}", pkg, fn_name);
                        fn_to_params.entry(go_key).or_insert_with(|| entry.clone());
                    }
                    if let Some(qname) = &go_meta.qualified_name {
                        fn_to_params.insert(qname.clone(), entry.clone());
                    }
                }
            }
        }

        // Resolve cross_file_calls from each file against the multi-key function index.
        let mut callee_params: HashMap<NodeId, Vec<(PathBuf, Vec<NodeId>)>> = HashMap::new();
        for idx in self.files.values() {
            for edge in &idx.cpg.workspace.cross_file_calls {
                // Try resolution in specificity order: qualified → class::name → simple.
                let resolved = edge
                    .qualified_callee
                    .as_deref()
                    .and_then(|q| fn_to_params.get(q))
                    .or_else(|| fn_to_params.get(&edge.callee_name));

                if let Some((callee_file, callee_param_nodes)) = resolved {
                    callee_params
                        .entry(edge.call_node)
                        .or_default()
                        .push((callee_file.clone(), callee_param_nodes.clone()));
                }
            }
        }

        // Build the flat DFG map for cross-file taint traversal.
        // Reuse the already-built DfgIndex from each FileIndex (no double-build).
        let mut cross_dfgs: HashMap<PathBuf, (DfgIndex, Cpg)> = HashMap::new();
        let callee_files: HashSet<PathBuf> = callee_params
            .values()
            .flat_map(|v| v.iter().map(|(f, _)| f.clone()))
            .collect();
        for file in callee_files {
            if let Some(idx) = self.files.get(&file) {
                cross_dfgs.insert(file, (idx.dfg.clone(), idx.cpg.clone()));
            }
        }

        prof::count("cross_file_edges", callee_params.len() as u64);
        prof::count("cross_file_callee_files", cross_dfgs.len() as u64);

        self.cross_file_callee_params = callee_params;
        self.cross_file_dfgs = cross_dfgs;
    }

    /// Run the rule set over all indexed files in parallel, returning all findings.
    ///
    /// Files are evaluated concurrently via rayon — each file gets its own
    /// independent [`EvalContext`] so there is no cross-file shared mutable state.
    /// Cross-file taint context is read-only and shared across all file evaluations.
    pub fn scan(&self, rule_set: &RuleSet) -> Vec<Finding> {
        let _span = prof::span("query.scan_total");
        let predicate_plans = &rule_set.predicate_plans;
        let predicate_params = &rule_set.predicate_params;
        let cross_file_ctx = CrossFileTaintCtx {
            file_dfgs: &self.cross_file_dfgs,
            call_to_callee_params: &self.cross_file_callee_params,
        };
        let cross_file_ref = &cross_file_ctx;

        let findings: Vec<Finding> = self
            .files
            .par_iter()
            .flat_map(|(_, file_idx)| {
                let _task = prof::task();
                let _span = prof::span("query.scan_file");

                let ctx = EvalContext {
                    cpg: &file_idx.cpg,
                    dfg: &file_idx.dfg,
                    cfg_cache: &file_idx.cfg_cache,
                    kind_index: &file_idx.kind_index,
                    alias: &file_idx.alias,
                    sizes: &file_idx.sizes,
                    nullability: &file_idx.nullability,
                    summaries: &self.summaries,
                    registry: &self.registry,
                    predicate_plans,
                    predicate_params,
                    cross_file: Some(cross_file_ref),
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

    /// Run the rule set using a per-file findings cache for incremental scans.
    ///
    /// Files in `dirty_files` (new/changed since the last scan, or affected by a
    /// cross-file edge change) are re-evaluated; unchanged files reuse the findings
    /// cached from their last evaluation instead of re-running the whole rule set.
    /// After scanning, the dirty set is cleared and the cache is refreshed.
    ///
    /// If `rule_set` differs from the one the cache was built with (e.g. rules were
    /// hot-reloaded), the entire cache is invalidated and every file is re-evaluated —
    /// findings computed under a different rule set must never be served as-is.
    pub fn scan_incremental(&mut self, rule_set: &RuleSet) -> Vec<Finding> {
        let _span = prof::span("query.scan_incremental_total");

        let sig = rule_set_signature(rule_set);
        if self.findings_cache_rule_set_sig != Some(sig) {
            self.findings_cache.clear();
            self.dirty_files.extend(self.files.keys().cloned());
            self.findings_cache_rule_set_sig = Some(sig);
        }

        let predicate_plans = &rule_set.predicate_plans;
        let predicate_params = &rule_set.predicate_params;
        let cross_file_ctx = CrossFileTaintCtx {
            file_dfgs: &self.cross_file_dfgs,
            call_to_callee_params: &self.cross_file_callee_params,
        };
        let cross_file_ref = &cross_file_ctx;
        let dirty = &self.dirty_files;
        let cache = &self.findings_cache;

        // Re-evaluate dirty files in parallel; clean files are read straight from cache
        // (cheap clone of already-computed `Finding`s, no RuleRunner work at all).
        let file_findings: Vec<(PathBuf, Vec<Finding>)> = self
            .files
            .par_iter()
            .map(|(path, file_idx)| {
                if !dirty.contains(path) {
                    if let Some(cached) = cache.get(path) {
                        prof::cache_hit("scan_incremental_findings");
                        return (path.clone(), cached.clone());
                    }
                }
                prof::cache_miss("scan_incremental_findings");

                let _span = prof::span("query.scan_file_incremental");
                let ctx = EvalContext {
                    cpg: &file_idx.cpg,
                    dfg: &file_idx.dfg,
                    cfg_cache: &file_idx.cfg_cache,
                    kind_index: &file_idx.kind_index,
                    alias: &file_idx.alias,
                    sizes: &file_idx.sizes,
                    nullability: &file_idx.nullability,
                    summaries: &self.summaries,
                    registry: &self.registry,
                    predicate_plans,
                    predicate_params,
                    cross_file: Some(cross_file_ref),
                };

                let runner = RuleRunner::new(ctx);
                let findings = runner.run(rule_set);

                prof::count("files_scanned", 1);
                prof::count("findings_emitted", findings.len() as u64);

                (path.clone(), findings)
            })
            .collect();

        // Flatten and refresh the per-file cache with the (possibly reused) results.
        let mut all_findings = Vec::with_capacity(file_findings.iter().map(|(_, f)| f.len()).sum());
        for (path, findings) in file_findings {
            self.findings_cache.insert(path, findings.clone());
            all_findings.extend(findings);
        }

        // Clear dirty set after successful scan.
        self.dirty_files.clear();

        all_findings
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

    /// Returns the set of files that have changed since the last scan.
    pub fn dirty_files(&self) -> &HashSet<PathBuf> {
        &self.dirty_files
    }
}
