use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use rayon::prelude::*;
use web_sitter::{Cpg, CpgEdgeData, CpgNodeData, CpgSubgraph, FunctionSummary, IrNodeKind, NodeId};
use web_profiler as prof;

use crate::alias::AliasIndex;
use crate::cfg::FunctionCfg;
use crate::dfg::DfgIndex;
use crate::finding::Finding;
use crate::ir::RuleSet;
use crate::kind_index::KindIndex;
use crate::nullability::NullabilityIndex;
use crate::node_ref::NodeRef;
use crate::size_tracking::AllocSizeIndex;
use crate::taint::{CrossFileTaintCtx, EndpointRegistry};
use crate::engine::{EvalContext, RuleRunner};

// ── File index ────────────────────────────────────────────────────────────────

/// Per-file analysis artifacts cached across incremental scans.
pub struct FileIndex {
    pub path: PathBuf,
    /// Arc-wrapped so cross-file taint context (`Workspace::cross_file_dfgs`) can share
    /// this CPG with other files via a cheap refcount bump instead of a full deep clone.
    pub cpg: Arc<Cpg>,
    pub dfg: Arc<DfgIndex>,
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
            cpg: Arc::new(cpg),
            dfg: Arc::new(dfg),
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
    /// Maps a call site (`NodeRef`, i.e. caller file + call_node_id) → list of
    /// (callee_file, callee_param_node_ids). Keyed by `NodeRef` rather than a bare
    /// `NodeId` because a `NodeId` is only unique within one file's CPG — see
    /// `NodeRef`'s docs.
    /// Built by `build_cross_file_edges()` after all files are indexed.
    pub cross_file_callee_params: HashMap<NodeRef, Vec<(PathBuf, Vec<NodeId>)>>,
    /// Flat map of (file_path) → (DfgIndex, Cpg) for cross-file taint traversal.
    /// Built by `build_cross_file_edges()` alongside `cross_file_callee_params`.
    /// Arc-wrapped — shares the same indexes already owned by `files`, no cloning.
    pub cross_file_dfgs: HashMap<PathBuf, (Arc<DfgIndex>, Arc<Cpg>)>,
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
        self.build_cross_file_edges_with_progress(|| {});
    }

    /// Like [`build_cross_file_edges`], but calls `on_file()` after each file's
    /// (expensive, per-node) key extraction completes, letting the caller drive
    /// a determinate progress bar for this stage instead of an indefinite spinner
    /// — this pass runs after all per-file CPGs (and their function summaries)
    /// are already built, and on a large workspace it can take long enough that
    /// having zero feedback during it looks like a hang.
    pub fn build_cross_file_edges_with_progress<F>(&mut self, on_file: F)
    where
        F: Fn() + Sync,
    {
        let _span = prof::span("query.build_cross_file_edges");

        // Build a multi-key name → (file, param_node_ids) index from all function defs.
        // Each function is registered under up to four keys (most-specific first wins):
        //   1. fully-qualified name  (e.g. "std::string::append" or "com.example.Foo.bar")
        //   2. class_context::name   (e.g. "Foo::bar")
        //   3. namespace::name       (e.g. "myns::helper")
        //   4. simple name           (e.g. "bar")
        //
        // The expensive per-node/per-file scan is independent across files, so it runs
        // in parallel; only the final merge into one shared map needs to stay sequential
        // (mirroring each key's original "first wins" vs "always overwrite" precedence).
        let per_file_keys: Vec<Vec<(String, bool, (PathBuf, Vec<NodeId>))>> = self
            .files
            .par_iter()
            .map(|(path, idx)| {
                let mut keys: Vec<(String, bool, (PathBuf, Vec<NodeId>))> = Vec::new();
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

                    // Simple name — lowest priority, first registration wins (`overwrite = false`).
                    keys.push((fn_name.clone(), false, entry.clone()));

                    // Namespace-qualified name (e.g. "myns::helper").
                    if let Some(ns) = &node.namespace {
                        keys.push((format!("{}::{}", ns, fn_name), false, entry.clone()));
                    }

                    // Class-qualified name (e.g. "Foo::bar").
                    if let Some(cls) = &node.class_context {
                        keys.push((format!("{}::{}", cls, fn_name), false, entry.clone()));
                    }

                    // Fully-qualified name — highest specificity, always overwrites.
                    if let Some(qname) = &node.qualified_name {
                        keys.push((qname.clone(), true, entry.clone()));
                    }

                    // Java fully-qualified class name.
                    if let Some(java_meta) = idx.cpg.java_metadata.get(node_id) {
                        if let Some(fqc) = &java_meta.fully_qualified_class {
                            keys.push((format!("{}.{}", fqc, fn_name), true, entry.clone()));
                        }
                    }

                    // Go: package-qualified name (e.g. "encoding/json.Marshal").
                    if let Some(go_meta) = idx.cpg.go_metadata.get(node_id) {
                        if let Some(pkg) = &go_meta.package_name {
                            keys.push((format!("{}.{}", pkg, fn_name), false, entry.clone()));
                        }
                        if let Some(qname) = &go_meta.qualified_name {
                            keys.push((qname.clone(), true, entry.clone()));
                        }
                    }
                }
                on_file();
                keys
            })
            .collect();

        let mut fn_to_params: HashMap<String, (PathBuf, Vec<NodeId>)> = HashMap::new();
        for (key, overwrite, value) in per_file_keys.into_iter().flatten() {
            if overwrite {
                fn_to_params.insert(key, value);
            } else {
                fn_to_params.entry(key).or_insert(value);
            }
        }

        // Resolve cross_file_calls from each file against the multi-key function index.
        // Keyed by `NodeRef` (caller file + call_node id) — never a bare `NodeId` —
        // since the same integer id routinely appears in many different files.
        let mut callee_params: HashMap<NodeRef, Vec<(PathBuf, Vec<NodeId>)>> = HashMap::new();
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
                        .entry(NodeRef::new(idx.path.clone(), edge.call_node))
                        .or_default()
                        .push((callee_file.clone(), callee_param_nodes.clone()));
                }
            }
        }

        // Build the flat DFG map for cross-file taint traversal.
        // Reuse the already-built DfgIndex/Cpg from each FileIndex — both are Arc-wrapped,
        // so this is a refcount bump rather than a deep clone of the whole CPG.
        let mut cross_dfgs: HashMap<PathBuf, (Arc<DfgIndex>, Arc<Cpg>)> = HashMap::new();
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
        self.scan_with_progress(rule_set, || {})
    }

    /// Like [`scan`] but calls `on_file()` after each file is processed, allowing
    /// the caller to drive a progress bar.
    pub fn scan_with_progress<F>(&self, rule_set: &RuleSet, on_file: F) -> Vec<Finding>
    where
        F: Fn() + Sync,
    {
        let _span = prof::span("query.scan_total");
        let predicate_plans = &rule_set.predicate_plans;
        let predicate_params = &rule_set.predicate_params;
        let cross_file_ctx = CrossFileTaintCtx {
            file_dfgs: &self.cross_file_dfgs,
            call_to_callee_params: &self.cross_file_callee_params,
        };
        let cross_file_ref = &cross_file_ctx;

        self.files
            .par_iter()
            .flat_map(|(path, file_idx)| {
                let _task = prof::task();
                let _span = prof::span("query.scan_file");

                let ctx = EvalContext {
                    cpg: &file_idx.cpg,
                    current_file: path.as_path(),
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
                on_file();

                file_findings
            })
            .collect()
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
                    current_file: path.as_path(),
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

    /// Extract a compact CPG subgraph for visualization of the given finding.
    ///
    /// Looks up the file by matching `finding.location.file` against
    /// `cpg.source_file` (which is the canonicalized absolute path set during
    /// parsing). Returns `None` if the file is not indexed or the finding has
    /// no matched nodes.
    pub fn extract_cpg_subgraph(&self, finding: &Finding) -> Option<CpgSubgraph> {
        if finding.matched_nodes.is_empty() {
            return None;
        }
        let file_idx = self.files.values().find(|fi| {
            fi.cpg.source_file.as_deref() == Some(finding.location.file.as_str())
        })?;
        Some(build_cpg_subgraph(&file_idx.cpg, &finding.matched_nodes))
    }
}

// ── CPG subgraph extraction ───────────────────────────────────────────────────

const SUBGRAPH_MAX_NODES: usize = 200;

fn find_fn_root(cpg: &Cpg, mut nid: NodeId) -> NodeId {
    for _ in 0..64 {
        if let Some(node) = cpg.ast.get(&nid) {
            if matches!(node.kind, IrNodeKind::MethodDef | IrNodeKind::LambdaDef) {
                return nid;
            }
            match node.parent_id {
                Some(p) => nid = p,
                None => return nid,
            }
        } else {
            return nid;
        }
    }
    nid
}

fn build_cpg_subgraph(cpg: &Cpg, matched_nodes: &[NodeId]) -> CpgSubgraph {
    let mut included: HashSet<NodeId> = HashSet::new();

    // BFS from each function root
    for &seed in matched_nodes {
        let root = find_fn_root(cpg, seed);
        let mut queue: VecDeque<NodeId> = VecDeque::new();
        queue.push_back(root);
        while let Some(nid) = queue.pop_front() {
            if included.len() >= SUBGRAPH_MAX_NODES {
                break;
            }
            if !included.insert(nid) {
                continue;
            }
            if let Some(node) = cpg.ast.get(&nid) {
                for &child in &node.children {
                    queue.push_back(child);
                }
            }
        }
        if included.len() >= SUBGRAPH_MAX_NODES {
            break;
        }
    }

    // If still too many, prune to matched nodes + ancestors + direct children
    let pruned = included.len() >= SUBGRAPH_MAX_NODES;
    if pruned {
        included.clear();
        for &seed in matched_nodes {
            included.insert(seed);
            let mut cur = seed;
            for _ in 0..24 {
                if let Some(node) = cpg.ast.get(&cur) {
                    match node.parent_id {
                        Some(p) => { included.insert(p); cur = p; }
                        None => break,
                    }
                } else {
                    break;
                }
            }
            if let Some(node) = cpg.ast.get(&seed) {
                for &child in &node.children {
                    included.insert(child);
                }
            }
        }
    }

    // Build node list
    let nodes: Vec<CpgNodeData> = included.iter().filter_map(|&id| {
        let n = cpg.ast.get(&id)?;
        let text = n.text.as_ref()
            .map(|t| t.chars().take(60).collect::<String>())
            .or_else(|| n.name.clone());
        Some(CpgNodeData {
            id,
            node_type: n.node_type.clone(),
            text,
            line: n.line,
            col: n.column,
            end_line: n.end_line,
            parent_id: n.parent_id.filter(|p| included.contains(p)),
        })
    }).collect();

    // AST edges (parent → child)
    let mut edges: Vec<CpgEdgeData> = Vec::new();
    for &id in &included {
        if let Some(n) = cpg.ast.get(&id) {
            if let Some(parent) = n.parent_id {
                if included.contains(&parent) {
                    edges.push(CpgEdgeData { s: parent, d: id, k: "A".to_string(), v: None });
                }
            }
        }
    }

    // DFG edges within subgraph
    for edge in &cpg.dataflow.edges {
        if included.contains(&edge.source) && included.contains(&edge.destination) {
            edges.push(CpgEdgeData {
                s: edge.source,
                d: edge.destination,
                k: "D".to_string(),
                v: if edge.variable.is_empty() { None } else { Some(edge.variable.clone()) },
            });
        }
    }

    CpgSubgraph { nodes, edges, pruned }
}
