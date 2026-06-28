use anyhow::{Context, Result, bail};
use crate::{AstNode, Cpg, NodeId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;
use tree_sitter::{InputEdit, Parser, Point, Tree};

use crate::cfg::{build_cfg_for_functions_with_start, cfg_topology_sig, compute_cfg_sccs};
use crate::cpg_generator::{
    GraphBuildOptions, SourceLanguage, collect_source_comments, get_node_graph_artifacts,
};
use crate::dfg::{
    build_call_graph, build_call_graph_for_functions, build_dataflow_for_functions,
    build_preprocessing_maps, get_func_def_name,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeType {
    Insert,
    Delete,
    Replace,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TextEdit {
    pub start_byte: usize,
    pub old_end_byte: usize,
    pub new_end_byte: usize,
    pub start_point: (usize, usize),
    pub old_end_point: (usize, usize),
    pub new_end_point: (usize, usize),
    pub change_type: ChangeType,
}

#[derive(Clone, Debug, Default)]
pub struct IncrementalCpgState {
    pub source_code: Vec<u8>,
    pub cpg: Option<Cpg>,
    pub source_hash: Option<String>,
    pub language: String,
    pub node_to_id: BTreeMap<u64, u32>,
    pub id_to_node_ptr: BTreeMap<u32, u64>,
    pub structural_key_to_id: BTreeMap<(i64, usize, String, usize), u32>,
    pub id_to_structural_key: BTreeMap<u32, (i64, usize, String, usize)>,
    pub function_map: BTreeMap<u32, u32>,
    pub type_index: BTreeMap<String, Vec<u32>>,
    pub macro_aliases: BTreeMap<String, String>,
    pub raw_macros: BTreeMap<String, String>,
    pub source_file: Option<String>,
    pub next_id: u32,
    pub deleted_ids: BTreeSet<u32>,
    /// Incremented on each targeted incremental update; node IDs record the
    /// generation at which they were created/reused so stale DFG edges can be
    /// dropped when IDs are recycled.
    pub generation: u32,
    pub node_generation: BTreeMap<u32, u32>,
    pub next_bb_id: u32,
    pub deleted_bb_ids: BTreeSet<String>,
    call_expressions: Vec<CachedCallExpression>,
    return_statements: Vec<CachedReturnStatement>,
    pub cache_stats: BTreeMap<String, u64>,
    pub stats: BTreeMap<String, u64>,
    pub last_affected_region: Option<AffectedRegion>,
    /// Cached root node ID (the translation_unit / source_file node).
    /// Avoids an O(N) scan on every incremental edit.
    pub root_node_id: Option<u32>,
    /// CFG topology signature per function: FNV-1a hash of SCC structure.
    /// When a function's signature changes, its loop structure changed and all
    /// transitive callers must be fully re-analysed (not just delta-propagated).
    pub cfg_topology_sigs: BTreeMap<u32, u64>,
    /// Function IDs present after the last successful CPG build (set-diff deletion).
    pub known_function_ids: BTreeSet<u32>,
    /// Fingerprint of preprocessor-relevant source regions; skips gcc when unchanged.
    pub macro_region_hash: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AffectedRegion {
    pub start_byte: usize,
    pub old_end_byte: usize,
    pub new_end_byte: usize,
    pub affected_node_ids: BTreeSet<u32>,
    pub affected_function_ids: BTreeSet<u32>,
    pub affected_basic_block_ids: BTreeSet<String>,
    pub rebuilt_function_ids: BTreeSet<u32>,
    pub requires_full_dfg_rebuild: bool,
    pub affected_function_names: BTreeSet<String>,
    pub has_global_changes: bool,
    /// Names of C++ classes whose body changed (C++ only).
    /// All methods in these classes are considered affected.
    pub affected_class_names: BTreeSet<String>,
    /// Names of C++ templates whose declaration changed (C++ only).
    /// All template instantiations referencing these names must be re-analyzed.
    pub affected_template_names: BTreeSet<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
struct CachedVarRef {
    name: String,
    node_id: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
struct CachedCallArgument {
    node_id: u32,
    variables_used: Vec<CachedVarRef>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
struct CachedCallExpression {
    node_id: u32,
    called_func: Option<String>,
    containing_func: Option<u32>,
    arguments: Vec<CachedCallArgument>,
    assigned_to: Option<CachedVarRef>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
struct CachedReturnValue {
    node_id: u32,
    variables_used: Vec<CachedVarRef>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
struct CachedReturnStatement {
    node_id: u32,
    return_value: Option<CachedReturnValue>,
    function: Option<u32>,
    function_name: Option<String>,
}

#[derive(Clone, Debug)]
struct TopLevelEntry {
    node_id: u32,
    node_type: String,
    start_byte: usize,
    end_byte: usize,
}

/// Only the fields that cannot be derived from the CPG are persisted.
/// Everything else — indexes, caches, ephemeral stats — is rebuilt on load.
/// Bump this whenever `IrNode`, `Cpg`, or `PersistedState` change their
/// serialized binary layout.  A mismatch causes `load_state` to treat the
/// cache file as a miss and rebuild from scratch.
const CACHE_FORMAT_VERSION: u32 = 3;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PersistedState {
    /// Must equal `CACHE_FORMAT_VERSION`; mismatched files are discarded.
    format_version: u32,
    source_code: Vec<u8>,
    cpg: Option<Cpg>,
    language: String,
    raw_macros: BTreeMap<String, String>,
    next_id: u32,
    deleted_ids: BTreeSet<u32>,
    generation: u32,
    /// Per-node generation stamps guard the persisted DFG: without them,
    /// `prune_stale_dfg_by_generation` would over/under-prune on the first
    /// post-load incremental edit.
    node_generation: BTreeMap<u32, u32>,
}

pub struct IncrementalCpgGenerator {
    parser: Parser,
    tree: Option<Tree>,
    options: GraphBuildOptions,
    pub state: IncrementalCpgState,
    source_language: SourceLanguage,
}

/// Structural index built during lightweight (AST-only) parse.
/// Tells the caller WHAT exists in the file — not used for rule matching.
/// Rule matching only runs on CPG nodes generated by `generate_function_cpg`.
#[derive(Clone, Debug, Default)]
pub struct LightweightIndex {
    /// Names of all function definitions found in the file.
    pub function_names: Vec<String>,
    /// Call graph edges: caller name → list of callee names.
    pub call_edges: BTreeMap<String, Vec<String>>,
    /// Top-level `static`/`const` variable declarations: name → AST node.
    pub global_constants: BTreeMap<String, AstNode>,
    /// Maps function name → its root CPG node ID (for use in `generate_function_cpg`).
    pub function_node_ids: BTreeMap<String, NodeId>,
}

impl IncrementalCpgGenerator {
    pub fn new(options: GraphBuildOptions) -> Result<Self> {
        Self::new_for_language(SourceLanguage::C, options)
    }

    pub fn new_for_language(language: SourceLanguage, options: GraphBuildOptions) -> Result<Self> {
        let mut parser = Parser::new();
        parser
            .set_language(&language.ts_language())
            .context("failed to initialize parser for incremental CPG")?;
        Ok(Self {
            parser,
            tree: None,
            options,
            state: IncrementalCpgState {
                language: language.as_str().to_string(),
                stats: default_incremental_stats(),
                ..IncrementalCpgState::default()
            },
            source_language: language,
        })
    }

    /// Bootstrap this generator's state from an already-parsed workspace generator,
    /// skipping the tree-sitter re-parse. The tree is NOT copied (it is not Clone);
    /// a lazy re-parse runs on the first `apply_edit` call if the user edits the file.
    /// Returns `true` if bootstrap succeeded (other generator had parsed source + CPG).
    pub fn bootstrap_from_state(&mut self, other: &IncrementalCpgState) -> bool {
        if other.source_code.is_empty() || other.cpg.is_none() {
            return false;
        }
        self.state = other.clone();
        self.tree = None;
        true
    }

    /// Merge CFG+DFG data from a cached per-function CPG into this generator's whole-file
    /// CPG. Only `basic_blocks` and `dataflow` are merged; the AST and call graph are
    /// already correct from the lightweight parse / bootstrap step.
    ///
    /// The cached CPG may have function-relative line numbers in its AST nodes, but
    /// `basic_blocks` and `dataflow` reference file-wide node IDs and need no adjustment.
    pub fn inject_function_cpg_data(&mut self, fn_cpg: &Cpg) -> Result<()> {
        let cpg = self.state.cpg.as_mut().ok_or_else(|| {
            anyhow::anyhow!("no CPG — call bootstrap_from_state or parse_lightweight first")
        })?;
        for (key, bb) in &fn_cpg.basic_blocks {
            cpg.basic_blocks
                .entry(key.clone())
                .or_insert_with(|| bb.clone());
        }
        cpg.dataflow
            .definitions
            .extend(fn_cpg.dataflow.definitions.clone());
        cpg.dataflow.uses.extend(fn_cpg.dataflow.uses.clone());
        cpg.dataflow.edges.extend(fn_cpg.dataflow.edges.clone());
        Ok(())
    }

    /// Initialise from a pre-built CPG and source bytes, **without** calling
    /// tree-sitter. The tree-sitter `Tree` is set to `None` and will be
    /// lazily re-parsed on the first `apply_edit` / `parse_incremental` call.
    ///
    /// Use this at workspace startup when the CPG was loaded from disk cache,
    /// so the expensive tree-sitter parse is skipped until the file is actually
    /// edited.
    ///
    /// Returns the `LightweightIndex` derived from the provided CPG (same
    /// contract as `parse_lightweight_with_file_path`).
    pub fn init_from_cache(
        &mut self,
        cpg: Cpg,
        source_bytes: Vec<u8>,
        file_path: Option<impl AsRef<std::path::Path>>,
    ) -> LightweightIndex {
        self.tree = None;
        self.state.source_code = source_bytes;
        self.state.source_hash = Some(content_hash(&self.state.source_code));
        self.state.source_file = cpg.source_file.clone();
        self.state.last_affected_region = None;

        // Rebuild macro aliases from raw_macros if any were stored.
        self.state.macro_aliases = self
            .state
            .raw_macros
            .iter()
            .filter_map(|(k, v)| {
                k.strip_prefix("__macro_alias_")
                    .map(|name| (name.to_lowercase(), v.clone()))
            })
            .collect();

        // Refresh include macros from the file path (no-op if None).
        self.refresh_macro_aliases(file_path.as_ref().map(|p| p.as_ref()));

        // Rebuild all derived indexes from the CPG — same tail as load_state.
        // state.cpg is None here so refresh_incremental_indexes starts fresh.
        refresh_incremental_indexes(&mut self.state, &cpg);
        let macro_aliases = if self.state.macro_aliases.is_empty() {
            None
        } else {
            Some(self.state.macro_aliases.clone())
        };
        refresh_incremental_analysis_caches(
            &mut self.state,
            &cpg,
            macro_aliases.as_ref(),
            None,
            None,
        );
        seed_node_generations(&mut self.state, &cpg);
        self.state.next_id = cpg.ast.keys().max().copied().unwrap_or(0).saturating_add(1);

        let index = build_lightweight_index(&cpg);
        self.state.cpg = Some(cpg);
        index
    }

    /// Phase 1: parse the source with tree-sitter and store the tree, build the
    /// AST (no CFG/DFG), and extract a lightweight structural index.
    ///
    /// The stored tree is reused by `generate_function_cpg` and `apply_edit`
    /// — tree-sitter is NOT called again for those operations.
    ///
    /// The returned `LightweightIndex` tells callers what functions/constants
    /// exist and how they relate, but is NOT used for rule matching itself.
    pub fn parse_lightweight(&mut self, source: &[u8]) -> Result<LightweightIndex> {
        self.parse_lightweight_with_file_path(source, Option::<&std::path::Path>::None)
    }

    pub fn parse_lightweight_with_file_path(
        &mut self,
        source: &[u8],
        file_path: Option<impl AsRef<std::path::Path>>,
    ) -> Result<LightweightIndex> {
        self.reset_incremental_state();
        self.refresh_macro_aliases(file_path.as_ref().map(|p| p.as_ref()));

        // Parse once — tree is stored and reused by generate_function_cpg / apply_edit.
        let tree = self
            .parser
            .parse(source, None)
            .ok_or_else(|| anyhow::anyhow!("parse failed in parse_lightweight"))?;
        self.state.source_code = source.to_vec();
        self.state.source_hash = Some(content_hash(source));
        self.state.last_affected_region = None;
        self.tree = Some(tree);

        // Build AST only — skip CFG and DFG.
        let mut lightweight_opts = self.options.clone();
        lightweight_opts.include_cfg = false;
        lightweight_opts.include_dfg = false;

        let tree_ref = self.tree.as_ref().expect("just stored above");
        let artifacts = get_node_graph_artifacts(tree_ref.root_node(), source, &lightweight_opts, self.source_language)?;
        let mut cpg = artifacts.cpg;
        cpg.source_file = self.state.source_file.clone();

        // Build call graph from the AST (cheap — no CFG/DFG needed).
        let maps = build_preprocessing_maps(&cpg.ast);
        cpg.call_graph =
            build_call_graph(&cpg.ast, Some(&maps), self.options.macro_aliases.as_ref());

        // Build the lightweight structural index.
        let index = build_lightweight_index(&cpg);

        // Store node tracking state for later generate_function_cpg / apply_edit.
        self.state.node_to_id = artifacts.node_to_id;
        self.state.id_to_node_ptr = artifacts.id_to_node_ptr;
        self.state.next_id = cpg.ast.keys().max().copied().unwrap_or(0).saturating_add(1);
        refresh_incremental_indexes(&mut self.state, &cpg);
        seed_node_generations(&mut self.state, &cpg);
        self.state.cpg = Some(cpg);

        Ok(index)
    }

    /// Phase 2: extend the already-stored AST-only CPG with CFG + DFG for the
    /// specified functions. Reuses the tree stored by `parse_lightweight` — no
    /// additional tree-sitter parse is performed.
    ///
    /// Can be called multiple times to lazily build CPG for more functions.
    /// Returns a reference to the (now partially complete) CPG.
    pub fn generate_function_cpg(&mut self, function_ids: &BTreeSet<NodeId>) -> Result<&Cpg> {
        // Allow generating CFG/DFG when the generator was bootstrapped from a workspace
        // state (tree=None but CPG exists). The tree is only needed by the tree-sitter
        // parse path; all CFG/DFG builders operate purely on the CPG's AST.
        if self.tree.is_none() && self.state.cpg.is_none() {
            bail!("generate_function_cpg called before parse_lightweight");
        }
        if function_ids.is_empty() {
            return self
                .state
                .cpg
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("no CPG available"));
        }

        let cpg =
            self.state.cpg.as_mut().ok_or_else(|| {
                anyhow::anyhow!("no CPG available — call parse_lightweight first")
            })?;

        // Build CFG for the requested functions.
        build_cfg_for_functions_with_start(
            &mut cpg.ast,
            &mut cpg.basic_blocks,
            function_ids,
            self.state.next_bb_id as usize,
        );

        // Build DFG (dataflow edges) for the requested functions only.
        let maps = build_preprocessing_maps(&cpg.ast);
        let (fresh_dataflow, new_xfile) = build_dataflow_for_functions(
            &cpg.ast,
            Some(&cpg.basic_blocks),
            Some(&cpg.dataflow),
            function_ids,
            false, // include_globals
            Some(&maps),
            self.options.macro_aliases.as_ref(),
        );
        cpg.dataflow = fresh_dataflow;
        // Merge newly discovered cross-file calls, deduplicating by call_node.
        {
            let existing: rustc_hash::FxHashSet<u32> =
                cpg.cross_file_calls.iter().map(|e| e.call_node).collect();
            for edge in new_xfile {
                if !existing.contains(&edge.call_node) {
                    cpg.cross_file_calls.push(edge);
                }
            }
        }

        // Update call graph for the newly processed functions.
        cpg.call_graph = build_call_graph_for_functions(
            &cpg.ast,
            Some(&cpg.call_graph),
            function_ids,
            Some(&maps),
            self.options.macro_aliases.as_ref(),
        );

        self.state
            .cpg
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("CPG missing after generate_function_cpg"))
    }

    pub fn parse_initial(&mut self, source: &[u8]) -> Result<&Cpg> {
        self.parse_initial_with_file_path(source, Option::<&std::path::Path>::None)
    }

    pub fn parse_initial_with_file_path(
        &mut self,
        source: &[u8],
        file_path: Option<impl AsRef<std::path::Path>>,
    ) -> Result<&Cpg> {
        let started = Instant::now();
        self.reset_incremental_state();
        self.refresh_macro_aliases(file_path.as_ref().map(|p| p.as_ref()));
        let tree = self
            .parser
            .parse(source, None)
            .ok_or_else(|| anyhow::anyhow!("parse failed"))?;
        self.state.source_code = source.to_vec();
        self.state.source_hash = Some(content_hash(source));
        self.state.last_affected_region = None;
        self.tree = Some(tree);
        self.rebuild_cpg()?;
        *self
            .state
            .stats
            .entry("full_builds".to_string())
            .or_insert(0) += 1;
        *self
            .state
            .stats
            .entry("nodes_rebuilt".to_string())
            .or_insert(0) += self
            .state
            .cpg
            .as_ref()
            .map(|cpg| cpg.ast.len() as u64)
            .unwrap_or(0);
        *self
            .state
            .stats
            .entry("total_time_ms".to_string())
            .or_insert(0) += started.elapsed().as_millis() as u64;
        self.state
            .cpg
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing CPG after initial parse"))
    }

    pub fn apply_edit(&mut self, edit: &TextEdit, new_source: &[u8]) -> Result<&Cpg> {
        self.apply_edit_with_file_path(edit, new_source, Option::<&std::path::Path>::None)
    }

    pub fn apply_edit_with_file_path(
        &mut self,
        edit: &TextEdit,
        new_source: &[u8],
        file_path: Option<impl AsRef<std::path::Path>>,
    ) -> Result<&Cpg> {
        let started = Instant::now();
        self.refresh_macro_aliases(file_path.as_ref().map(|p| p.as_ref()));
        self.state.last_affected_region = self
            .state
            .cpg
            .as_ref()
            .map(|cpg| compute_affected_region(cpg, edit));
        // If the generator was bootstrapped from workspace state (no tree stored), do a
        // one-time full parse now so we have a tree to base incremental edits on.
        if self.tree.is_none() && !self.state.source_code.is_empty() {
            let source = self.state.source_code.clone();
            let tree = self.parser.parse(&source, None).ok_or_else(|| {
                anyhow::anyhow!("lazy re-parse failed for bootstrapped generator")
            })?;
            self.tree = Some(tree);
        }
        let Some(old_tree) = self.tree.as_mut() else {
            bail!("cannot apply incremental edit before parse_initial");
        };

        old_tree.edit(&InputEdit {
            start_byte: edit.start_byte,
            old_end_byte: edit.old_end_byte,
            new_end_byte: edit.new_end_byte,
            start_position: point(edit.start_point),
            old_end_position: point(edit.old_end_point),
            new_end_position: point(edit.new_end_point),
        });

        let new_tree = self
            .parser
            .parse(new_source, Some(old_tree))
            .ok_or_else(|| anyhow::anyhow!("incremental parse failed"))?;
        self.tree = Some(new_tree);
        self.state.source_code = new_source.to_vec();
        self.state.source_hash = Some(content_hash(new_source));
        if !self.try_targeted_update(edit)? {
            self.rebuild_cpg()?;
        }
        self.compact_deleted_ids(1000);
        *self
            .state
            .stats
            .entry("incremental_updates".to_string())
            .or_insert(0) += 1;
        *self
            .state
            .stats
            .entry("total_time_ms".to_string())
            .or_insert(0) += started.elapsed().as_millis() as u64;
        self.state
            .cpg
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing CPG after incremental parse"))
    }

    pub fn parse_incremental(&mut self, new_source: &[u8], edits: &[TextEdit]) -> Result<&Cpg> {
        self.parse_incremental_with_file_path(new_source, edits, Option::<&std::path::Path>::None)
    }

    pub fn parse_incremental_with_file_path(
        &mut self,
        new_source: &[u8],
        edits: &[TextEdit],
        file_path: Option<impl AsRef<std::path::Path>>,
    ) -> Result<&Cpg> {
        let started = Instant::now();
        self.refresh_macro_aliases(file_path.as_ref().map(|p| p.as_ref()));
        self.state.last_affected_region = self
            .state
            .cpg
            .as_ref()
            .and_then(|cpg| edits.first().map(|edit| compute_affected_region(cpg, edit)));
        if self.tree.is_none() && !self.state.source_code.is_empty() {
            let source = self.state.source_code.clone();
            let tree = self.parser.parse(&source, None).ok_or_else(|| {
                anyhow::anyhow!("lazy re-parse failed for bootstrapped generator")
            })?;
            self.tree = Some(tree);
        }
        let Some(old_tree) = self.tree.as_mut() else {
            bail!("cannot apply incremental parse before parse_initial");
        };

        if edits.is_empty() {
            return self.parse_full(new_source);
        }

        for edit in edits {
            old_tree.edit(&InputEdit {
                start_byte: edit.start_byte,
                old_end_byte: edit.old_end_byte,
                new_end_byte: edit.new_end_byte,
                start_position: point(edit.start_point),
                old_end_position: point(edit.old_end_point),
                new_end_position: point(edit.new_end_point),
            });
        }

        let new_tree = self
            .parser
            .parse(new_source, Some(old_tree))
            .ok_or_else(|| anyhow::anyhow!("incremental parse failed"))?;
        self.tree = Some(new_tree);
        self.state.source_code = new_source.to_vec();
        self.state.source_hash = Some(content_hash(new_source));
        if edits.len() == 1 {
            if !self.try_targeted_update(&edits[0])? {
                self.rebuild_cpg()?;
            }
        } else {
            self.rebuild_cpg()?;
        }
        self.compact_deleted_ids(1000);
        *self
            .state
            .stats
            .entry("incremental_updates".to_string())
            .or_insert(0) += 1;
        *self
            .state
            .stats
            .entry("total_time_ms".to_string())
            .or_insert(0) += started.elapsed().as_millis() as u64;
        self.state
            .cpg
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing CPG after incremental parse"))
    }

    pub fn parse_full(&mut self, source: &[u8]) -> Result<&Cpg> {
        self.parse_full_with_file_path(source, Option::<&std::path::Path>::None)
    }

    pub fn parse_full_with_file_path(
        &mut self,
        source: &[u8],
        file_path: Option<impl AsRef<std::path::Path>>,
    ) -> Result<&Cpg> {
        let started = Instant::now();
        self.reset_incremental_state();
        self.refresh_macro_aliases(file_path.as_ref().map(|p| p.as_ref()));
        let tree = self
            .parser
            .parse(source, None)
            .ok_or_else(|| anyhow::anyhow!("full parse failed"))?;
        self.tree = Some(tree);
        self.state.source_code = source.to_vec();
        self.state.source_hash = Some(content_hash(source));
        self.state.last_affected_region = None;
        self.rebuild_cpg()?;
        *self
            .state
            .stats
            .entry("full_builds".to_string())
            .or_insert(0) += 1;
        *self
            .state
            .stats
            .entry("nodes_rebuilt".to_string())
            .or_insert(0) += self
            .state
            .cpg
            .as_ref()
            .map(|cpg| cpg.ast.len() as u64)
            .unwrap_or(0);
        *self
            .state
            .stats
            .entry("total_time_ms".to_string())
            .or_insert(0) += started.elapsed().as_millis() as u64;
        self.state
            .cpg
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing CPG after full parse"))
    }

    fn rebuild_cpg(&mut self) -> Result<()> {
        let tree = self
            .tree
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing parse tree for CPG rebuild"))?;
        let previous_node_count = self
            .state
            .cpg
            .as_ref()
            .map(|cpg| cpg.ast.len() as u64)
            .unwrap_or(0);
        self.options.macro_aliases = if self.state.macro_aliases.is_empty() {
            None
        } else {
            Some(self.state.macro_aliases.clone())
        };
        let artifacts =
            get_node_graph_artifacts(tree.root_node(), &self.state.source_code, &self.options, self.source_language)?;
        let mut cpg = artifacts.cpg;
        if let Some(old_cpg) = &self.state.cpg {
            let reuse =
                stabilize_cpg_ids(old_cpg, &cpg, self.state.next_id, &self.state.deleted_ids);
            apply_cpg_remap(&mut cpg, &reuse.remap);
            self.state.deleted_ids.extend(reuse.deleted_ids);
            self.state.next_id = reuse.next_id;
            *self
                .state
                .cache_stats
                .entry("structural_key_hits".to_string())
                .or_insert(0) += reuse.reused as u64;
            *self
                .state
                .cache_stats
                .entry("structural_key_misses".to_string())
                .or_insert(0) += reuse.created as u64;
            *self
                .state
                .stats
                .entry("nodes_reused".to_string())
                .or_insert(0) += reuse.reused as u64;
        } else {
            self.state.next_id = cpg.ast.keys().max().copied().unwrap_or(0).saturating_add(1);
        }
        let new_node_count = cpg.ast.len() as u64;
        if new_node_count > previous_node_count {
            *self
                .state
                .stats
                .entry("nodes_rebuilt".to_string())
                .or_insert(0) += new_node_count - previous_node_count;
        }
        cpg.source_file = self.state.source_file.clone();
        self.state.node_to_id = artifacts.node_to_id;
        self.state.id_to_node_ptr = artifacts.id_to_node_ptr;
        refresh_incremental_indexes(&mut self.state, &cpg);
        refresh_incremental_analysis_caches(
            &mut self.state,
            &cpg,
            self.options.macro_aliases.as_ref(),
            None,
            None, // full rebuild — maps will be built inside
        );
        seed_node_generations(&mut self.state, &cpg);
        self.state.cpg = Some(cpg);
        Ok(())
    }

    fn try_targeted_update(&mut self, edit: &TextEdit) -> Result<bool> {
        self.state.generation = self.state.generation.saturating_add(1);
        let current_generation = self.state.generation;
        // Take ownership rather than cloning the full CPG; early returns restore it.
        let Some(mut old_cpg) = self.state.cpg.take() else {
            return Ok(false);
        };
        let Some(tree) = self.tree.as_ref() else {
            self.state.cpg = Some(old_cpg);
            return Ok(false);
        };
        let Some(root_id) = self.state.root_node_id else {
            self.state.cpg = Some(old_cpg);
            return Ok(false);
        };
        let Some(old_root) = old_cpg.ast.get(&root_id) else {
            self.state.cpg = Some(old_cpg);
            return Ok(false);
        };

        let new_root = tree.root_node();
        let old_root_children = old_root.children.clone();
        let mut old_top_level = Vec::new();
        let mut affected_function_ids = BTreeSet::new();
        let mut has_global_changes = false;
        let mut requires_full_dfg_rebuild = false;
        let mut unaffected_after_ids = Vec::new();
        for child_id in old_root_children {
            let Some(child) = old_cpg.ast.get(&child_id) else {
                continue;
            };
            let entry = TopLevelEntry {
                node_id: child_id,
                node_type: child.node_type.clone(),
                start_byte: child.start_byte.unwrap_or(0) as usize,
                end_byte: child.end_byte.unwrap_or(0) as usize,
            };
            if entry.end_byte <= edit.start_byte {
            } else if entry.start_byte >= edit.old_end_byte {
                unaffected_after_ids.push(entry.node_id);
            } else if is_function_like(&entry.node_type) {
                affected_function_ids.insert(entry.node_id);
            } else if matches!(
                entry.node_type.as_str(),
                "class_specifier" | "struct_specifier"
            ) {
                // C++: try to find the specific method(s) that changed inside
                // the class body rather than forcing a full DFG rebuild for
                // every class method edit.
                let (method_ids, struct_changed) = collect_method_ids_in_range(
                    &old_cpg.ast,
                    entry.node_id,
                    edit.start_byte,
                    edit.old_end_byte,
                );
                if !method_ids.is_empty() && !struct_changed {
                    affected_function_ids.extend(method_ids);
                } else {
                    has_global_changes = true;
                    requires_full_dfg_rebuild = true;
                }
            } else {
                has_global_changes = true;
                // Only force a full DFG rebuild when the changed node can
                // introduce or remove global dataflow edges: a global variable
                // declaration, a macro definition/alias, or a type definition.
                // Comments, includes, and attribute annotations do not affect
                // the DFG and can skip the full rebuild.
                if is_global_dfg_affecting(&entry.node_type) {
                    requires_full_dfg_rebuild = true;
                }
            }
            old_top_level.push(entry);
        }
        let total_functions = old_top_level
            .iter()
            .filter(|entry| is_function_like(&entry.node_type))
            .count();
        let threshold = if total_functions > 4 {
            std::cmp::max(2, total_functions / 2)
        } else {
            total_functions.saturating_add(1)
        };
        if affected_function_ids.len() > threshold {
            self.state.cpg = Some(old_cpg);
            return Ok(false);
        }

        // Extract heavy fields now that all early returns are past — moved rather than cloned.
        let old_basic_blocks = std::mem::take(&mut old_cpg.basic_blocks);
        let old_dataflow = std::mem::take(&mut old_cpg.dataflow);
        let old_call_graph = std::mem::take(&mut old_cpg.call_graph);

        let mut kept_ast = old_cpg.ast.clone();
        let mut kept_deleted_ids = self.state.deleted_ids.clone();
        let mut new_children = Vec::new();
        let mut new_field_names = Vec::new();
        let mut removed_ids = BTreeSet::new();
        let mut next_id = self.state.next_id;
        let mut surviving_old = BTreeSet::new();
        let byte_delta = edit.new_end_byte as isize - edit.old_end_byte as isize;
        let mut node_to_id = BTreeMap::new();
        let mut id_to_node_ptr = BTreeMap::new();
        node_to_id.insert(new_root.id() as u64, root_id);
        id_to_node_ptr.insert(root_id, new_root.id() as u64);
        // Tracks old top-level entries that have been consumed as a matching_old
        // source. Without this, two new children (e.g. an edited function and a
        // newly inserted sibling) would both match the same old entry, causing the
        // second child's nodes to receive IDs that are immediately deleted by the
        // removed_ids cleanup pass.
        let mut consumed_overlapping: BTreeSet<u32> = BTreeSet::new();

        let mut preserved_by_key: BTreeMap<(String, usize), TopLevelEntry> = BTreeMap::new();
        for entry in &old_top_level {
            let overlaps_edit =
                !(entry.end_byte <= edit.start_byte || entry.start_byte >= edit.old_end_byte);
            if overlaps_edit {
                continue;
            }
            let adjusted_start = if entry.start_byte >= edit.old_end_byte {
                entry.start_byte.saturating_add_signed(byte_delta)
            } else {
                entry.start_byte
            };
            preserved_by_key.insert((entry.node_type.clone(), adjusted_start), entry.clone());
        }

        for i in 0..new_root.child_count() {
            let Some(ts_child) = new_root.child(i as u32) else {
                continue;
            };
            if !ts_child.is_named() || should_skip_named_node(ts_child.kind()) {
                continue;
            }

            let start = ts_child.start_byte();
            let field_name = new_root
                .field_name_for_child(i as u32)
                .map(|s| s.to_string());
            let preserved_old = preserved_by_key.remove(&(ts_child.kind().to_string(), start));

            if let Some(entry) = preserved_old {
                surviving_old.insert(entry.node_id);
                new_children.push(entry.node_id);
                new_field_names.push(field_name);
                node_to_id.insert(ts_child.id() as u64, entry.node_id);
                id_to_node_ptr.insert(entry.node_id, ts_child.id() as u64);
                if entry.start_byte >= edit.old_end_byte && byte_delta != 0 {
                    shift_subtree_positions(
                        &mut kept_ast,
                        entry.node_id,
                        byte_delta,
                        &self.state.source_code,
                    );
                }
            } else {
                let mut subtree_options = self.options.clone();
                subtree_options.macro_aliases = if self.state.macro_aliases.is_empty() {
                    None
                } else {
                    Some(self.state.macro_aliases.clone())
                };
                let mut subtree_artifacts =
                    get_node_graph_artifacts(ts_child, &self.state.source_code, &subtree_options, self.source_language)?;
                let mut subtree_cpg = subtree_artifacts.cpg;

                let matching_old = old_top_level
                    .iter()
                    .find(|entry| {
                        !consumed_overlapping.contains(&entry.node_id)
                            && entry.node_type == ts_child.kind()
                            && !(entry.end_byte <= edit.start_byte
                                || entry.start_byte >= edit.old_end_byte)
                    })
                    .map(|entry| entry.node_id);

                if let Some(old_subtree_root) = matching_old {
                    consumed_overlapping.insert(old_subtree_root);
                    collect_subtree_ids(&old_cpg.ast, old_subtree_root, &mut removed_ids);
                    let old_subtree = extract_subtree_cpg(&old_cpg, old_subtree_root);
                    let reuse =
                        stabilize_cpg_ids(&old_subtree, &subtree_cpg, next_id, &kept_deleted_ids);
                    apply_cpg_remap(&mut subtree_cpg, &reuse.remap);
                    remap_pointer_maps(
                        &mut subtree_artifacts.node_to_id,
                        &mut subtree_artifacts.id_to_node_ptr,
                        &reuse.remap,
                    );
                    kept_deleted_ids.extend(reuse.deleted_ids.iter().copied());
                    next_id = reuse.next_id;
                    *self
                        .state
                        .cache_stats
                        .entry("structural_key_hits".to_string())
                        .or_insert(0) += reuse.reused as u64;
                    *self
                        .state
                        .cache_stats
                        .entry("structural_key_misses".to_string())
                        .or_insert(0) += reuse.created as u64;
                    *self
                        .state
                        .stats
                        .entry("nodes_reused".to_string())
                        .or_insert(0) += reuse.reused as u64;
                } else {
                    let reuse = stabilize_cpg_ids(
                        &Cpg::default(),
                        &subtree_cpg,
                        next_id,
                        &kept_deleted_ids,
                    );
                    apply_cpg_remap(&mut subtree_cpg, &reuse.remap);
                    remap_pointer_maps(
                        &mut subtree_artifacts.node_to_id,
                        &mut subtree_artifacts.id_to_node_ptr,
                        &reuse.remap,
                    );
                    next_id = reuse.next_id;
                    *self
                        .state
                        .cache_stats
                        .entry("structural_key_misses".to_string())
                        .or_insert(0) += reuse.created as u64;
                }

                let subtree_root_id = subtree_cpg
                    .ast
                    .iter()
                    .find_map(|(id, node)| (node.parent_id.is_none()).then_some(*id))
                    .ok_or_else(|| anyhow::anyhow!("subtree CPG missing root"))?;

                for (node_id, mut node) in subtree_cpg.ast {
                    if node_id == subtree_root_id {
                        node.parent_id = Some(root_id);
                    }
                    kept_ast.insert(node_id, node);
                }
                node_to_id.extend(subtree_artifacts.node_to_id);
                id_to_node_ptr.extend(subtree_artifacts.id_to_node_ptr);
                new_children.push(subtree_root_id);
                new_field_names.push(field_name);
                if is_function_like(ts_child.kind()) {
                    affected_function_ids.insert(subtree_root_id);
                } else {
                    has_global_changes = true;
                }
            }
        }

        for entry in &old_top_level {
            if !surviving_old.contains(&entry.node_id) {
                collect_subtree_ids(&old_cpg.ast, entry.node_id, &mut removed_ids);
            }
        }

        for removed_id in &removed_ids {
            kept_ast.remove(removed_id);
            kept_deleted_ids.insert(*removed_id);
        }
        for node in kept_ast.values_mut() {
            node.children
                .retain(|child_id| !removed_ids.contains(child_id));
        }
        if let Some(root_node) = kept_ast.get_mut(&root_id) {
            root_node.children = new_children;
            root_node.field_names = new_field_names;
            root_node.text = Some(
                String::from_utf8_lossy(&self.state.source_code).replace(['\n', '\r', '\t'], ""),
            );
            root_node.start_byte = Some(new_root.start_byte() as u32);
            root_node.end_byte = Some(new_root.end_byte() as u32);
            root_node.line = (new_root.start_position().row + 1) as u32;
            root_node.column = new_root.start_position().column as u32;
            root_node.end_line = (new_root.end_position().row + 1) as u32;
            root_node.end_column = new_root.end_position().column as u32;
        }
        let mut detached_roots = BTreeSet::new();
        for removed_id in &removed_ids {
            if let Some(parent_id) = old_cpg.ast.get(removed_id).and_then(|n| n.parent_id) {
                if kept_ast.contains_key(&parent_id) {
                    detached_roots.insert(parent_id);
                }
            }
        }
        prune_unreachable_ast_nodes(
            &mut kept_ast,
            root_id,
            &mut kept_deleted_ids,
            &detached_roots,
        );

        // Re-collect comments from the updated parse tree.
        let updated_comments = self
            .tree
            .as_ref()
            .map(|t| collect_source_comments(t.root_node(), &self.state.source_code))
            .unwrap_or_default();

        let cpg_macro_aliases: BTreeMap<String, String> = self
            .state
            .raw_macros
            .iter()
            .filter_map(|(k, v)| {
                if let Some(name) = k.strip_prefix("__macro_alias_") {
                    return Some((name.to_string(), v.clone()));
                }
                if !k.starts_with("__")
                    && crate::cpg_generator::is_valid_identifier_pub(v)
                    && k != v
                {
                    return Some((k.clone(), v.clone()));
                }
                None
            })
            .collect();
        let cpg_macro_bodies: BTreeMap<String, crate::MacroBody> = self
            .state
            .raw_macros
            .iter()
            .filter_map(|(k, v)| {
                let name = k.strip_prefix("__macro_def_")?;
                let (params_str, body) = v.split_once('|')?;
                let params = if params_str.trim().is_empty() {
                    vec![]
                } else {
                    params_str
                        .split(',')
                        .map(|p| p.trim().to_string())
                        .collect()
                };
                Some((
                    name.to_string(),
                    crate::MacroBody {
                        params,
                        body: body.to_string(),
                    },
                ))
            })
            .collect();
        let mut cpg = Cpg {
            ast: kept_ast,
            basic_blocks: old_basic_blocks
                .into_iter()
                .filter(|(_, bb)| !affected_function_ids.contains(&bb.function))
                .collect(),
            call_graph: BTreeMap::new(),
            dataflow: crate::DataflowGraph::default(), // filled by build_dataflow_for_functions below
            source_file: self.state.source_file.clone(),
            language: old_cpg.language.clone(),
            comments: updated_comments,
            macro_aliases: cpg_macro_aliases,
            macro_bodies: cpg_macro_bodies,
            custom_allocators: old_cpg.custom_allocators.clone(),
            cross_file_calls: Vec::new(),
            cpp_metadata: old_cpg.cpp_metadata.clone(),
            go_metadata: old_cpg.go_metadata.clone(),
            python_metadata: old_cpg.python_metadata.clone(),
            java_metadata: old_cpg.java_metadata.clone(),
            js_metadata: old_cpg.js_metadata.clone(),
            ts_metadata: old_cpg.ts_metadata.clone(),
            rust_metadata: old_cpg.rust_metadata.clone(),
            class_hierarchy: old_cpg.class_hierarchy.clone(),
            function_summaries: old_cpg.function_summaries.clone(),
        };
        clear_basic_block_annotations(&mut cpg.ast, Some(&affected_function_ids));
        if !affected_function_ids.is_empty() {
            build_cfg_for_functions_with_start(
                &mut cpg.ast,
                &mut cpg.basic_blocks,
                &affected_function_ids,
                self.state.next_bb_id as usize,
            );
        }
        let maps = build_preprocessing_maps(&cpg.ast);

        // Compute topology signatures for affected functions and detect which
        // have changed SCC structure (loop-structure changes require full
        // transitive-caller re-analysis; edge-only changes use delta tier).
        let topology_changed_fns = update_and_diff_topology_sigs(
            &cpg.basic_blocks,
            &cpg.ast,
            &affected_function_ids,
            &mut self.state.cfg_topology_sigs,
        );

        let mut incremental_targets = expand_incremental_function_targets(
            &old_cpg.ast,
            &cpg.ast,
            &maps,
            &old_dataflow,
            &old_call_graph,
            &affected_function_ids,
            &topology_changed_fns,
            has_global_changes,
            self.options.macro_aliases.as_ref(),
        );
        // When a function is rebuilt its node ID changes.  `expand_incremental_function_targets`
        // starts from old IDs, so rebuilt functions only have their OLD id in the set.
        // Add the NEW function IDs for rebuilt subtrees so that the analysis-cache scan
        // (which keys on new-CPG node IDs) covers them.
        for (node_id, node) in &cpg.ast {
            if node.is_method_def() && !surviving_old.contains(node_id) {
                incremental_targets.insert(*node_id);
            }
        }
        cpg.call_graph = if incremental_targets.is_empty() {
            old_call_graph
        } else {
            build_call_graph_for_functions(
                &cpg.ast,
                Some(&old_call_graph),
                &incremental_targets,
                Some(&maps),
                self.options.macro_aliases.as_ref(),
            )
        };
        let (new_dataflow, new_xfile) = build_dataflow_for_functions(
            &cpg.ast,
            Some(&cpg.basic_blocks),
            Some(&old_dataflow),
            &incremental_targets,
            requires_full_dfg_rebuild,
            Some(&maps),
            self.options.macro_aliases.as_ref(),
        );
        cpg.dataflow = new_dataflow;
        // Replace cross-file calls for affected functions; keep others.
        // Filter new_xfile to only include edges from actual incremental targets
        // (add_interprocedural_edges may emit edges for non-target functions too).
        cpg.cross_file_calls
            .retain(|e| !incremental_targets.contains(&e.caller_fn));
        cpg.cross_file_calls.extend(
            new_xfile
                .into_iter()
                .filter(|e| incremental_targets.contains(&e.caller_fn)),
        );

        self.state.next_id =
            next_id.max(cpg.ast.keys().max().copied().unwrap_or(0).saturating_add(1));
        self.state.deleted_ids = kept_deleted_ids;
        self.state.node_to_id = node_to_id;
        self.state.id_to_node_ptr = id_to_node_ptr;
        refresh_incremental_indexes(&mut self.state, &cpg);
        refresh_incremental_analysis_caches(
            &mut self.state,
            &cpg,
            self.options.macro_aliases.as_ref(),
            Some(&incremental_targets),
            Some(&maps),
        );
        for removed_id in &removed_ids {
            self.state.node_generation.remove(removed_id);
        }
        let node_in_rebuilt_scope = |node_id: &u32| {
            incremental_targets.contains(node_id)
                || cpg
                    .ast
                    .get(node_id)
                    .and_then(|n| n.function_id)
                    .is_some_and(|fid| incremental_targets.contains(&fid))
        };
        for node_id in cpg.ast.keys() {
            if node_in_rebuilt_scope(node_id)
                || removed_ids.contains(node_id)
                || !old_cpg.ast.contains_key(node_id)
            {
                self.state
                    .node_generation
                    .insert(*node_id, current_generation);
            }
        }
        let new_function_ids: BTreeSet<u32> = cpg.call_graph.keys().copied().collect();
        for deleted_fn in self.state.known_function_ids.difference(&new_function_ids) {
            self.state.cfg_topology_sigs.remove(deleted_fn);
        }
        self.state.known_function_ids = new_function_ids;
        prune_stale_dfg_by_generation(
            &mut cpg.dataflow,
            &self.state.node_generation,
            &cpg.ast,
            &incremental_targets,
        );
        apply_cached_interprocedural_edges(
            &mut cpg.dataflow,
            &cpg.ast,
            &self.state.call_expressions,
            &self.state.return_statements,
            &incremental_targets,
            has_global_changes,
            &maps,
        );
        self.state.last_affected_region = Some(AffectedRegion {
            start_byte: edit.start_byte,
            old_end_byte: edit.old_end_byte,
            new_end_byte: edit.new_end_byte,
            affected_node_ids: removed_ids.clone(),
            affected_function_ids: incremental_targets.clone(),
            affected_basic_block_ids: cpg
                .basic_blocks
                .iter()
                .filter_map(|(bb_id, bb)| {
                    incremental_targets
                        .contains(&bb.function)
                        .then_some(bb_id.clone())
                })
                .collect(),
            rebuilt_function_ids: incremental_targets,
            requires_full_dfg_rebuild,
            affected_function_names: removed_ids
                .iter()
                .filter_map(|node_id| {
                    old_cpg.ast.get(node_id).and_then(|node| {
                        node.is_method_def()
                            .then(|| function_name_for_id(&old_cpg, *node_id))
                            .flatten()
                    })
                })
                .collect(),
            has_global_changes,
            // Preserve class/template names from the preliminary region computed
            // by compute_affected_region (from the old CPG) — used by C++ cross-file
            // invalidation when consumers are wired up.
            affected_class_names: self
                .state
                .last_affected_region
                .as_ref()
                .map(|r| r.affected_class_names.clone())
                .unwrap_or_default(),
            affected_template_names: self
                .state
                .last_affected_region
                .as_ref()
                .map(|r| r.affected_template_names.clone())
                .unwrap_or_default(),
        });
        self.state.cpg = Some(cpg);
        Ok(true)
    }

    fn reset_incremental_state(&mut self) {
        self.state = IncrementalCpgState {
            language: self.state.language.clone(),
            stats: default_incremental_stats(),
            ..IncrementalCpgState::default()
        };
        self.tree = None;
    }

    fn refresh_macro_aliases(&mut self, file_path: Option<&std::path::Path>) {
        self.state.macro_aliases.clear();
        self.state.raw_macros.clear();
        self.state.source_file = file_path.map(|p| {
            p.canonicalize()
                .unwrap_or_else(|_| p.to_path_buf())
                .display()
                .to_string()
        });
        let Some(file_path) = file_path else {
            return;
        };
        let region_hash = macro_region_hash_for_file(file_path, &self.state.source_code);
        let extracted =
            if region_hash == self.state.macro_region_hash && !self.state.raw_macros.is_empty() {
                self.state.raw_macros.clone()
            } else {
                let extracted = crate::cpg_generator::extract_macros(file_path);
                self.state.macro_region_hash = region_hash;
                extracted
            };
        self.state.raw_macros = extracted.clone();
        self.state.macro_aliases = extracted
            .into_iter()
            .filter_map(|(k, v)| {
                if let Some(name) = k.strip_prefix("__macro_alias_") {
                    Some((name.to_lowercase(), v))
                } else {
                    None
                }
            })
            .collect();
    }

    fn compact_deleted_ids(&mut self, threshold: usize) {
        if self.state.deleted_ids.len() < threshold {
            return;
        }
        let max_current_id = self
            .state
            .cpg
            .as_ref()
            .and_then(|cpg| cpg.ast.keys().max().copied())
            .unwrap_or(0);
        self.state.deleted_ids.retain(|id| *id < max_current_id);
        if self.state.next_id <= max_current_id {
            self.state.next_id = max_current_id.saturating_add(1);
        }
    }

    pub fn save_state(&self, path: impl AsRef<std::path::Path>) -> Result<()> {
        let persisted = PersistedState {
            format_version: CACHE_FORMAT_VERSION,
            source_code: self.state.source_code.clone(),
            cpg: self.state.cpg.clone(),
            language: self.state.language.clone(),
            raw_macros: self.state.raw_macros.clone(),
            next_id: self.state.next_id,
            deleted_ids: self.state.deleted_ids.clone(),
            generation: self.state.generation,
            node_generation: self.state.node_generation.clone(),
        };
        let encoded = bincode::serde::encode_to_vec(&persisted, bincode::config::standard())
            .context("failed to encode incremental CPG state")?;
        let payload = lz4_flex::compress_prepend_size(&encoded);
        std::fs::write(path.as_ref(), payload).with_context(|| {
            format!(
                "failed to write incremental state to {}",
                path.as_ref().display()
            )
        })?;
        Ok(())
    }

    pub fn load_state(&mut self, path: impl AsRef<std::path::Path>) -> Result<bool> {
        let bytes = {
            match std::fs::read(path.as_ref()) {
                Ok(bytes) => bytes,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(false);
                }
                Err(err) => return Err(err.into()),
            }
        };
        let (persisted, _): (PersistedState, usize) = {
            // Try LZ4 decompression first; fall back to raw bytes for old cache files.
            let decode_buf: Vec<u8>;
            let decode_src = match lz4_flex::decompress_size_prepended(&bytes) {
                Ok(decompressed) => {
                    decode_buf = decompressed;
                    decode_buf.as_slice()
                }
                Err(_) => bytes.as_slice(),
            };
            match bincode::serde::decode_from_slice(decode_src, bincode::config::standard()) {
                Ok(v) => v,
                Err(_) => {
                    return Ok(false);
                }
            }
        };

        if persisted.format_version != CACHE_FORMAT_VERSION {
            return Ok(false);
        }

        if persisted.source_code.is_empty() {
            self.state = IncrementalCpgState {
                language: "c".to_string(),
                stats: default_incremental_stats(),
                ..IncrementalCpgState::default()
            };
            return Ok(true);
        }

        {
            // Restore the irreducible persisted fields.
            self.state.source_code = persisted.source_code;
            self.state.language = if persisted.language.is_empty() {
                "c".to_string()
            } else {
                persisted.language
            };
            self.state.raw_macros = persisted.raw_macros;
            self.state.next_id = persisted.next_id;
            self.state.deleted_ids = persisted.deleted_ids;
            self.state.generation = persisted.generation;
            self.state.node_generation = persisted.node_generation;

            if persisted.cpg.is_none() {
                // No CPG on disk — rebuild from source (requires a parse first).
                // The lazy-reparse path in apply_incremental_edit handles tree init.
                self.rebuild_cpg()?;
            } else {
                self.state.cpg = persisted.cpg;
                // Rebuild all derived state from the loaded CPG.
                // state.cpg is None here so refresh_incremental_indexes sees no
                // prior BBs, leaving deleted_bb_ids empty (correct for a fresh load).
                let cpg = self.state.cpg.take().unwrap();
                self.state.source_file = cpg.source_file.clone();
                self.state.macro_aliases = self
                    .state
                    .raw_macros
                    .iter()
                    .filter_map(|(k, v)| {
                        k.strip_prefix("__macro_alias_")
                            .map(|name| (name.to_lowercase(), v.clone()))
                    })
                    .collect();
                self.state.source_hash = Some(content_hash(&self.state.source_code));
                refresh_incremental_indexes(&mut self.state, &cpg);
                let macro_aliases = if self.state.macro_aliases.is_empty() {
                    None
                } else {
                    Some(self.state.macro_aliases.clone())
                };
                refresh_incremental_analysis_caches(
                    &mut self.state,
                    &cpg,
                    macro_aliases.as_ref(),
                    None,
                    None,
                );
                seed_node_generations(&mut self.state, &cpg);
                self.state.cpg = Some(cpg);
            }
        }
        Ok(true)
    }

    pub fn get_cache_stats(&self) -> BTreeMap<String, sonic_rs::Value> {
        let mut out = BTreeMap::new();
        let hits = *self
            .state
            .cache_stats
            .get("structural_key_hits")
            .unwrap_or(&0);
        let misses = *self
            .state
            .cache_stats
            .get("structural_key_misses")
            .unwrap_or(&0);
        let deleted_id_skips = *self.state.cache_stats.get("deleted_id_skips").unwrap_or(&0);
        let total = hits + misses;

        out.insert("structural_key_hits".to_string(), sonic_rs::json!(hits));
        out.insert("structural_key_misses".to_string(), sonic_rs::json!(misses));
        out.insert(
            "deleted_id_skips".to_string(),
            sonic_rs::json!(deleted_id_skips),
        );
        out.insert(
            "mapping_builds".to_string(),
            sonic_rs::json!(*self.state.cache_stats.get("mapping_builds").unwrap_or(&0)),
        );
        out.insert("next_id".to_string(), sonic_rs::json!(self.state.next_id));
        out.insert(
            "deleted_ids_count".to_string(),
            sonic_rs::json!(self.state.deleted_ids.len()),
        );
        out.insert(
            "node_reuse_rate".to_string(),
            sonic_rs::json!(if total > 0 {
                hits as f64 / total as f64
            } else {
                0.0
            }),
        );
        out
    }

    pub fn get_incremental_stats(&self) -> BTreeMap<String, sonic_rs::Value> {
        let mut out = BTreeMap::new();
        for (k, v) in &self.state.stats {
            out.insert(k.clone(), sonic_rs::json!(v));
        }
        out.insert(
            "source_hash".to_string(),
            sonic_rs::json!(self.state.source_hash.clone()),
        );
        out.insert(
            "macro_aliases".to_string(),
            sonic_rs::json!(self.state.macro_aliases.clone()),
        );
        out.insert(
            "raw_macros".to_string(),
            sonic_rs::json!(self.state.raw_macros.clone()),
        );
        out.insert(
            "source_file".to_string(),
            sonic_rs::json!(self.state.source_file.clone()),
        );
        out.insert(
            "type_index_size".to_string(),
            sonic_rs::json!(self.state.type_index.len()),
        );
        out.insert(
            "function_map_size".to_string(),
            sonic_rs::json!(self.state.function_map.len()),
        );
        out.insert(
            "structural_key_count".to_string(),
            sonic_rs::json!(self.state.structural_key_to_id.len()),
        );
        out.insert(
            "next_bb_id".to_string(),
            sonic_rs::json!(self.state.next_bb_id),
        );
        out.insert(
            "last_affected_region".to_string(),
            sonic_rs::json!(self.state.last_affected_region.clone()),
        );
        out.insert(
            "cached_call_expressions".to_string(),
            sonic_rs::json!(self.state.call_expressions.len()),
        );
        out.insert(
            "cached_return_statements".to_string(),
            sonic_rs::json!(self.state.return_statements.len()),
        );
        out
    }
}

fn point((row, column): (usize, usize)) -> Point {
    Point { row, column }
}

fn content_hash(source: &[u8]) -> String {
    let digest = Sha256::digest(source);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn default_incremental_stats() -> BTreeMap<String, u64> {
    BTreeMap::from([
        ("full_builds".to_string(), 0),
        ("incremental_updates".to_string(), 0),
        ("total_time_ms".to_string(), 0),
        ("nodes_rebuilt".to_string(), 0),
        ("nodes_reused".to_string(), 0),
    ])
}

fn refresh_incremental_indexes(state: &mut IncrementalCpgState, cpg: &Cpg) {
    let previous_bb_ids = if let Some(existing) = &state.cpg {
        existing
            .basic_blocks
            .keys()
            .cloned()
            .collect::<BTreeSet<String>>()
    } else {
        BTreeSet::new()
    };
    state.type_index.clear();
    state.function_map.clear();
    state.structural_key_to_id.clear();
    state.id_to_structural_key.clear();
    *state
        .cache_stats
        .entry("mapping_builds".to_string())
        .or_insert(0) += 1;

    let mut children_by_parent: BTreeMap<i64, Vec<u32>> = BTreeMap::new();
    state.root_node_id = None;
    for (node_id, node) in &cpg.ast {
        if node.parent_id.is_none() {
            state.root_node_id = Some(*node_id);
        }
        let parent_key = node.parent_id.map(|id| id as i64).unwrap_or(-1);
        children_by_parent
            .entry(parent_key)
            .or_default()
            .push(*node_id);
        state
            .type_index
            .entry(node.node_type.clone())
            .or_default()
            .push(*node_id);
    }
    for child_ids in children_by_parent.values_mut() {
        child_ids.sort_by_key(|node_id| {
            cpg.ast
                .get(node_id)
                .and_then(|node| node.start_byte)
                .unwrap_or(0)
        });
    }

    let function_ids: BTreeSet<u32> = cpg
        .ast
        .iter()
        .filter_map(|(node_id, node)| node.is_method_def().then_some(*node_id))
        .collect();
    for (node_id, node) in &cpg.ast {
        if let Some(function_id) = node
            .function_id
            .filter(|function_id| function_ids.contains(function_id))
        {
            state.function_map.insert(*node_id, function_id);
        } else if function_ids.contains(node_id) {
            state.function_map.insert(*node_id, *node_id);
        }

        let parent_key = node.parent_id.map(|id| id as i64).unwrap_or(-1);
        let child_index = children_by_parent
            .get(&parent_key)
            .and_then(|siblings| siblings.iter().position(|candidate| candidate == node_id))
            .unwrap_or(0);
        let start_byte = node.start_byte.unwrap_or(0) as usize;
        let key = (parent_key, child_index, node.node_type.clone(), start_byte);
        state.structural_key_to_id.insert(key.clone(), *node_id);
        state.id_to_structural_key.insert(*node_id, key);
    }

    state.next_bb_id = cpg
        .basic_blocks
        .keys()
        .filter_map(|bb_id| bb_id.strip_prefix("bb_"))
        .filter_map(|suffix| suffix.parse::<u32>().ok())
        .max()
        .map(|max_id| max_id.saturating_add(1))
        .unwrap_or(0);
    let current_bb_ids = cpg
        .basic_blocks
        .keys()
        .cloned()
        .collect::<BTreeSet<String>>();
    state
        .deleted_bb_ids
        .extend(previous_bb_ids.difference(&current_bb_ids).cloned());
}

/// Rebuild the analysis caches (call_expressions, return_statements, taint_sources,
/// sensitive_sinks) for the given CPG.
///
/// When `affected_function_ids` is `Some`, only entries belonging to the listed
/// functions are invalidated and rebuilt — O(affected) instead of O(all_nodes).
/// Pass `None` for a full rebuild (cold start / full reparse).
fn refresh_incremental_analysis_caches(
    state: &mut IncrementalCpgState,
    cpg: &Cpg,
    macro_aliases: Option<&BTreeMap<String, String>>,
    affected_function_ids: Option<&BTreeSet<u32>>,
    preprocessing_maps: Option<&crate::dfg::PreprocessingMaps>,
) {
    let owned_maps: crate::dfg::PreprocessingMaps;
    let maps = match preprocessing_maps {
        Some(m) => m,
        None => {
            owned_maps = crate::dfg::build_preprocessing_maps(&cpg.ast);
            &owned_maps
        }
    };
    let function_map = &maps.1;

    match affected_function_ids {
        None => {
            // Full rebuild: clear everything and rescan all nodes.
            state.call_expressions.clear();
            state.return_statements.clear();
        }
        Some(affected) => {
            // Incremental: only remove entries for affected functions, keep
            // entries for unchanged functions.  This is O(cached) instead of
            // O(all_nodes) when only a few functions changed.
            state
                .call_expressions
                .retain(|e| !e.containing_func.map_or(false, |f| affected.contains(&f)));
            state
                .return_statements
                .retain(|e| !e.function.map_or(false, |f| affected.contains(&f)));
        }
    }

    // Use type_index to avoid scanning all AST nodes for function_definition.
    let function_name_to_id: BTreeMap<_, _> = state
        .type_index
        .get("function_definition")
        .into_iter()
        .flat_map(|ids| ids.iter())
        .filter_map(|node_id| {
            crate::dfg::get_func_def_name(&cpg.ast, *node_id).map(|name| (name, *node_id))
        })
        .collect();

    // Scan only the relevant subset of nodes.
    let nodes_to_scan: Box<dyn Iterator<Item = (&u32, &crate::AstNode)>> =
        match affected_function_ids {
            None => Box::new(cpg.ast.iter()),
            Some(affected) => Box::new(
                cpg.ast
                    .iter()
                    .filter(|(id, _)| function_map.get(id).map_or(false, |f| affected.contains(f))),
            ),
        };

    for (node_id, node) in nodes_to_scan {
        if node.is_call() {
            let called_func =
                crate::dfg::extract_called_function_name(&cpg.ast, *node_id, macro_aliases);
            let arguments = extract_cached_call_arguments(&cpg.ast, *node_id)
                .into_iter()
                .map(|(arg_id, variables_used)| CachedCallArgument {
                    node_id: arg_id,
                    variables_used,
                })
                .collect::<Vec<_>>();
            let assigned_to = extract_assignment_target(&cpg.ast, *node_id);
            state.call_expressions.push(CachedCallExpression {
                node_id: *node_id,
                called_func,
                containing_func: function_map.get(node_id).copied(),
                arguments,
                assigned_to,
            });
        } else if node.is_return() {
            let return_value = extract_cached_return_value(&cpg.ast, *node_id);
            let function = function_map.get(node_id).copied();
            state.return_statements.push(CachedReturnStatement {
                node_id: *node_id,
                return_value,
                function,
                function_name: function.and_then(|fid| {
                    function_name_to_id
                        .iter()
                        .find_map(|(name, id)| (*id == fid).then_some(name.clone()))
                }),
            });
        }
    }
}

fn extract_cached_call_arguments(
    ast: &BTreeMap<u32, crate::AstNode>,
    call_id: u32,
) -> Vec<(u32, Vec<CachedVarRef>)> {
    crate::dfg::extract_call_argument_nodes(ast, call_id)
        .into_iter()
        .map(|arg_id| (arg_id, collect_cached_identifiers(ast, arg_id)))
        .collect()
}

fn extract_cached_return_value(
    ast: &BTreeMap<u32, crate::AstNode>,
    return_id: u32,
) -> Option<CachedReturnValue> {
    let node = ast.get(&return_id)?;
    let value_id = node.children.iter().copied().find(|child_id| {
        ast.get(child_id)
            .map(|child| !matches!(child.node_type.as_str(), "return" | ";"))
            .unwrap_or(false)
    })?;
    Some(CachedReturnValue {
        node_id: value_id,
        variables_used: collect_cached_identifiers(ast, value_id)
            .into_iter()
            .filter(|var| !is_call_callee_identifier(ast, var.node_id))
            .collect(),
    })
}

fn extract_assignment_target(
    ast: &BTreeMap<u32, crate::AstNode>,
    call_id: u32,
) -> Option<CachedVarRef> {
    let call = ast.get(&call_id)?;
    let parent_id = call.parent_id?;
    let parent = ast.get(&parent_id)?;
    if !matches!(
        parent.node_type.as_str(),
        "init_declarator" | "assignment_expression"
    ) {
        return None;
    }
    let lhs_id = *parent.children.first()?;
    collect_cached_identifiers(ast, lhs_id).into_iter().next()
}

fn collect_cached_identifiers(
    ast: &BTreeMap<u32, crate::AstNode>,
    root_id: u32,
) -> Vec<CachedVarRef> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut stack = vec![root_id];
    while let Some(node_id) = stack.pop() {
        if !seen.insert(node_id) {
            continue;
        }
        let Some(node) = ast.get(&node_id) else {
            continue;
        };
        if node.is_identifier() {
            if let Some(name) = node.text.clone() {
                out.push(CachedVarRef { name, node_id });
            }
        }
        stack.extend(node.children.iter().copied());
    }
    out
}

fn is_call_callee_identifier(ast: &BTreeMap<u32, crate::AstNode>, node_id: u32) -> bool {
    let Some(node) = ast.get(&node_id) else {
        return false;
    };
    if !node.is_identifier() {
        return false;
    }
    let Some(parent_id) = node.parent_id else {
        return false;
    };
    let Some(parent) = ast.get(&parent_id) else {
        return false;
    };
    if !parent.is_call() {
        return false;
    }
    parent.children.first().copied() == Some(node_id)
}

fn apply_cached_interprocedural_edges(
    dataflow: &mut crate::DataflowGraph,
    ast: &BTreeMap<u32, crate::AstNode>,
    call_expressions: &[CachedCallExpression],
    return_statements: &[CachedReturnStatement],
    incremental_targets: &BTreeSet<u32>,
    include_globals: bool,
    preprocessing_maps: &crate::dfg::PreprocessingMaps,
) {
    let function_map = &preprocessing_maps.1;
    dataflow.edges.retain(|edge| {
        if edge.edge_type != "INTERPROCEDURAL_FLOW" && edge.edge_type != "RETURN_FLOW" {
            return true;
        }
        !edge_touches_incremental_scope(edge, function_map, incremental_targets, include_globals)
    });

    // Use type_index from preprocessing_maps to build function_name_to_id
    // without scanning all AST nodes.
    let function_name_to_id: BTreeMap<_, _> = preprocessing_maps
        .2
        .get("function_definition")
        .into_iter()
        .flat_map(|ids| ids.iter())
        .filter_map(|node_id| {
            crate::dfg::get_func_def_name(ast, *node_id).map(|name| (name, *node_id))
        })
        .collect();
    let params_by_function = function_name_to_id
        .values()
        .copied()
        .map(|func_id| (func_id, extract_cached_function_params(ast, func_id)))
        .collect::<BTreeMap<_, _>>();
    let returns_by_function = return_statements
        .iter()
        .filter_map(|ret| ret.function.map(|fid| (fid, ret.clone())))
        .fold(
            BTreeMap::<u32, Vec<CachedReturnStatement>>::new(),
            |mut acc, (fid, ret)| {
                acc.entry(fid).or_default().push(ret);
                acc
            },
        );

    for ret in return_statements {
        if !cache_item_in_scope(ret.function, incremental_targets, include_globals) {
            continue;
        }
        if let Some(value) = &ret.return_value {
            for used in &value.variables_used {
                push_cached_edge(
                    &mut dataflow.edges,
                    used.node_id,
                    ret.node_id,
                    used.name.clone(),
                    "RETURN_FLOW",
                );
            }
        }
    }

    for call in call_expressions {
        let callee_id = call
            .called_func
            .as_ref()
            .and_then(|name| function_name_to_id.get(name).copied());
        let touches_scope =
            cache_item_in_scope(call.containing_func, incremental_targets, include_globals)
                || callee_id.is_some_and(|fid| incremental_targets.contains(&fid));
        if !touches_scope {
            continue;
        }
        let Some(callee_id) = callee_id else {
            continue;
        };
        let params = params_by_function
            .get(&callee_id)
            .cloned()
            .unwrap_or_default();
        for (idx, arg) in call.arguments.iter().enumerate() {
            let Some(param) = params.get(idx).cloned().or_else(|| {
                (idx >= params.len() && !params.is_empty())
                    .then_some(params[params.len() - 1].clone())
            }) else {
                continue;
            };
            push_cached_edge(
                &mut dataflow.edges,
                arg.node_id,
                param.node_id,
                param.name.clone(),
                "INTERPROCEDURAL_FLOW",
            );
            for used in &arg.variables_used {
                push_cached_edge(
                    &mut dataflow.edges,
                    used.node_id,
                    param.node_id,
                    param.name.clone(),
                    "INTERPROCEDURAL_FLOW",
                );
            }
        }
        if let Some(lhs) = &call.assigned_to {
            for ret in returns_by_function.get(&callee_id).into_iter().flatten() {
                if let Some(value) = &ret.return_value {
                    push_cached_edge(
                        &mut dataflow.edges,
                        value.node_id,
                        lhs.node_id,
                        lhs.name.clone(),
                        "INTERPROCEDURAL_FLOW",
                    );
                    for used in &value.variables_used {
                        push_cached_edge(
                            &mut dataflow.edges,
                            used.node_id,
                            lhs.node_id,
                            lhs.name.clone(),
                            "INTERPROCEDURAL_FLOW",
                        );
                    }
                }
            }
        }
    }

    // Dedup once at the end rather than per-push (avoids O(n²) linear scan).
    {
        use std::collections::HashSet;
        let mut seen: HashSet<(u32, u32, String, String)> = HashSet::default();
        dataflow.edges.retain(|e| {
            seen.insert((
                e.source,
                e.destination,
                e.variable.clone(),
                e.edge_type.clone(),
            ))
        });
    }
}

fn extract_cached_function_params(
    ast: &BTreeMap<u32, crate::AstNode>,
    func_id: u32,
) -> Vec<CachedVarRef> {
    let mut out = Vec::new();
    collect_cached_function_params_in_order(ast, func_id, &mut out);
    out
}

fn collect_cached_function_params_in_order(
    ast: &BTreeMap<u32, crate::AstNode>,
    node_id: u32,
    out: &mut Vec<CachedVarRef>,
) {
    let mut stack = vec![node_id];
    while let Some(current_id) = stack.pop() {
        let Some(node) = ast.get(&current_id) else {
            continue;
        };
        if node.is_block() {
            continue;
        }
        if node.is_param_def() {
            if let Some(param) = collect_cached_identifiers(ast, current_id)
                .into_iter()
                .next()
            {
                out.push(param);
            }
            continue;
        }
        for child_id in node.children.iter().rev() {
            stack.push(*child_id);
        }
    }
}

fn seed_node_generations(state: &mut IncrementalCpgState, cpg: &Cpg) {
    let generation = state.generation;
    for node_id in cpg.ast.keys() {
        state.node_generation.entry(*node_id).or_insert(generation);
    }
    state.known_function_ids = cpg.call_graph.keys().copied().collect();
}

fn prune_stale_dfg_by_generation(
    dataflow: &mut crate::DataflowGraph,
    node_generation: &BTreeMap<u32, u32>,
    ast: &BTreeMap<u32, crate::AstNode>,
    affected_fns: &std::collections::BTreeSet<u32>,
) {
    let same_gen = |a: u32, b: u32| {
        node_generation
            .get(&a)
            .is_some_and(|ga| node_generation.get(&b) == Some(ga))
    };
    // Prune an edge only when the SOURCE node belongs to a rebuilt function.
    // Edges from unchanged functions (callers) into rebuilt callees survive —
    // discarding them caused false negatives vs. fresh analysis (interprocedural
    // paths through unchanged callers were incorrectly invalidated).
    let src_in_affected_fn = |src: u32| -> bool {
        ast.get(&src)
            .and_then(|n| n.function_id)
            .map_or(false, |fid| affected_fns.contains(&fid))
    };
    dataflow.edges.retain(|edge| {
        if !src_in_affected_fn(edge.source) {
            // Source is in an unchanged function — keep regardless of generation.
            return true;
        }
        same_gen(edge.source, edge.destination)
    });
    dataflow
        .definitions
        .retain(|def| node_generation.contains_key(&def.node_id));
    dataflow
        .uses
        .retain(|use_item| node_generation.contains_key(&use_item.node_id));
}

fn push_cached_edge(
    edges: &mut Vec<crate::DataflowEdge>,
    source: u32,
    destination: u32,
    variable: String,
    edge_type: &str,
) {
    edges.push(crate::DataflowEdge {
        source,
        destination,
        variable,
        edge_type: edge_type.to_string(),
        field_path: vec![],
    });
}

fn cache_item_in_scope(
    function_id: Option<u32>,
    incremental_targets: &BTreeSet<u32>,
    include_globals: bool,
) -> bool {
    match function_id {
        Some(function_id) => incremental_targets.contains(&function_id),
        None => include_globals,
    }
}

fn edge_touches_incremental_scope(
    edge: &crate::DataflowEdge,
    function_map: &BTreeMap<u32, u32>,
    incremental_targets: &BTreeSet<u32>,
    include_globals: bool,
) -> bool {
    cache_item_in_scope(
        function_map.get(&edge.source).copied(),
        incremental_targets,
        include_globals,
    ) || cache_item_in_scope(
        function_map.get(&edge.destination).copied(),
        incremental_targets,
        include_globals,
    )
}

fn should_skip_named_node(node_type: &str) -> bool {
    matches!(
        node_type,
        "comment" | "string_content" | "character" | "escape_sequence" | "system_lib_string"
    )
}

fn is_function_like(node_type: &str) -> bool {
    matches!(
        node_type,
        // C/C++/Python
        "function_definition" | "lambda_expression"
        // Go
        | "function_declaration" | "method_declaration" | "func_literal"
        // Java
        | "method_declaration" | "constructor_declaration"
        // JS/TS
        | "function_expression" | "arrow_function" | "method_definition"
        // Rust
        | "function_item"
    )
}
// NOTE: is_function_like above is intentionally kept on raw ts node_type strings —
// it's only used during incremental subtree hash/boundary detection (tree-sitter level),
// before nodes have been lifted into IrNode. Do NOT migrate to IrNodeKind here.

/// Walk a `class_specifier` or `struct_specifier` node in the CPG AST and
/// collect any `function_definition` (method) nodes whose byte range overlaps
/// [edit_start, edit_end).  Also returns whether any non-method members
/// (field declarations, access specifiers whose content changed, etc.) overlap
/// the edit — callers use this to decide if a full DFG rebuild is needed.
///
/// Container-only node types (`field_declaration_list`, `access_specifier`)
/// are traversed transparently; they are not counted as structural changes.
fn collect_method_ids_in_range(
    ast: &std::collections::BTreeMap<u32, crate::AstNode>,
    class_node_id: u32,
    edit_start: usize,
    edit_end: usize,
) -> (BTreeSet<u32>, bool) {
    const CONTAINERS: &[&str] = &[
        "field_declaration_list",
        "declaration_list",
        "access_specifier",
        "class_specifier",
        "struct_specifier",
        "template_declaration",
        "namespace_definition",
    ];

    let mut method_ids = BTreeSet::new();
    let mut has_structural_change = false;
    let mut stack = vec![class_node_id];

    while let Some(id) = stack.pop() {
        let Some(node) = ast.get(&id) else { continue };

        // Always walk the root class node itself.
        if id == class_node_id {
            for &child_id in &node.children {
                stack.push(child_id);
            }
            continue;
        }

        let start = node.start_byte.unwrap_or(0) as usize;
        let end = node.end_byte.unwrap_or(u32::MAX) as usize;
        let overlaps = !(end <= edit_start || start >= edit_end);
        if !overlaps {
            continue;
        }

        if node.is_method_def() {
            method_ids.insert(id);
            // Don't descend — the whole method is the rebuild unit.
        } else if CONTAINERS.contains(&node.node_type.as_str()) {
            for &child_id in &node.children {
                stack.push(child_id);
            }
        } else {
            // A real structural member (field_declaration for member variables,
            // using_declaration, static_assert, etc.)
            has_structural_change = true;
        }
    }

    (method_ids, has_structural_change)
}

/// Returns true when a change to a top-level node of this kind requires a full
/// DFG rebuild because it can add or remove global dataflow edges.
/// Node kinds that do NOT affect the DFG (comments, includes, `extern` function
/// declarations without a body, etc.) return false so incremental updates stay
/// scoped to the affected functions.
fn is_global_dfg_affecting(node_type: &str) -> bool {
    matches!(
        node_type,
        // Global variable declarations
        "declaration"
        // Macro definitions that may alias function names or expand to expressions
        | "preproc_def"
        | "preproc_function_def"
        // Type definitions can change struct field offsets tracked in the DFG
        | "typedef_declaration"
        | "struct_specifier"
        | "union_specifier"
        | "enum_specifier"
        // C++ namespace / class at file scope
        | "namespace_definition"
        | "class_specifier"
        // Template definitions at file scope
        | "template_declaration"
    )
}

fn compute_affected_region(cpg: &Cpg, edit: &TextEdit) -> AffectedRegion {
    let mut affected = AffectedRegion {
        start_byte: edit.start_byte,
        old_end_byte: edit.old_end_byte,
        new_end_byte: edit.new_end_byte,
        ..AffectedRegion::default()
    };

    let root_id = cpg
        .ast
        .iter()
        .find_map(|(id, node)| (node.parent_id.is_none()).then_some(*id));
    let Some(root_id) = root_id else {
        return affected;
    };
    let Some(root) = cpg.ast.get(&root_id) else {
        return affected;
    };

    for child_id in &root.children {
        let Some(child) = cpg.ast.get(child_id) else {
            continue;
        };
        let start = child.start_byte.unwrap_or(0) as usize;
        let end = child.end_byte.unwrap_or(0) as usize;
        if end <= edit.start_byte || start >= edit.old_end_byte {
            continue;
        }
        collect_subtree_ids(&cpg.ast, *child_id, &mut affected.affected_node_ids);
        if is_function_like(&child.node_type) {
            affected.affected_function_ids.insert(*child_id);
            affected.rebuilt_function_ids.insert(*child_id);
            if let Some(name) = function_name_for_id(cpg, *child_id) {
                affected.affected_function_names.insert(name);
            }
        } else if matches!(
            child.node_type.as_str(),
            "class_specifier" | "struct_specifier"
        ) {
            // C++: try to pinpoint which method(s) changed rather than going global.
            let (method_ids, struct_changed) = collect_method_ids_in_range(
                &cpg.ast,
                *child_id,
                edit.start_byte,
                edit.old_end_byte,
            );
            if !method_ids.is_empty() && !struct_changed {
                for method_id in method_ids {
                    affected.affected_function_ids.insert(method_id);
                    affected.rebuilt_function_ids.insert(method_id);
                    if let Some(name) = function_name_for_id(cpg, method_id) {
                        affected.affected_function_names.insert(name);
                    }
                }
            } else {
                affected.has_global_changes = true;
                affected.requires_full_dfg_rebuild = true;
                // Collect class name for targeted method invalidation.
                if let Some(class_name) = child
                    .text
                    .as_deref()
                    .and_then(|t| {
                        t.split_whitespace().nth(1).map(|s| {
                            s.trim_end_matches('{')
                                .trim_end_matches(':')
                                .trim()
                                .to_string()
                        })
                    })
                    .filter(|s| !s.is_empty())
                {
                    affected.affected_class_names.insert(class_name);
                }
            }
        } else {
            affected.has_global_changes = true;
            affected.requires_full_dfg_rebuild = true;
            // C++ template change: collect template name for instantiation invalidation.
            if child.node_type == "template_declaration" {
                if let Some(text) = &child.text {
                    // Extract the name from the inner declaration (class or function).
                    let name = text
                        .lines()
                        .skip(1) // skip "template <...>" line
                        .find_map(|line| {
                            let trimmed = line.trim();
                            if trimmed.starts_with("class ")
                                || trimmed.starts_with("struct ")
                                || trimmed.starts_with("void ")
                                || trimmed.starts_with("auto ")
                            {
                                trimmed.split_whitespace().nth(1).map(|n| {
                                    n.trim_end_matches('(')
                                        .trim_end_matches('<')
                                        .trim_end_matches('{')
                                        .to_string()
                                })
                            } else {
                                None
                            }
                        });
                    if let Some(name) = name {
                        if !name.is_empty() {
                            affected.affected_template_names.insert(name);
                        }
                    }
                }
            }
        }
    }

    affected.affected_basic_block_ids = cpg
        .basic_blocks
        .iter()
        .filter_map(|(bb_id, bb)| {
            affected
                .affected_function_ids
                .contains(&bb.function)
                .then_some(bb_id.clone())
        })
        .collect();

    affected
}

fn collect_subtree_ids(
    ast: &BTreeMap<u32, crate::AstNode>,
    root_id: u32,
    out: &mut BTreeSet<u32>,
) {
    let mut stack = vec![root_id];
    while let Some(node_id) = stack.pop() {
        if !out.insert(node_id) {
            continue;
        }
        if let Some(node) = ast.get(&node_id) {
            stack.extend(node.children.iter().copied());
        }
    }
}

fn prune_unreachable_ast_nodes(
    ast: &mut BTreeMap<u32, crate::AstNode>,
    root_id: u32,
    deleted_ids: &mut BTreeSet<u32>,
    detached_roots: &BTreeSet<u32>,
) {
    let mut reachable = BTreeSet::new();
    collect_subtree_ids(ast, root_id, &mut reachable);

    let mut stale_ids = BTreeSet::new();
    for root in detached_roots {
        if reachable.contains(root) {
            continue;
        }
        let mut queue = std::collections::VecDeque::from([*root]);
        while let Some(node_id) = queue.pop_front() {
            if !stale_ids.insert(node_id) {
                continue;
            }
            if let Some(node) = ast.get(&node_id) {
                for child_id in &node.children {
                    queue.push_back(*child_id);
                }
            }
        }
    }

    #[cfg(test)]
    {
        let full_scan: BTreeSet<u32> = ast
            .keys()
            .copied()
            .filter(|node_id| !reachable.contains(node_id))
            .collect();
        debug_assert_eq!(
            stale_ids, full_scan,
            "detached-root prune missed stale nodes"
        );
    }

    if stale_ids.is_empty() {
        return;
    }

    for stale_id in &stale_ids {
        ast.remove(stale_id);
        deleted_ids.insert(*stale_id);
    }
    for node in ast.values_mut() {
        node.children
            .retain(|child_id| !stale_ids.contains(child_id));
        if node
            .parent_id
            .is_some_and(|parent_id| stale_ids.contains(&parent_id))
        {
            node.parent_id = None;
        }
    }
}

fn macro_region_hash_for_file(path: &std::path::Path, source: &[u8]) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    if let Ok(meta) = std::fs::metadata(path) {
        meta.len().hash(&mut hasher);
        meta.modified().ok().hash(&mut hasher);
    }
    for line in source.split(|b| *b == b'\n') {
        let trimmed = line.trim_ascii_start();
        if trimmed.starts_with(b"#include") || trimmed.starts_with(b"#define") {
            trimmed.hash(&mut hasher);
        }
    }
    hasher.finish()
}

fn function_name_for_id(cpg: &Cpg, func_id: u32) -> Option<String> {
    cpg.call_graph
        .get(&func_id)
        .map(|entry| entry.name.clone())
        .or_else(|| {
            cpg.ast
                .get(&func_id)
                .and_then(|node| node.text.as_ref())
                .and_then(|text| text.split('(').next())
                .map(|prefix| {
                    prefix
                        .split_whitespace()
                        .last()
                        .unwrap_or_default()
                        .trim_matches('*')
                        .to_string()
                })
                .filter(|name| !name.is_empty())
        })
}

#[derive(Default)]
struct ReusePlan {
    remap: BTreeMap<u32, u32>,
    deleted_ids: BTreeSet<u32>,
    next_id: u32,
    reused: usize,
    created: usize,
}

fn stabilize_cpg_ids(
    old_cpg: &Cpg,
    new_cpg: &Cpg,
    next_id: u32,
    prior_deleted: &BTreeSet<u32>,
) -> ReusePlan {
    let mut plan = ReusePlan {
        next_id: next_id.max(
            old_cpg
                .ast
                .keys()
                .chain(new_cpg.ast.keys())
                .copied()
                .max()
                .unwrap_or(0)
                .saturating_add(1),
        ),
        ..ReusePlan::default()
    };

    let old_root = old_cpg
        .ast
        .iter()
        .find_map(|(id, node)| (node.parent_id.is_none()).then_some(*id));
    let new_root = new_cpg
        .ast
        .iter()
        .find_map(|(id, node)| (node.parent_id.is_none()).then_some(*id));

    let mut matched_old = BTreeSet::new();
    if let (Some(old_root), Some(new_root)) = (old_root, new_root) {
        match_subtrees(
            old_cpg,
            new_cpg,
            old_root,
            new_root,
            &mut plan.remap,
            &mut matched_old,
        );
    }

    plan.reused = plan.remap.len();

    for new_id in new_cpg.ast.keys().copied() {
        if plan.remap.contains_key(&new_id) {
            continue;
        }
        while prior_deleted.contains(&plan.next_id) {
            plan.next_id += 1;
        }
        plan.remap.insert(new_id, plan.next_id);
        plan.next_id += 1;
        plan.created += 1;
    }

    for old_id in old_cpg.ast.keys().copied() {
        if !matched_old.contains(&old_id) {
            plan.deleted_ids.insert(old_id);
        }
    }

    plan
}

fn match_subtrees(
    old_cpg: &Cpg,
    new_cpg: &Cpg,
    old_id: u32,
    new_id: u32,
    remap: &mut BTreeMap<u32, u32>,
    matched_old: &mut BTreeSet<u32>,
) {
    let Some(old_node) = old_cpg.ast.get(&old_id) else {
        return;
    };
    let Some(new_node) = new_cpg.ast.get(&new_id) else {
        return;
    };
    if !nodes_compatible(old_node, new_node) {
        return;
    }

    remap.insert(new_id, old_id);
    matched_old.insert(old_id);

    let mut unmatched_old: Vec<u32> = old_node.children.clone();

    for (idx, new_child_id) in new_node.children.iter().enumerate() {
        let Some(new_child) = new_cpg.ast.get(new_child_id) else {
            continue;
        };

        let mut matched = None;

        if let Some(candidate_old_id) = old_node.children.get(idx).copied() {
            if !matched_old.contains(&candidate_old_id) {
                if let Some(candidate_old) = old_cpg.ast.get(&candidate_old_id) {
                    if nodes_compatible(candidate_old, new_child)
                        && child_field_name(old_node, idx) == child_field_name(new_node, idx)
                    {
                        matched = Some(candidate_old_id);
                    }
                }
            }
        }

        if matched.is_none() {
            if let Some((unmatched_idx, candidate_old_id)) = unmatched_old
                .iter()
                .enumerate()
                .filter_map(|(unmatched_idx, old_candidate_id)| {
                    let old_candidate = old_cpg.ast.get(old_candidate_id)?;
                    if !nodes_compatible(old_candidate, new_child)
                        || matched_old.contains(old_candidate_id)
                    {
                        return None;
                    }
                    Some((
                        unmatched_idx,
                        *old_candidate_id,
                        structural_match_score(old_candidate, new_child),
                    ))
                })
                .max_by_key(|(_, _, score)| *score)
                .map(|(unmatched_idx, candidate_old_id, _)| (unmatched_idx, candidate_old_id))
            {
                unmatched_old.remove(unmatched_idx);
                matched = Some(candidate_old_id);
            }
        }

        if let Some(old_child_id) = matched {
            match_subtrees(
                old_cpg,
                new_cpg,
                old_child_id,
                *new_child_id,
                remap,
                matched_old,
            );
        }
    }
}

fn child_field_name(node: &crate::AstNode, idx: usize) -> Option<&str> {
    node.field_names.get(idx).and_then(|name| name.as_deref())
}

fn structural_match_score(old: &crate::AstNode, new: &crate::AstNode) -> i64 {
    let mut score = 0i64;
    if old.text == new.text {
        score += 100;
    }
    if old.operator == new.operator {
        score += 20;
    }
    if old.argument_count == new.argument_count {
        score += 10;
    }
    if old.children.len() == new.children.len() {
        score += 5;
    }
    let old_start = old.start_byte.unwrap_or(0) as i64;
    let new_start = new.start_byte.unwrap_or(0) as i64;
    score - (old_start - new_start).abs()
}

fn nodes_compatible(old: &crate::AstNode, new: &crate::AstNode) -> bool {
    if old.node_type != new.node_type {
        return false;
    }
    if old.operator != new.operator {
        return false;
    }
    if old.argument_count != new.argument_count {
        return false;
    }
    if old.field_names.len() != new.field_names.len() {
        return false;
    }
    match old.node_type.as_str() {
        "identifier"
        | "field_identifier"
        | "type_identifier"
        | "primitive_type"
        | "sized_type_specifier"
        | "number_literal"
        | "char_literal"
        | "string_literal"
        // Top-level container and function nodes: any text change (body or member
        // edit) must invalidate the old-ID mapping so the rebuilt subtree receives
        // fresh stable IDs.  Without this, a Replace edit inside a function or
        // class causes the rebuilt node to inherit the old node's ID, which is
        // then deleted by the removed_ids cleanup pass.
        //
        // Class/module containers
        | "class_declaration"       // Java / JS / TS / Python (top-level class)
        | "class_definition"        // Python
        | "impl_item"               // Rust impl block
        | "trait_item"              // Rust trait
        // Function nodes (all languages)
        | "function_definition"     // C / C++ / Python
        | "function_declaration"    // Go / JS / TS
        | "function_item"           // Rust
        | "method_declaration"      // Go / Java
        | "constructor_declaration" // Java
        | "function_expression"     // JS / TS
        | "arrow_function"          // JS / TS
        | "method_definition"       // JS / TS
        | "function_declarator"
        | "call_expression"
        | "return_statement" => old.text == new.text,
        _ => true,
    }
}

fn apply_cpg_remap(cpg: &mut Cpg, remap: &BTreeMap<u32, u32>) {
    let old_ast = std::mem::take(&mut cpg.ast);
    let mut new_ast = BTreeMap::new();
    for (old_new_id, mut node) in old_ast {
        let mapped_id = *remap.get(&old_new_id).unwrap_or(&old_new_id);
        node.children = node
            .children
            .into_iter()
            .map(|child_id| *remap.get(&child_id).unwrap_or(&child_id))
            .collect();
        node.parent_id = node.parent_id.map(|id| *remap.get(&id).unwrap_or(&id));
        node.function_id = node.function_id.map(|id| *remap.get(&id).unwrap_or(&id));
        new_ast.insert(mapped_id, node);
    }
    cpg.ast = new_ast;

    for bb in cpg.basic_blocks.values_mut() {
        bb.nodes = bb
            .nodes
            .iter()
            .map(|id| *remap.get(id).unwrap_or(id))
            .collect();
        bb.function = *remap.get(&bb.function).unwrap_or(&bb.function);
    }

    let old_call_graph = std::mem::take(&mut cpg.call_graph);
    let mut new_call_graph = BTreeMap::new();
    for (func_id, mut entry) in old_call_graph {
        let mapped_func_id = *remap.get(&func_id).unwrap_or(&func_id);
        for call in &mut entry.calls {
            call.callee_id = call.callee_id.map(|id| *remap.get(&id).unwrap_or(&id));
        }
        entry.called_by = entry
            .called_by
            .into_iter()
            .map(|id| *remap.get(&id).unwrap_or(&id))
            .collect();
        new_call_graph.insert(mapped_func_id, entry);
    }
    cpg.call_graph = new_call_graph;

    for def in &mut cpg.dataflow.definitions {
        def.node_id = *remap.get(&def.node_id).unwrap_or(&def.node_id);
        def.function_id = def.function_id.map(|id| *remap.get(&id).unwrap_or(&id));
    }
    for use_item in &mut cpg.dataflow.uses {
        use_item.node_id = *remap.get(&use_item.node_id).unwrap_or(&use_item.node_id);
        use_item.function_id = use_item
            .function_id
            .map(|id| *remap.get(&id).unwrap_or(&id));
    }
    for edge in &mut cpg.dataflow.edges {
        edge.source = *remap.get(&edge.source).unwrap_or(&edge.source);
        edge.destination = *remap.get(&edge.destination).unwrap_or(&edge.destination);
    }
}

fn remap_pointer_maps(
    node_to_id: &mut BTreeMap<u64, u32>,
    id_to_node_ptr: &mut BTreeMap<u32, u64>,
    remap: &BTreeMap<u32, u32>,
) {
    for node_id in node_to_id.values_mut() {
        *node_id = *remap.get(node_id).unwrap_or(node_id);
    }
    let old = std::mem::take(id_to_node_ptr);
    for (node_id, node_ptr) in old {
        let mapped_id = *remap.get(&node_id).unwrap_or(&node_id);
        id_to_node_ptr.insert(mapped_id, node_ptr);
    }
}

fn clear_basic_block_annotations(
    ast: &mut BTreeMap<u32, crate::AstNode>,
    affected_function_ids: Option<&BTreeSet<u32>>,
) {
    for node in ast.values_mut() {
        let should_clear = affected_function_ids.map_or(true, |affected| {
            node.function_id
                .is_some_and(|function_id| affected.contains(&function_id))
        });
        if should_clear {
            node.basic_block = None;
        }
    }
}

/// Recompute CFG topology signatures for the given set of functions and update
/// `sig_store`.  Returns the subset of `function_ids` whose topology changed
/// (i.e. SCC structure differs from the stored signature).
///
/// A topology change means loops were added, removed, or restructured — callers
/// of such functions must be fully re-analysed.  Functions that changed only
/// their internal edge labels (no loop-structure change) can use delta-only
/// propagation, which is cheaper.
pub fn update_and_diff_topology_sigs(
    basic_blocks: &BTreeMap<String, crate::BasicBlock>,
    _ast: &BTreeMap<u32, crate::AstNode>,
    function_ids: &BTreeSet<u32>,
    sig_store: &mut BTreeMap<u32, u64>,
) -> BTreeSet<u32> {
    let mut topology_changed = BTreeSet::new();

    for &fn_id in function_ids {
        // Collect BB IDs belonging to this function.
        let fn_bbs: Vec<&str> = basic_blocks
            .iter()
            .filter(|(_, bb)| bb.function == fn_id)
            .map(|(id, _)| id.as_str())
            .collect();

        let sccs = compute_cfg_sccs(basic_blocks, &fn_bbs);
        let new_sig = cfg_topology_sig(basic_blocks, &sccs);
        let old_sig = sig_store.get(&fn_id).copied().unwrap_or(u64::MAX);

        sig_store.insert(fn_id, new_sig);
        if new_sig != old_sig {
            topology_changed.insert(fn_id);
        }
    }

    topology_changed
}

fn expand_incremental_function_targets(
    old_ast: &BTreeMap<u32, crate::AstNode>,
    ast: &BTreeMap<u32, crate::AstNode>,
    maps: &crate::dfg::PreprocessingMaps,
    previous_dataflow: &crate::DataflowGraph,
    previous_call_graph: &BTreeMap<u32, crate::CallGraphEntry>,
    affected_function_ids: &BTreeSet<u32>,
    topology_changed_fns: &BTreeSet<u32>,
    has_global_changes: bool,
    macro_aliases: Option<&BTreeMap<String, String>>,
) -> BTreeSet<u32> {
    let function_map = &maps.1;
    let mut targets = affected_function_ids.clone();

    if has_global_changes {
        let changed_global_names = collect_global_definition_names(ast)
            .symmetric_difference(&collect_global_definition_names(old_ast))
            .cloned()
            .collect::<BTreeSet<_>>();
        let changed_global_names = if changed_global_names.is_empty() {
            previous_dataflow
                .definitions
                .iter()
                .filter(|def| def.function_id.is_none())
                .map(|def| def.variable.clone())
                .collect::<BTreeSet<_>>()
        } else {
            changed_global_names
        };
        for use_item in &previous_dataflow.uses {
            if changed_global_names.contains(&use_item.variable) {
                if let Some(function_id) = use_item.function_id {
                    targets.insert(function_id);
                }
            }
        }
    }

    // Build a map from variable name → functions that use that variable, for
    // the delta-propagation tier (edge-only-changed functions).
    let var_to_users: std::collections::HashMap<&str, BTreeSet<u32>> = {
        let mut m: std::collections::HashMap<&str, BTreeSet<u32>> =
            std::collections::HashMap::new();
        for use_item in &previous_dataflow.uses {
            if let Some(fid) = use_item.function_id {
                m.entry(use_item.variable.as_str()).or_default().insert(fid);
            }
        }
        m
    };

    // Collect the return-variable names exported by each affected function
    // (used by the delta tier to limit caller expansion).
    let affected_return_vars: BTreeSet<String> = previous_dataflow
        .edges
        .iter()
        .filter(|e| {
            e.edge_type == "RETURN_FLOW"
                && previous_dataflow.definitions.iter().any(|d| {
                    d.node_id == e.source
                        && affected_function_ids.contains(&d.function_id.unwrap_or(u32::MAX))
                })
        })
        .map(|e| e.variable.clone())
        .collect();

    // Tier-1: topology-changed functions → expand to ALL transitive callers
    //         (same as the original algorithm).
    // Tier-2: edge-only-changed functions → expand only to callers that use
    //         a return variable of the changed function.
    //
    // Functions NOT in topology_changed_fns use the cheaper Tier-2 path.
    let tier1_frontier: BTreeSet<u32> = targets
        .iter()
        .filter(|fid| topology_changed_fns.contains(fid) || has_global_changes)
        .copied()
        .collect();

    let tier2_frontier: BTreeSet<u32> = targets
        .iter()
        .filter(|fid| !topology_changed_fns.contains(fid) && !has_global_changes)
        .copied()
        .collect();

    // ── Tier-1 full transitive closure ───────────────────────────────────────
    let mut t1_frontier = tier1_frontier;
    while !t1_frontier.is_empty() {
        let mut next = BTreeSet::new();
        for (caller_id, entry) in previous_call_graph {
            if targets.contains(caller_id) {
                continue;
            }
            if entry
                .calls
                .iter()
                .filter_map(|call| call.callee_id)
                .any(|callee_id| t1_frontier.contains(&callee_id))
            {
                next.insert(*caller_id);
            }
        }

        for (node_id, node) in ast {
            if !node.is_call() {
                continue;
            }
            let Some(caller_id) = function_map.get(node_id).copied() else {
                continue;
            };
            if targets.contains(&caller_id) {
                continue;
            }
            let Some(callee_name) =
                crate::dfg::extract_called_function_name(ast, *node_id, macro_aliases)
            else {
                continue;
            };
            if t1_frontier.iter().any(|fid| {
                previous_call_graph
                    .get(fid)
                    .map(|entry| entry.name == callee_name)
                    .unwrap_or(false)
            }) {
                next.insert(caller_id);
            }
        }

        targets.extend(next.iter().copied());
        t1_frontier = next;
    }

    // ── Tier-2 delta-propagation: only callers using changed return vars ──────
    if !tier2_frontier.is_empty() && !affected_return_vars.is_empty() {
        for var in &affected_return_vars {
            if let Some(users) = var_to_users.get(var.as_str()) {
                for &user_fn in users {
                    if !targets.contains(&user_fn) {
                        // Check this user actually calls a tier-2-changed function.
                        let calls_changed = previous_call_graph
                            .get(&user_fn)
                            .map(|entry| {
                                entry
                                    .calls
                                    .iter()
                                    .filter_map(|c| c.callee_id)
                                    .any(|cid| tier2_frontier.contains(&cid))
                            })
                            .unwrap_or(false);
                        if calls_changed {
                            targets.insert(user_fn);
                        }
                    }
                }
            }
        }
    }

    targets
}

fn collect_global_definition_names(ast: &BTreeMap<u32, crate::AstNode>) -> BTreeSet<String> {
    ast.iter()
        .filter(|(_, node)| node.function_id.is_none())
        .filter_map(|(_, node)| {
            if node.is_identifier() || node.node_type == "enumerator" {
                node.text.clone()
            } else {
                None
            }
        })
        .collect()
}

fn shift_subtree_positions(
    ast: &mut BTreeMap<u32, crate::AstNode>,
    root_id: u32,
    delta: isize,
    source: &[u8],
) {
    if delta == 0 {
        return;
    }
    let mut stack = vec![root_id];
    while let Some(node_id) = stack.pop() {
        let Some(node) = ast.get_mut(&node_id) else {
            continue;
        };
        if let Some(start) = node.start_byte {
            let updated = (start as isize + delta).max(0) as usize;
            node.start_byte = Some(updated as u32);
            let (row, column) = point_from_offset(source, updated);
            node.line = (row + 1) as u32;
            node.column = column as u32;
        }
        if let Some(end) = node.end_byte {
            let updated = (end as isize + delta).max(0) as usize;
            node.end_byte = Some(updated as u32);
            let (row, column) = point_from_offset(source, updated);
            node.end_line = (row + 1) as u32;
            node.end_column = column as u32;
        }
        stack.extend(node.children.iter().copied());
    }
}

fn extract_subtree_cpg(cpg: &Cpg, root_id: u32) -> Cpg {
    let mut ids = BTreeSet::new();
    collect_subtree_ids(&cpg.ast, root_id, &mut ids);
    let live_ids = ids.clone();
    let mut ast = BTreeMap::new();
    for node_id in ids {
        let Some(node) = cpg.ast.get(&node_id).cloned() else {
            continue;
        };
        ast.insert(node_id, node);
    }
    for node in ast.values_mut() {
        node.children.retain(|child_id| live_ids.contains(child_id));
        if node
            .parent_id
            .is_some_and(|parent_id| !live_ids.contains(&parent_id))
        {
            node.parent_id = None;
        }
        if node
            .function_id
            .is_some_and(|function_id| !live_ids.contains(&function_id))
        {
            node.function_id = None;
        }
    }
    Cpg {
        ast,
        basic_blocks: BTreeMap::new(),
        call_graph: BTreeMap::new(),
        dataflow: Default::default(),
        source_file: cpg.source_file.clone(),
        language: cpg.language.clone(),
        comments: cpg.comments.clone(),
        macro_aliases: cpg.macro_aliases.clone(),
        macro_bodies: cpg.macro_bodies.clone(),
        custom_allocators: cpg.custom_allocators.clone(),
        cross_file_calls: Vec::new(),
        cpp_metadata: cpg.cpp_metadata.clone(),
        go_metadata: cpg.go_metadata.clone(),
        python_metadata: cpg.python_metadata.clone(),
        java_metadata: cpg.java_metadata.clone(),
        js_metadata: cpg.js_metadata.clone(),
        ts_metadata: cpg.ts_metadata.clone(),
        rust_metadata: cpg.rust_metadata.clone(),
        class_hierarchy: cpg.class_hierarchy.clone(),
        function_summaries: cpg.function_summaries.clone(),
    }
}

pub fn compute_edit(old_source: &[u8], new_source: &[u8]) -> Option<TextEdit> {
    if old_source == new_source {
        return None;
    }

    let mut prefix = 0usize;
    let min_len = old_source.len().min(new_source.len());
    while prefix < min_len && old_source[prefix] == new_source[prefix] {
        prefix += 1;
    }

    let mut old_suffix = old_source.len();
    let mut new_suffix = new_source.len();
    while old_suffix > prefix
        && new_suffix > prefix
        && old_source[old_suffix - 1] == new_source[new_suffix - 1]
    {
        old_suffix -= 1;
        new_suffix -= 1;
    }

    let start_point = point_from_offset(old_source, prefix);
    let old_end_point = point_from_offset(old_source, old_suffix);
    let new_end_point = point_from_offset(new_source, new_suffix);

    let change_type = if old_suffix == prefix && new_suffix > prefix {
        ChangeType::Insert
    } else if new_suffix == prefix && old_suffix > prefix {
        ChangeType::Delete
    } else {
        ChangeType::Replace
    };

    Some(TextEdit {
        start_byte: prefix,
        old_end_byte: old_suffix,
        new_end_byte: new_suffix,
        start_point,
        old_end_point,
        new_end_point,
        change_type,
    })
}

fn point_from_offset(source: &[u8], offset: usize) -> (usize, usize) {
    let mut row = 0usize;
    let mut column = 0usize;
    let mut i = 0usize;
    let upper = offset.min(source.len());
    while i < upper {
        if source[i] == b'\n' {
            row += 1;
            column = 0;
        } else {
            column += 1;
        }
        i += 1;
    }
    (row, column)
}

/// Builds a `LightweightIndex` from a CPG that has AST + call graph but no CFG/DFG.
fn build_lightweight_index(cpg: &Cpg) -> LightweightIndex {
    let mut function_names = Vec::new();
    let mut function_node_ids = BTreeMap::new();
    let mut global_constants = BTreeMap::new();

    for (node_id, node) in &cpg.ast {
        if node.is_method_def() {
            if let Some(name) = get_func_def_name(&cpg.ast, *node_id) {
                function_names.push(name.clone());
                function_node_ids.insert(name, *node_id);
            }
        }

        // Top-level const/static variable declarations.
        if node.parent_id.is_none() {
            continue;
        }
        let is_top_level = cpg
            .ast
            .get(&node.parent_id.unwrap())
            .map(|p| p.parent_id.is_none())
            .unwrap_or(false);
        if !is_top_level {
            continue;
        }
        if !node.is_local_def() {
            continue;
        }
        let Some(text) = &node.text else { continue };
        let is_const_or_static = text.contains("const ") || text.contains("static ");
        if !is_const_or_static {
            continue;
        }
        // Use the identifier child as the key.
        for child_id in &node.children {
            if let Some(child) = cpg.ast.get(child_id) {
                if child.is_identifier() {
                    if let Some(name) = &child.text {
                        global_constants.insert(name.clone(), node.clone());
                        break;
                    }
                }
            }
        }
    }

    // Build call_edges from call_graph.
    let mut call_edges: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (func_id, entry) in &cpg.call_graph {
        let caller_name =
            get_func_def_name(&cpg.ast, *func_id).unwrap_or_else(|| format!("fn_{func_id}"));
        let callees: Vec<String> = entry.calls.iter().map(|cs| cs.callee.clone()).collect();
        call_edges.insert(caller_name, callees);
    }

    LightweightIndex {
        function_names,
        call_edges,
        global_constants,
        function_node_ids,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpg_generator::GraphBuildOptions;
    use std::collections::BTreeSet;

    #[test]
    fn incremental_parse_updates_state() {
        let mut inc = IncrementalCpgGenerator::new(GraphBuildOptions::default()).expect("init");
        let base = b"int main(){int x=1;return x;}";
        let initial = inc.parse_initial(base).expect("initial");
        assert!(!initial.ast.is_empty());

        let updated = b"int main(){int x=2;return x;}";
        let edit = TextEdit {
            start_byte: 17,
            old_end_byte: 18,
            new_end_byte: 18,
            start_point: (0, 17),
            old_end_point: (0, 18),
            new_end_point: (0, 18),
            change_type: ChangeType::Replace,
        };
        let next = inc.apply_edit(&edit, updated).expect("incremental");
        assert!(!next.ast.is_empty());
    }

    #[test]
    fn compute_edit_detects_insert() {
        let old = b"int main(){return 0;}";
        let new = b"int main(){int x=1;return 0;}";
        let edit = compute_edit(old, new).expect("edit");
        assert_eq!(edit.change_type, ChangeType::Insert);
        assert_eq!(edit.start_byte, 11);
        assert_eq!(edit.old_end_byte, 11);
        assert_eq!(edit.new_end_byte, 19);
    }

    #[test]
    fn compute_edit_detects_replace() {
        let old = b"int main(){int x=1;return x;}";
        let new = b"int main(){int x=2;return x;}";
        let edit = compute_edit(old, new).expect("edit");
        assert_eq!(edit.change_type, ChangeType::Replace);
        assert_eq!(edit.start_byte, 17);
        assert_eq!(edit.old_end_byte, 18);
        assert_eq!(edit.new_end_byte, 18);
    }

    #[test]
    fn parse_incremental_accepts_compute_edit() {
        let mut inc = IncrementalCpgGenerator::new(GraphBuildOptions::default()).expect("init");
        let old = b"int main(){int x=1;return x;}";
        let new = b"int main(){int x=2;return x;}";
        let before = inc.parse_initial(old).expect("initial");
        assert!(!before.ast.is_empty());

        let edit = compute_edit(old, new).expect("edit");
        let after = inc.parse_incremental(new, &[edit]).expect("incremental");
        assert!(!after.ast.is_empty());
    }

    #[test]
    fn incremental_result_matches_fresh_full_parse_signature() {
        let options = GraphBuildOptions::default();
        let mut inc = IncrementalCpgGenerator::new(options.clone()).expect("init");
        let old = b"int add(int a,int b){return a+b;} int main(){return add(1,2);}";
        let new = b"int add(int a,int b){int c=a+b;return c;} int main(){return add(1,2);}";
        let _ = inc.parse_initial(old).expect("initial");
        let edit = compute_edit(old, new).expect("edit");
        let updated = inc.parse_incremental(new, &[edit]).expect("incremental");

        let mut full = IncrementalCpgGenerator::new(options).expect("fresh");
        let fresh = full.parse_full(new).expect("full");

        assert_eq!(updated.ast.len(), fresh.ast.len());
        assert_eq!(updated.dataflow.edges.len(), fresh.dataflow.edges.len());

        let updated_types: BTreeSet<String> =
            updated.ast.values().map(|n| n.node_type.clone()).collect();
        let fresh_types: BTreeSet<String> =
            fresh.ast.values().map(|n| n.node_type.clone()).collect();
        assert_eq!(updated_types, fresh_types);
    }

    #[test]
    fn incremental_state_round_trip() {
        let mut inc = IncrementalCpgGenerator::new(GraphBuildOptions::default()).expect("init");
        let source = b"int main(){int x=1;return x;}";
        let parsed_len = inc.parse_initial(source).expect("parse").ast.len();
        assert!(parsed_len > 0);

        let state_path = std::env::temp_dir().join("rust-scuzz-inc-state.bin");
        inc.save_state(&state_path).expect("save");

        let mut loaded = IncrementalCpgGenerator::new(GraphBuildOptions::default()).expect("init");
        let ok = loaded.load_state(&state_path).expect("load");
        assert!(ok);
        let cpg = loaded.state.cpg.as_ref().expect("loaded cpg");
        assert_eq!(cpg.ast.len(), parsed_len);
    }

    #[test]
    fn parse_lightweight_returns_index_and_stores_tree() {
        let mut cpg_gen = IncrementalCpgGenerator::new(GraphBuildOptions::default()).expect("init");
        let source = b"static const int LIMIT = 100;\nvoid foo(){}\nvoid bar(){ foo(); }";
        let index = cpg_gen.parse_lightweight(source).expect("lightweight");

        // Tree is stored for later reuse.
        assert!(cpg_gen.tree.is_some());
        // AST-only CPG is stored (no CFG/DFG yet).
        let cpg = cpg_gen.state.cpg.as_ref().expect("cpg stored");
        assert!(cpg.basic_blocks.is_empty(), "CFG should not be built yet");
        assert!(cpg.dataflow.edges.is_empty(), "DFG should not be built yet");

        // Index contains structural metadata.
        assert!(index.function_names.contains(&"foo".to_string()));
        assert!(index.function_names.contains(&"bar".to_string()));
        assert!(
            index
                .call_edges
                .get("bar")
                .map(|v| v.contains(&"foo".to_string()))
                .unwrap_or(false)
        );
        // global_constants may or may not capture simple const ints depending on AST shape.
    }

    #[test]
    fn generate_function_cpg_extends_lightweight_cpg() {
        let mut cpg_gen = IncrementalCpgGenerator::new(GraphBuildOptions::default()).expect("init");
        let source = b"void foo(int x){ if(x>0){x=x-1;} }\nvoid bar(){ foo(1); }";
        let index = cpg_gen.parse_lightweight(source).expect("lightweight");

        // CPG has no CFG/DFG before generate_function_cpg.
        let pre_bbs = cpg_gen.state.cpg.as_ref().unwrap().basic_blocks.len();
        assert_eq!(pre_bbs, 0);

        // Generate CPG for foo only.
        let foo_id = index.function_node_ids.get("foo").copied().unwrap();
        let fn_ids: std::collections::BTreeSet<u32> = [foo_id].into_iter().collect();
        let cpg = cpg_gen.generate_function_cpg(&fn_ids).expect("gen fn cpg");

        // CFG blocks now exist for foo.
        assert!(!cpg.basic_blocks.is_empty());
        // DFG edges now exist.
        assert!(!cpg.dataflow.edges.is_empty());
        // Tree is still stored for subsequent apply_edit calls.
        assert!(cpg_gen.tree.is_some());
    }
}
