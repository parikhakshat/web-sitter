use std::collections::{HashMap, HashSet};
use std::collections::VecDeque;
use std::path::PathBuf;
use web_sitter::{Cpg, FunctionSummary, IrNode, IrNodeKind, NodeId};
use crate::dfg::{DfgIndex, TaintConfig};
use crate::ir::{TaintEndpointRef, TaintSpec};

// ── Taint endpoint resolution ─────────────────────────────────────────────────

/// A resolved taint endpoint: a concrete node that acts as a source or sink.
#[derive(Debug, Clone)]
pub struct ResolvedEndpoint {
    pub node: NodeId,
    /// The name of the source/sink/sanitizer definition that matched.
    pub def_name: String,
}

/// Registry of named source / sink / sanitizer / propagator definitions.
/// These are evaluated against the CPG to yield concrete node sets.
pub struct EndpointRegistry {
    /// name → closure that extracts matching nodes from a CPG
    extractors: HashMap<String, Box<dyn Fn(&Cpg) -> Vec<NodeId> + Send + Sync>>,
    /// name → closure that extracts (from, to) propagator edge pairs from a CPG
    propagator_extractors: HashMap<String, Box<dyn Fn(&Cpg) -> Vec<(NodeId, NodeId)> + Send + Sync>>,
}

impl EndpointRegistry {
    pub fn new() -> Self {
        Self {
            extractors: HashMap::new(),
            propagator_extractors: HashMap::new(),
        }
    }

    pub fn register(
        &mut self,
        name: impl Into<String>,
        f: impl Fn(&Cpg) -> Vec<NodeId> + Send + Sync + 'static,
    ) {
        self.extractors.insert(name.into(), Box::new(f));
    }

    /// Register a pre-computed static list of node IDs for a given endpoint name.
    /// Useful for registering per-CPG source/sink nodes derived from SearchPlan evaluation.
    pub fn register_static(&mut self, name: impl Into<String>, nodes: Vec<NodeId>) {
        self.extractors.insert(name.into(), Box::new(move |_| nodes.clone()));
    }

    /// Merge all entries from `other` into this registry, with `other` taking precedence.
    pub fn merge_from(&mut self, other: EndpointRegistry) {
        for (name, f) in other.extractors {
            self.extractors.insert(name, f);
        }
        for (name, f) in other.propagator_extractors {
            self.propagator_extractors.insert(name, f);
        }
    }

    /// Register a propagator: a function that returns (from_node, to_node) pairs
    /// representing extra taint-flow edges (e.g. memcpy arg0 → arg1).
    pub fn register_propagator(
        &mut self,
        name: impl Into<String>,
        f: impl Fn(&Cpg) -> Vec<(NodeId, NodeId)> + Send + Sync + 'static,
    ) {
        self.propagator_extractors.insert(name.into(), Box::new(f));
    }

    pub fn resolve(&self, endpoint: &TaintEndpointRef, cpg: &Cpg) -> Vec<ResolvedEndpoint> {
        match self.extractors.get(&endpoint.name) {
            Some(f) => f(cpg)
                .into_iter()
                .map(|node| ResolvedEndpoint { node, def_name: endpoint.name.clone() })
                .collect(),
            None => vec![],
        }
    }

    pub fn resolve_propagator(&self, name: &str, cpg: &Cpg) -> Vec<(NodeId, NodeId)> {
        match self.propagator_extractors.get(name) {
            Some(f) => f(cpg),
            None => vec![],
        }
    }
}

impl Default for EndpointRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Taint finding ─────────────────────────────────────────────────────────────

/// A single taint-flow finding: a concrete source→sink path that was confirmed.
#[derive(Debug, Clone)]
pub struct TaintFinding {
    pub source_node: NodeId,
    pub source_def: String,
    pub sink_node: NodeId,
    pub sink_def: String,
    /// Intermediate nodes along the taint path (may be empty if direct).
    pub path: Vec<NodeId>,
}

/// Cross-file context for interprocedural DFG traversal.
pub struct CrossFileTaintCtx<'a> {
    /// Per-file DFG indexes and CPGs.
    pub file_dfgs: &'a HashMap<PathBuf, (DfgIndex, Cpg)>,
    /// Maps call_node (in the current file) → list of (callee_file, callee_param_node_ids).
    /// Built by `Workspace::build_cross_file_edges()`.
    pub call_to_callee_params: &'a HashMap<NodeId, Vec<(PathBuf, Vec<NodeId>)>>,
}

// ── Taint engine ──────────────────────────────────────────────────────────────

pub struct TaintEngine<'a> {
    pub registry: &'a EndpointRegistry,
    pub dfg: &'a DfgIndex,
    pub cpg: &'a Cpg,
    /// Function summaries for interprocedural expansion.
    pub summaries: &'a HashMap<String, FunctionSummary>,
    /// Optional cross-file DFG context for cross-file taint propagation.
    pub cross_file: Option<&'a CrossFileTaintCtx<'a>>,
}

impl<'a> TaintEngine<'a> {
    pub fn new(
        registry: &'a EndpointRegistry,
        dfg: &'a DfgIndex,
        cpg: &'a Cpg,
        summaries: &'a HashMap<String, FunctionSummary>,
    ) -> Self {
        Self { registry, dfg, cpg, summaries, cross_file: None }
    }

    pub fn with_cross_file(mut self, ctx: &'a CrossFileTaintCtx<'a>) -> Self {
        self.cross_file = Some(ctx);
        self
    }

    /// Run a full taint check for the given spec, returning all findings.
    pub fn run(&self, spec: &TaintSpec) -> Vec<TaintFinding> {
        // Resolve all sources, sinks, and sanitizers to concrete nodes
        let sources: Vec<ResolvedEndpoint> = spec
            .sources
            .iter()
            .flat_map(|s| self.registry.resolve(s, self.cpg))
            .collect();

        let sinks: Vec<ResolvedEndpoint> = spec
            .sinks
            .iter()
            .flat_map(|s| self.registry.resolve(s, self.cpg))
            .collect();

        let sanitizer_nodes: HashSet<NodeId> = spec
            .sanitizers
            .iter()
            .flat_map(|s| self.registry.resolve(s, self.cpg))
            .map(|r| r.node)
            .collect();

        // Extra propagator edges (node-level; from propagator defs)
        let propagator_edges: Vec<(NodeId, NodeId)> = self
            .resolve_propagator_edges(&spec.propagators);

        if sources.is_empty() || sinks.is_empty() {
            return vec![];
        }

        let taint_cfg = TaintConfig {
            sanitizer_nodes: &sanitizer_nodes,
            propagator_edges: &propagator_edges,
            max_depth: spec.max_call_depth * 2 + 1, // generous bound
        };

        let source_ids: Vec<NodeId> = sources.iter().map(|r| r.node).collect();
        let mut result = self.dfg.propagate_taint(&source_ids, &taint_cfg);

        // Interprocedural expansion: for each tainted Call node, check if any
        // argument is tainted. If a function summary says arg_i → return, mark
        // the call node itself as tainted (representing the return value) and
        // re-propagate. This handles library functions without DFG edges.
        if spec.require_interprocedural && !self.summaries.is_empty() {
            self.expand_interprocedural(&mut result, &sanitizer_nodes, &taint_cfg);
        }

        // Cross-file interprocedural expansion: propagate taint into callee files
        // when a tainted call node's callee is defined in another file.
        if spec.require_interprocedural && self.cross_file.is_some() {
            let mut changed = true;
            while changed {
                changed = self.expand_cross_file(&mut result, &taint_cfg);
                if changed {
                    // Re-propagate from any newly tainted nodes in the current file.
                    let new_tainted: Vec<NodeId> = result.tainted.iter().copied().collect();
                    let extra = self.dfg.propagate_taint(&new_tainted, &taint_cfg);
                    for node in extra.tainted {
                        result.tainted.insert(node);
                    }
                }
            }
        }

        // Check which sinks are reachable and emit findings
        let mut findings = Vec::new();
        for sink in &sinks {
            if result.tainted.contains(&sink.node) {
                // Find which source leads to this sink
                for src in &sources {
                    if self.dfg.reaches(src.node, sink.node)
                    {
                        // Enforce same-function constraint when requested
                        if spec.require_same_function {
                            let src_fn = self.cpg.ast.get(&src.node).and_then(|n| n.function_id);
                            let sink_fn = self.cpg.ast.get(&sink.node).and_then(|n| n.function_id);
                            if src_fn != sink_fn || src_fn.is_none() {
                                continue;
                            }
                        }
                        // Build a minimal path (source → sink) via BFS
                        let path = self.shortest_path(src.node, sink.node, &taint_cfg);
                        findings.push(TaintFinding {
                            source_node: src.node,
                            source_def: src.def_name.clone(),
                            sink_node: sink.node,
                            sink_def: sink.def_name.clone(),
                            path,
                        });
                    }
                }
            }
        }

        findings
    }

    fn resolve_propagator_edges(&self, propagators: &[TaintEndpointRef]) -> Vec<(NodeId, NodeId)> {
        let mut edges = Vec::new();
        for prop in propagators {
            let pairs = self.registry.resolve_propagator(&prop.name, self.cpg);
            edges.extend(pairs);
        }
        edges
    }

    /// Worklist-driven interprocedural taint expansion: for each Call node whose
    /// arguments are tainted, consult its function summary; if the summary says
    /// `TaintReturn(arg_i)`, mark the call node itself as tainted (representing its
    /// return value) and continue expanding from there. Mutates `result.tainted`
    /// in place.
    ///
    /// Precomputes each call's argument ids once, plus a reverse index (argument
    /// node id → calls that read it), so each round only re-checks calls whose
    /// inputs actually changed in the previous round instead of rescanning every
    /// node in the AST — the standard "dirty node" worklist shape for incremental
    /// dataflow fixpoints.
    fn expand_interprocedural(
        &self,
        result: &mut crate::dfg::TaintResult,
        sanitizer_nodes: &HashSet<NodeId>,
        taint_cfg: &TaintConfig<'_>,
    ) {
        let (call_args, arg_to_calls) = index_call_arguments(self.cpg);

        let mut frontier: HashSet<NodeId> = HashSet::new();
        for t in &result.tainted {
            if let Some(calls) = arg_to_calls.get(t) {
                frontier.extend(calls.iter().copied());
            }
        }

        while !frontier.is_empty() {
            let mut new_tainted: Vec<NodeId> = Vec::new();
            let mut next_frontier: HashSet<NodeId> = HashSet::new();

            for &call_id in &frontier {
                if sanitizer_nodes.contains(&call_id) || result.tainted.contains(&call_id) {
                    continue;
                }
                let Some(node) = self.cpg.ast.get(&call_id) else { continue };
                let Some(arg_ids) = call_args.get(&call_id) else { continue };
                let tainted_args: HashSet<usize> = arg_ids
                    .iter()
                    .enumerate()
                    .filter(|(_, arg_id)| result.tainted.contains(arg_id))
                    .map(|(i, _)| i)
                    .collect();
                if tainted_args.is_empty() {
                    continue;
                }

                let expansion = expand_call_with_summary(node, &tainted_args, self.summaries);
                if let TaintExpansionResult::Known { return_tainted: true, .. } = expansion {
                    result.tainted.insert(call_id);
                    new_tainted.push(call_id);
                    // The call node itself may be a literal argument to another call
                    // (e.g. `outer(inner(x))`) — re-check those callers directly,
                    // since they won't necessarily show up via DFG propagation below.
                    if let Some(calls) = arg_to_calls.get(&call_id) {
                        next_frontier.extend(calls.iter().copied());
                    }
                }
            }

            if !new_tainted.is_empty() {
                // Propagate only from the newly tainted nodes (not all tainted nodes)
                // to avoid quadratic re-propagation on each iteration.
                let extra = self.dfg.propagate_taint(&new_tainted, taint_cfg);
                for node in extra.tainted {
                    if result.tainted.insert(node) {
                        if let Some(calls) = arg_to_calls.get(&node) {
                            next_frontier.extend(calls.iter().copied());
                        }
                    }
                }
            }

            frontier = next_frontier;
        }
    }

    /// Cross-file taint expansion: when a call node is tainted and the callee
    /// lives in another file, propagate taint into the callee's DFG and check
    /// if return nodes become tainted, marking the call node as the return value.
    fn expand_cross_file(
        &self,
        result: &mut crate::dfg::TaintResult,
        taint_cfg: &TaintConfig<'_>,
    ) -> bool {
        let Some(ctx) = self.cross_file else { return false };
        let mut changed = false;

        // `call_to_callee_params` is already the sparse set of call sites with a
        // resolved cross-file callee (built once by `Workspace::build_cross_file_edges`)
        // — iterate it directly instead of rescanning every node in the AST.
        for (node_id, callee_list) in ctx.call_to_callee_params {
            if !result.tainted.contains(node_id) {
                continue;
            }
            let Some(node) = self.cpg.ast.get(node_id) else { continue };

            for (callee_file, callee_params) in callee_list {
                let Some((callee_dfg, callee_cpg)) = ctx.file_dfgs.get(callee_file) else { continue };

                // Find which argument nodes at this call site are tainted, and map
                // them to the corresponding callee param nodes.
                let tainted_param_nodes: Vec<NodeId> = node
                    .children
                    .iter()
                    .enumerate()
                    .filter(|(_, arg_id)| result.tainted.contains(*arg_id))
                    .filter_map(|(i, _)| callee_params.get(i).copied())
                    .collect();

                if tainted_param_nodes.is_empty() {
                    continue;
                }

                let sanitizers_empty = HashSet::new();
                let props_empty = [];
                let callee_cfg = TaintConfig {
                    sanitizer_nodes: &sanitizers_empty,
                    propagator_edges: &props_empty,
                    max_depth: taint_cfg.max_depth,
                };
                let callee_result = callee_dfg.propagate_taint(&tainted_param_nodes, &callee_cfg);

                // If any Return node in the callee is tainted, mark the call node itself.
                let callee_return_tainted = callee_cpg.ast.iter().any(|(id, n)| {
                    n.kind == IrNodeKind::Return && callee_result.tainted.contains(id)
                });

                if callee_return_tainted && result.tainted.insert(*node_id) {
                    changed = true;
                }
            }
        }

        changed
    }

    fn shortest_path(
        &self,
        from: NodeId,
        to: NodeId,
        cfg: &TaintConfig<'_>,
    ) -> Vec<NodeId> {
        let mut visited: HashMap<NodeId, NodeId> = HashMap::new(); // node → parent
        let mut queue = VecDeque::new();
        queue.push_back(from);
        visited.insert(from, from);

        while let Some(node) = queue.pop_front() {
            if node == to {
                // Reconstruct path
                let mut path = vec![to];
                let mut cur = to;
                while cur != from {
                    cur = *visited.get(&cur).unwrap();
                    path.push(cur);
                }
                path.reverse();
                return path;
            }
            for &s in self.dfg.successors(node) {
                if !visited.contains_key(&s) && !cfg.sanitizer_nodes.contains(&s) {
                    visited.insert(s, node);
                    queue.push_back(s);
                }
            }
            for &(f, t) in cfg.propagator_edges {
                if f == node && !visited.contains_key(&t) {
                    visited.insert(t, node);
                    queue.push_back(t);
                }
            }
        }

        vec![from, to] // fallback: direct edge
    }
}

/// For every `Call` node in `cpg`, collect its ordered argument node ids (descending
/// into an `argument_list`/`arguments` container child when present, matching the
/// per-language call shapes used elsewhere in this module), plus the reverse index
/// (argument node id → calls that read it). Used to drive the interprocedural taint
/// expansion worklist without rescanning the whole AST on every round.
fn index_call_arguments(
    cpg: &Cpg,
) -> (HashMap<NodeId, Vec<NodeId>>, HashMap<NodeId, Vec<NodeId>>) {
    let mut call_args: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
    let mut arg_to_calls: HashMap<NodeId, Vec<NodeId>> = HashMap::new();

    for (&node_id, node) in &cpg.ast {
        if node.kind != IrNodeKind::Call {
            continue;
        }
        let arg_ids: Vec<NodeId> = node
            .children
            .iter()
            .find_map(|&cid| {
                let child = cpg.ast.get(&cid)?;
                if matches!(child.node_type.as_str(), "argument_list" | "arguments") {
                    Some(child.children.iter().copied().collect::<Vec<_>>())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| node.children.iter().copied().collect());

        for &arg_id in &arg_ids {
            arg_to_calls.entry(arg_id).or_default().push(node_id);
        }
        call_args.insert(node_id, arg_ids);
    }

    (call_args, arg_to_calls)
}

// ── Interprocedural expansion ─────────────────────────────────────────────────

/// Given a call node, expand it using function summaries to determine if
/// taint flows through the callee.
pub fn expand_call_with_summary(
    call_node: &IrNode,
    tainted_args: &HashSet<usize>, // which argument indices are tainted
    summaries: &HashMap<String, FunctionSummary>,
) -> TaintExpansionResult {
    // For call nodes, the callee name is stored in `name` or can be derived from `text`
    let callee_name = call_node.name.as_deref().unwrap_or_default();
    if callee_name.is_empty() {
        return TaintExpansionResult::Unknown;
    }

    if let Some(summary) = summaries.get(callee_name) {
        use web_sitter::ParamEffect;
        let mut return_tainted = false;
        let mut is_sink = false;

        for effect in &summary.param_effects {
            let idx = effect.index();
            if tainted_args.contains(&idx) {
                match effect {
                    ParamEffect::Sink(_) => is_sink = true,
                    ParamEffect::TaintReturn(_) | ParamEffect::TaintOut(_) => {
                        return_tainted = true;
                    }
                    ParamEffect::Frees(_) => {}
                }
            }
        }

        TaintExpansionResult::Known { return_tainted, is_sink }
    } else {
        TaintExpansionResult::Unknown
    }
}

#[derive(Debug, Clone)]
pub enum TaintExpansionResult {
    /// Callee has no summary — treat conservatively (taint passes through).
    Unknown,
    Known {
        return_tainted: bool,
        is_sink: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use web_sitter::{FunctionSummary, ParamEffect};

    fn call_node(name: &str, children: Vec<NodeId>) -> IrNode {
        IrNode {
            kind: IrNodeKind::Call,
            node_type: "call_expression".to_owned(),
            name: Some(name.to_owned()),
            children,
            ..IrNode::default()
        }
    }

    fn args_container_node(children: Vec<NodeId>) -> IrNode {
        IrNode {
            kind: IrNodeKind::Unknown,
            node_type: "argument_list".to_owned(),
            children,
            ..IrNode::default()
        }
    }

    fn cpg_from(nodes: Vec<(NodeId, IrNode)>) -> Cpg {
        Cpg {
            ast: nodes.into_iter().collect(),
            language: "c".to_owned(),
            ..Cpg::default()
        }
    }

    // ── index_call_arguments ────────────────────────────────────────────────

    #[test]
    fn index_call_arguments_uses_direct_children_when_no_wrapper() {
        // call(1) with direct children [10, 11] (no argument_list wrapper).
        let cpg = cpg_from(vec![
            (1, call_node("f", vec![10, 11])),
            (10, IrNode { kind: IrNodeKind::Identifier, ..IrNode::default() }),
            (11, IrNode { kind: IrNodeKind::Identifier, ..IrNode::default() }),
        ]);
        let (call_args, arg_to_calls) = index_call_arguments(&cpg);

        assert_eq!(call_args.get(&1), Some(&vec![10, 11]));
        assert_eq!(arg_to_calls.get(&10), Some(&vec![1]));
        assert_eq!(arg_to_calls.get(&11), Some(&vec![1]));
    }

    #[test]
    fn index_call_arguments_descends_into_argument_list_wrapper() {
        // call(1) → argument_list(2) → [10, 11]
        let cpg = cpg_from(vec![
            (1, call_node("f", vec![2])),
            (2, args_container_node(vec![10, 11])),
            (10, IrNode { kind: IrNodeKind::Identifier, ..IrNode::default() }),
            (11, IrNode { kind: IrNodeKind::Identifier, ..IrNode::default() }),
        ]);
        let (call_args, arg_to_calls) = index_call_arguments(&cpg);

        assert_eq!(call_args.get(&1), Some(&vec![10, 11]));
        assert_eq!(arg_to_calls.get(&10), Some(&vec![1]));
        assert_eq!(arg_to_calls.get(&11), Some(&vec![1]));
        // The wrapper node itself is not registered as an argument.
        assert!(call_args.get(&2).is_none());
    }

    #[test]
    fn index_call_arguments_links_nested_call_as_argument() {
        // outer(2) → [inner(1)]   i.e. `outer(inner(x))`
        let cpg = cpg_from(vec![
            (1, call_node("inner", vec![10])),
            (2, call_node("outer", vec![1])),
            (10, IrNode { kind: IrNodeKind::Identifier, ..IrNode::default() }),
        ]);
        let (_call_args, arg_to_calls) = index_call_arguments(&cpg);

        // The inner call node id (1) is itself an argument of the outer call (2).
        assert_eq!(arg_to_calls.get(&1), Some(&vec![2]));
    }

    #[test]
    fn index_call_arguments_ignores_non_call_nodes() {
        let cpg = cpg_from(vec![
            (1, IrNode { kind: IrNodeKind::MethodDef, ..IrNode::default() }),
        ]);
        let (call_args, arg_to_calls) = index_call_arguments(&cpg);
        assert!(call_args.is_empty());
        assert!(arg_to_calls.is_empty());
    }

    // ── expand_interprocedural (worklist) ───────────────────────────────────

    fn summary_with_taint_return(name: &str, arg_idx: usize) -> FunctionSummary {
        let mut param_effects = BTreeSet::new();
        param_effects.insert(ParamEffect::TaintReturn(arg_idx));
        FunctionSummary {
            name: name.to_owned(),
            param_effects,
            ..FunctionSummary::default()
        }
    }

    /// Two-hop chained interprocedural expansion: `wrap2(wrap1(source))`, where
    /// neither call has a direct DFG forward edge — taint must flow purely through
    /// the call-argument worklist (`expand_interprocedural`'s `next_frontier`
    /// re-triggering for a call node that is itself a literal argument of another
    /// call). This is the scenario the worklist refactor must not regress: without
    /// re-checking `arg_to_calls` for the just-tainted call id itself (not only for
    /// nodes touched by the subsequent DFG propagation), the second hop would never
    /// be discovered, since the inner call has no DFG successors of its own.
    #[test]
    fn expand_interprocedural_propagates_through_chained_nested_calls() {
        const SOURCE: NodeId = 2;
        const WRAP1: NodeId = 3; // wrap1(source)
        const WRAP2: NodeId = 4; // wrap2(wrap1(source))

        let cpg = cpg_from(vec![
            (SOURCE, call_node("get_input", vec![])),
            (WRAP1, call_node("wrap1", vec![SOURCE])),
            (WRAP2, call_node("wrap2", vec![WRAP1])),
        ]);

        let dfg = DfgIndex::build(&cpg);
        let mut summaries = HashMap::new();
        summaries.insert("wrap1".to_owned(), summary_with_taint_return("wrap1", 0));
        summaries.insert("wrap2".to_owned(), summary_with_taint_return("wrap2", 0));

        let registry = EndpointRegistry::new();
        let engine = TaintEngine::new(&registry, &dfg, &cpg, &summaries);

        let mut result = dfg.propagate_taint(&[SOURCE], &TaintConfig {
            sanitizer_nodes: &HashSet::new(),
            propagator_edges: &[],
            max_depth: 20,
        });
        assert_eq!(result.tainted, HashSet::from([SOURCE]), "sanity: no DFG edges yet");

        let sanitizer_nodes = HashSet::new();
        let taint_cfg = TaintConfig {
            sanitizer_nodes: &sanitizer_nodes,
            propagator_edges: &[],
            max_depth: 20,
        };
        engine.expand_interprocedural(&mut result, &sanitizer_nodes, &taint_cfg);

        assert!(result.tainted.contains(&WRAP1), "first hop (wrap1) should become tainted");
        assert!(
            result.tainted.contains(&WRAP2),
            "second hop (wrap2) should become tainted via the nested-call worklist, \
             even though wrap1 has no DFG forward edges of its own"
        );
    }

    #[test]
    fn expand_interprocedural_stops_at_sanitizer() {
        const SOURCE: NodeId = 2;
        const WRAP1: NodeId = 3;

        let cpg = cpg_from(vec![
            (SOURCE, call_node("get_input", vec![])),
            (WRAP1, call_node("wrap1", vec![SOURCE])),
        ]);

        let dfg = DfgIndex::build(&cpg);
        let mut summaries = HashMap::new();
        summaries.insert("wrap1".to_owned(), summary_with_taint_return("wrap1", 0));

        let registry = EndpointRegistry::new();
        let engine = TaintEngine::new(&registry, &dfg, &cpg, &summaries);

        let mut result = crate::dfg::TaintResult {
            tainted: HashSet::from([SOURCE]),
            sanitized_at: vec![],
        };

        let sanitizer_nodes: HashSet<NodeId> = HashSet::from([WRAP1]);
        let taint_cfg = TaintConfig {
            sanitizer_nodes: &sanitizer_nodes,
            propagator_edges: &[],
            max_depth: 20,
        };
        engine.expand_interprocedural(&mut result, &sanitizer_nodes, &taint_cfg);

        assert!(
            !result.tainted.contains(&WRAP1),
            "a call node marked as a sanitizer must not be flagged tainted by the worklist"
        );
    }
}
