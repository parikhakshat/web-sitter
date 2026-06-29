use std::collections::{HashMap, HashSet};
use std::collections::VecDeque;
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
}

impl EndpointRegistry {
    pub fn new() -> Self {
        Self { extractors: HashMap::new() }
    }

    pub fn register(
        &mut self,
        name: impl Into<String>,
        f: impl Fn(&Cpg) -> Vec<NodeId> + Send + Sync + 'static,
    ) {
        self.extractors.insert(name.into(), Box::new(f));
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

// ── Taint engine ──────────────────────────────────────────────────────────────

pub struct TaintEngine<'a> {
    pub registry: &'a EndpointRegistry,
    pub dfg: &'a DfgIndex,
    pub cpg: &'a Cpg,
    /// Function summaries for interprocedural expansion.
    pub summaries: &'a HashMap<String, FunctionSummary>,
}

impl<'a> TaintEngine<'a> {
    pub fn new(
        registry: &'a EndpointRegistry,
        dfg: &'a DfgIndex,
        cpg: &'a Cpg,
        summaries: &'a HashMap<String, FunctionSummary>,
    ) -> Self {
        Self { registry, dfg, cpg, summaries }
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
            let mut changed = true;
            while changed {
                changed = false;
                let mut new_tainted: Vec<NodeId> = Vec::new();

                for (node_id, node) in &self.cpg.ast {
                    if node.kind != web_sitter::IrNodeKind::Call {
                        continue;
                    }
                    if sanitizer_nodes.contains(node_id) {
                        continue;
                    }
                    // Check which argument positions are tainted
                    let tainted_args: HashSet<usize> = node
                        .children
                        .iter()
                        .enumerate()
                        .filter(|(_, arg_id)| result.tainted.contains(*arg_id))
                        .map(|(i, _)| i)
                        .collect();

                    if tainted_args.is_empty() {
                        continue;
                    }

                    let expansion = expand_call_with_summary(node, &tainted_args, self.summaries);
                    match expansion {
                        TaintExpansionResult::Known { return_tainted: true, .. } => {
                            if result.tainted.insert(*node_id) {
                                new_tainted.push(*node_id);
                                changed = true;
                            }
                        }
                        _ => {}
                    }
                }

                if !new_tainted.is_empty() {
                    // Re-propagate from newly tainted call nodes
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
                        || result.tainted.contains(&src.node)
                    {
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
        // Propagators are source/sink pairs within a single call node.
        // They're modelled by finding call nodes that match the propagator definition
        // and then adding an edge from the "from" argument to the "to" argument.
        let mut edges = Vec::new();
        for prop in propagators {
            if let Some(nodes) = self.find_propagator_nodes(&prop.name) {
                edges.extend(nodes);
            }
        }
        edges
    }

    fn find_propagator_nodes(&self, _name: &str) -> Option<Vec<(NodeId, NodeId)>> {
        // Placeholder: in a full implementation, look up the PropagatorDef in the
        // registry and pattern-match call nodes against it, then build from→to pairs.
        None
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
