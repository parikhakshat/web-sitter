use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::RwLock;
use web_profiler as prof;
use web_sitter::{Cpg, IrNodeKind, NodeId};

// ── DFG index ─────────────────────────────────────────────────────────────────

/// A compact forward+backward DFG index built from the CPG's dataflow edges.
pub struct DfgIndex {
    /// Forward edges: from → set of tos
    pub forward: HashMap<NodeId, Vec<NodeId>>,
    /// Backward edges: to → set of froms
    pub backward: HashMap<NodeId, Vec<NodeId>>,
    /// Variable-named edges: variable_name → vec of (source, dest)
    pub var_edges: HashMap<String, Vec<(NodeId, NodeId)>>,
    /// Memoized forward-reachability sets (computed on demand, reused across queries).
    /// Keyed by source NodeId → set of all nodes reachable from it.
    reach_cache: RwLock<HashMap<NodeId, HashSet<NodeId>>>,
}

impl Clone for DfgIndex {
    fn clone(&self) -> Self {
        Self {
            forward: self.forward.clone(),
            backward: self.backward.clone(),
            var_edges: self.var_edges.clone(),
            reach_cache: RwLock::new(HashMap::new()),
        }
    }
}

impl DfgIndex {
    /// Build a DfgIndex from the dataflow graph embedded in a CPG.
    pub fn build(cpg: &Cpg) -> Self {
        let mut forward: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
        let mut backward: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
        let mut var_edges: HashMap<String, Vec<(NodeId, NodeId)>> = HashMap::new();

        for edge in &cpg.dataflow.edges {
            forward.entry(edge.source).or_default().push(edge.destination);
            backward.entry(edge.destination).or_default().push(edge.source);
            var_edges
                .entry(edge.variable.clone())
                .or_default()
                .push((edge.source, edge.destination));
        }

        Self { forward, backward, var_edges, reach_cache: RwLock::new(HashMap::new()) }
    }

    /// True if `node` is a definition site for `var_name` (it is a source of a DFG edge for that variable).
    pub fn defines_var(&self, node: NodeId, var_name: &str) -> bool {
        self.var_edges
            .get(var_name)
            .map_or(false, |edges| edges.iter().any(|(src, _)| *src == node))
    }

    /// True if `node` is a use site for `var_name` (it is a destination of a DFG edge for that variable).
    pub fn uses_var(&self, node: NodeId, var_name: &str) -> bool {
        self.var_edges
            .get(var_name)
            .map_or(false, |edges| edges.iter().any(|(_, dst)| *dst == node))
    }

    /// True if there is a direct dataflow edge from `a` to `b`.
    pub fn direct_flow(&self, from: NodeId, to: NodeId) -> bool {
        self.forward.get(&from).map_or(false, |v| v.contains(&to))
    }

    /// BFS forward reachability: returns all nodes reachable from `source`
    /// (including `source` itself). Results are memoized in `reach_cache`.
    pub fn reachable_from(&self, source: NodeId) -> HashSet<NodeId> {
        // Fast path: already cached
        if let Ok(cache) = self.reach_cache.read() {
            if let Some(set) = cache.get(&source) {
                prof::cache_hit("dfg.reach_cache");
                return set.clone();
            }
        }
        prof::cache_miss("dfg.reach_cache");

        // Compute via BFS
        let _span = prof::span("dfg.reachable_from_bfs");
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(source);
        visited.insert(source);
        while let Some(node) = queue.pop_front() {
            if let Some(succs) = self.forward.get(&node) {
                for &s in succs {
                    if visited.insert(s) {
                        queue.push_back(s);
                    }
                }
            }
        }
        prof::count("dfg.reachable_from_bfs.nodes_visited", visited.len() as u64);

        // Store in cache (best-effort; ignore poison)
        if let Ok(mut cache) = self.reach_cache.write() {
            // Rough per-entry footprint: one NodeId (u32) per visited node, plus
            // the HashSet's own bucket overhead — good enough for cache accounting,
            // not meant to be exact.
            prof::cache_insert("dfg.reach_cache", (visited.len() * std::mem::size_of::<NodeId>()) as u64);
            cache.insert(source, visited.clone());
        }
        visited
    }

    /// BFS backward reachability: returns all nodes that can reach `sink`.
    pub fn reaches_to(&self, sink: NodeId) -> HashSet<NodeId> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(sink);
        visited.insert(sink);

        while let Some(node) = queue.pop_front() {
            if let Some(preds) = self.backward.get(&node) {
                for &p in preds {
                    if visited.insert(p) {
                        queue.push_back(p);
                    }
                }
            }
        }
        visited
    }

    /// True if `from` can reach `to` via the dataflow graph.
    /// Uses cached forward reachability for amortized O(1) repeated queries from the same source.
    pub fn reaches(&self, from: NodeId, to: NodeId) -> bool {
        if from == to {
            return true;
        }
        self.reachable_from(from).contains(&to)
    }

    /// True if `from` can reach `to` without passing through any node whose
    /// kind is in `barrier_kinds`.
    pub fn reaches_with_barrier(
        &self,
        from: NodeId,
        to: NodeId,
        barrier_kinds: &[IrNodeKind],
        cpg: &Cpg,
    ) -> bool {
        if from == to {
            return true;
        }
        let _span = prof::span("dfg.reaches_with_barrier_bfs");

        let is_barrier = |node: NodeId| -> bool {
            cpg.ast
                .get(&node)
                .map_or(false, |n| barrier_kinds.contains(&n.kind))
        };

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(from);
        visited.insert(from);

        while let Some(node) = queue.pop_front() {
            if node == to {
                return true;
            }
            if let Some(succs) = self.forward.get(&node) {
                for &s in succs {
                    if !visited.contains(&s) && !is_barrier(s) {
                        visited.insert(s);
                        queue.push_back(s);
                    }
                }
            }
        }
        false
    }

    /// Returns all direct successors of `node` in the DFG.
    pub fn successors(&self, node: NodeId) -> &[NodeId] {
        self.forward.get(&node).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Returns all direct predecessors of `node` in the DFG.
    pub fn predecessors(&self, node: NodeId) -> &[NodeId] {
        self.backward.get(&node).map(Vec::as_slice).unwrap_or(&[])
    }
}

// ── Taint-aware DFG traversal ─────────────────────────────────────────────────

/// Result of a single-source taint propagation sweep.
pub struct TaintResult {
    /// All nodes that are tainted from the given source.
    pub tainted: HashSet<NodeId>,
    /// Paths that were cut by sanitizers (source → blocked node).
    pub sanitized_at: Vec<(NodeId, NodeId)>,
}

/// Configuration for a taint propagation run.
pub struct TaintConfig<'a> {
    pub sanitizer_nodes: &'a HashSet<NodeId>,
    pub propagator_edges: &'a [(NodeId, NodeId)], // extra edges from propagators
    pub max_depth: u32,
}

impl DfgIndex {
    /// BFS taint propagation from a set of source nodes, respecting sanitizers.
    /// Returns the set of all tainted nodes.
    pub fn propagate_taint(&self, sources: &[NodeId], cfg: &TaintConfig<'_>) -> TaintResult {
        let _span = prof::span("dfg.propagate_taint_bfs");
        let mut tainted = HashSet::new();
        let mut sanitized_at = Vec::new();
        let mut queue: VecDeque<(NodeId, u32)> = VecDeque::new();

        for &src in sources {
            if tainted.insert(src) {
                queue.push_back((src, 0));
            }
        }

        while let Some((node, depth)) = queue.pop_front() {
            if depth >= cfg.max_depth {
                continue;
            }

            // Follow standard DFG edges
            if let Some(succs) = self.forward.get(&node) {
                for &s in succs {
                    if cfg.sanitizer_nodes.contains(&s) {
                        sanitized_at.push((node, s));
                        continue;
                    }
                    if tainted.insert(s) {
                        queue.push_back((s, depth + 1));
                    }
                }
            }

            // Follow extra propagator edges
            for &(from, to) in cfg.propagator_edges {
                if from == node {
                    if cfg.sanitizer_nodes.contains(&to) {
                        sanitized_at.push((node, to));
                        continue;
                    }
                    if tainted.insert(to) {
                        queue.push_back((to, depth + 1));
                    }
                }
            }
        }

        prof::count("dfg.propagate_taint_bfs.nodes_tainted", tainted.len() as u64);
        TaintResult { tainted, sanitized_at }
    }
}
