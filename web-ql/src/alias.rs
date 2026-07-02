use std::collections::{HashMap, HashSet};
use web_sitter::{Cpg, NodeId};

/// Points-to / may-alias index built from POINTS_TO edges in the CPG dataflow graph.
///
/// A POINTS_TO edge `(src → dst, var = "p")` encodes that variable `p` at node `src`
/// may point to (alias) the object at node `dst`.
///
/// This is a field-insensitive, flow-insensitive may-alias analysis over the
/// existing POINTS_TO edges emitted by `add_points_to_edges` in dfg.rs (currently
/// C/C++ address-of assignments: `ptr = &x`).
pub struct AliasIndex {
    /// Forward: pointer node → set of pointee nodes it may point to.
    pub points_to: HashMap<NodeId, HashSet<NodeId>>,
    /// Backward: pointee node → set of pointer nodes that may point to it.
    pub pointed_by: HashMap<NodeId, HashSet<NodeId>>,
    /// Variable name → pointer nodes for that variable (for name-based lookup).
    pub var_to_ptrs: HashMap<String, Vec<NodeId>>,
}

impl AliasIndex {
    pub fn build(cpg: &Cpg) -> Self {
        let mut points_to: HashMap<NodeId, HashSet<NodeId>> = HashMap::new();
        let mut pointed_by: HashMap<NodeId, HashSet<NodeId>> = HashMap::new();
        let mut var_to_ptrs: HashMap<String, Vec<NodeId>> = HashMap::new();

        for edge in &cpg.dataflow.edges {
            if edge.edge_type == "POINTS_TO" {
                points_to
                    .entry(edge.source)
                    .or_default()
                    .insert(edge.destination);
                pointed_by
                    .entry(edge.destination)
                    .or_default()
                    .insert(edge.source);
                var_to_ptrs
                    .entry(edge.variable.clone())
                    .or_default()
                    .push(edge.source);
            }
        }

        Self {
            points_to,
            pointed_by,
            var_to_ptrs,
        }
    }

    /// All nodes that `ptr_node` may point to (empty slice if none).
    pub fn points_to_set(&self, ptr_node: NodeId) -> Option<&HashSet<NodeId>> {
        self.points_to.get(&ptr_node)
    }

    /// True if `a` and `b` may alias (share ≥1 common pointee, or are the same node).
    pub fn may_alias(&self, a: NodeId, b: NodeId) -> bool {
        if a == b {
            return true;
        }
        match (self.points_to.get(&a), self.points_to.get(&b)) {
            (Some(sa), Some(sb)) => sa.intersection(sb).next().is_some(),
            _ => false,
        }
    }

    /// All pointer nodes that may point to `pointee`.
    pub fn aliased_pointers(&self, pointee: NodeId) -> Option<&HashSet<NodeId>> {
        self.pointed_by.get(&pointee)
    }

    /// True if `node` appears as the source of any POINTS_TO edge.
    pub fn is_pointer(&self, node: NodeId) -> bool {
        self.points_to.contains_key(&node)
    }

    /// All nodes reachable transitively via POINTS_TO (deep alias set for `ptr_node`).
    /// Bounded by depth to avoid cycles.
    pub fn transitive_targets(&self, ptr_node: NodeId) -> HashSet<NodeId> {
        let mut visited = HashSet::new();
        let mut queue = vec![ptr_node];
        while let Some(cur) = queue.pop() {
            if let Some(targets) = self.points_to.get(&cur) {
                for &t in targets {
                    if visited.insert(t) {
                        queue.push(t);
                    }
                }
            }
        }
        visited
    }
}
