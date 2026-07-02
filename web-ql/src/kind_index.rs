//! Per-file structural index over a `Cpg`: node-kind / raw-node-type buckets and a
//! call-site lookup keyed by call-expression NodeId.
//!
//! Built once per file (in `FileIndex::build`) and reused across every rule and every
//! root-binding/Exists/Forall evaluation against that file, replacing what used to be a
//! fresh `O(|cpg.ast|)` scan (or `O(|call_graph|)` scan for call-site lookups) on every
//! single binding/predicate evaluation.

use std::collections::HashMap;
use web_sitter::{CallSite, Cpg, IrNodeKind, NodeId};

pub struct KindIndex {
    by_kind: HashMap<IrNodeKind, Vec<NodeId>>,
    /// Keyed by the exact (non-lowercased) `node_type` string as stored on the IrNode.
    by_node_type: HashMap<String, Vec<NodeId>>,
    /// call-expression NodeId → its `CallSite` record from `cpg.call_graph`.
    call_site_by_node: HashMap<NodeId, CallSite>,
}

impl KindIndex {
    pub fn build(cpg: &Cpg) -> Self {
        let mut by_kind: HashMap<IrNodeKind, Vec<NodeId>> = HashMap::new();
        let mut by_node_type: HashMap<String, Vec<NodeId>> = HashMap::new();
        for (&id, node) in &cpg.ast {
            by_kind.entry(node.kind).or_default().push(id);
            by_node_type
                .entry(node.node_type.clone())
                .or_default()
                .push(id);
        }

        let mut call_site_by_node: HashMap<NodeId, CallSite> = HashMap::new();
        for entry in cpg.call_graph.values() {
            for cs in &entry.calls {
                if let Some(call_id) = cs.call_site {
                    call_site_by_node.insert(call_id, cs.clone());
                }
            }
        }

        Self {
            by_kind,
            by_node_type,
            call_site_by_node,
        }
    }

    /// All node ids matching any of `kinds`. Empty `kinds` returns every node, matching
    /// the historical "no kind filter" behavior of root bindings / Exists / Forall.
    pub fn nodes_of_kinds(&self, kinds: &[IrNodeKind]) -> Vec<NodeId> {
        if kinds.is_empty() {
            return self.by_kind.values().flatten().copied().collect();
        }
        let mut out = Vec::new();
        for k in kinds {
            if let Some(v) = self.by_kind.get(k) {
                out.extend_from_slice(v);
            }
        }
        out
    }

    /// Node ids whose raw tree-sitter `node_type` matches `raw`, case-insensitively
    /// (matches both the literal string and its lowercased form, deduplicated).
    pub fn nodes_of_raw_type(&self, raw: &str) -> Vec<NodeId> {
        let raw_lc = raw.to_lowercase();
        if raw_lc == raw {
            return self.by_node_type.get(raw).cloned().unwrap_or_default();
        }
        let mut out = self
            .by_node_type
            .get(raw_lc.as_str())
            .cloned()
            .unwrap_or_default();
        if let Some(extra) = self.by_node_type.get(raw) {
            for id in extra {
                if !out.contains(id) {
                    out.push(*id);
                }
            }
        }
        out
    }

    /// The `CallSite` record for a call-expression node, or `None` if it isn't a
    /// recognized call site in the call graph.
    pub fn call_site_for_node(&self, call_node_id: NodeId) -> Option<&CallSite> {
        self.call_site_by_node.get(&call_node_id)
    }
}
