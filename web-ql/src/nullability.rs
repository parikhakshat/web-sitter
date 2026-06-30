use std::collections::{HashMap, HashSet, VecDeque};
use web_sitter::{Cpg, IrNodeKind, LiteralKind, NodeId};

/// Functions whose return value may be null (NULL / nullptr / None / nil).
///
/// Extend this list to cover platform-specific or project-specific APIs.
const NULLABLE_FUNCTIONS: &[&str] = &[
    // ── Standard C heap ──────────────────────────────────────────────────────
    "malloc", "calloc", "realloc", "reallocarray", "aligned_alloc",
    "valloc", "memalign", "posix_memalign",
    // ── String helpers ───────────────────────────────────────────────────────
    "strdup", "strndup", "wcsdup",
    // ── String search (returns NULL on no-match) ─────────────────────────────
    "strstr", "strchr", "strrchr", "memchr", "memmem",
    // ── File / IO ────────────────────────────────────────────────────────────
    "fopen", "fdopen", "freopen", "popen", "tmpfile",
    // ── POSIX / system ───────────────────────────────────────────────────────
    "opendir", "getenv", "getenv_s", "getcwd", "realpath", "inet_ntoa",
    "dlopen", "dlsym", "mmap", "shmat",
    // ── Search / scan ────────────────────────────────────────────────────────
    "bsearch", "lfind", "lsearch",
    // ── GLib ─────────────────────────────────────────────────────────────────
    "g_malloc", "g_try_malloc", "g_try_malloc0", "g_realloc",
    "g_strdup", "g_strndup",
    // ── Linux kernel ─────────────────────────────────────────────────────────
    "kmalloc", "kzalloc", "vmalloc", "kvmalloc",
    // ── Windows ──────────────────────────────────────────────────────────────
    "HeapAlloc", "GlobalAlloc", "LocalAlloc", "VirtualAlloc", "VirtualAllocEx",
    "CreateFile", "CreateFileA", "CreateFileW",
    // ── C++ ──────────────────────────────────────────────────────────────────
    "std::make_unique", "std::make_shared",
];

/// Nullability index: tracks which CPG nodes may carry a null/None/nil value,
/// propagating forward through dataflow edges from known null sources.
///
/// Two classes of null sources:
/// 1. **Literal null nodes** — `NULL`, `nullptr`, `null`, `nil`, `None`, `undefined`.
/// 2. **Nullable function calls** — return value may be null (malloc, fopen, …).
///
/// Nullability is then propagated forward through `REACHING_DEF`, `CALL_RETURN`,
/// and `INTERPROCEDURAL_FLOW` edges so that variables assigned from these sources
/// are also flagged.
pub struct NullabilityIndex {
    /// All nodes that may hold a null value (seeds + forward-propagated).
    pub may_be_null: HashSet<NodeId>,
    /// For each nullable node: the original seed node that caused it to be nullable.
    pub null_origin: HashMap<NodeId, NodeId>,
}

impl NullabilityIndex {
    pub fn build(cpg: &Cpg) -> Self {
        let mut seeds: Vec<NodeId> = Vec::new();

        for (node_id, node) in &cpg.ast {
            // 1. Null literal nodes
            if node.kind == IrNodeKind::Literal {
                let is_null = matches!(node.lit_kind, Some(LiteralKind::Null))
                    || node.text.as_deref().map_or(false, |t| {
                        matches!(t, "NULL" | "nullptr" | "null" | "nil" | "None" | "undefined")
                    });
                if is_null {
                    seeds.push(*node_id);
                    continue;
                }
            }

            // 2. Nullable function call sites
            if node.kind == IrNodeKind::Call {
                if let Some(callee) = callee_name(cpg, *node_id) {
                    if is_nullable_callee(&callee) {
                        seeds.push(*node_id);
                    }
                }
            }
        }

        // Forward BFS through REACHING_DEF / CALL_RETURN / INTERPROCEDURAL_FLOW
        let fwd = build_forward_edges(cpg);

        let mut may_be_null: HashSet<NodeId> = HashSet::with_capacity(seeds.len() * 2);
        let mut null_origin: HashMap<NodeId, NodeId> = HashMap::new();
        let mut queue: VecDeque<NodeId> = VecDeque::new();

        for &seed in &seeds {
            if may_be_null.insert(seed) {
                null_origin.insert(seed, seed);
                queue.push_back(seed);
            }
        }

        while let Some(cur) = queue.pop_front() {
            let origin = null_origin.get(&cur).copied().unwrap_or(cur);
            for &next in fwd.get(&cur).into_iter().flatten() {
                if may_be_null.insert(next) {
                    null_origin.insert(next, origin);
                    queue.push_back(next);
                }
            }
        }

        Self { may_be_null, null_origin }
    }

    /// True if `node_id` may carry a null value.
    pub fn may_be_null(&self, node_id: NodeId) -> bool {
        self.may_be_null.contains(&node_id)
    }

    /// The original null-producing node (seed) that caused `node_id` to be nullable,
    /// or `None` if `node_id` is not nullable.
    pub fn null_origin_of(&self, node_id: NodeId) -> Option<NodeId> {
        self.null_origin.get(&node_id).copied()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn is_nullable_callee(callee: &str) -> bool {
    NULLABLE_FUNCTIONS.iter().any(|&f| {
        callee == f || callee.ends_with(&format!("::{f}")) || callee.ends_with(&format!(".{f}"))
    })
}

fn callee_name(cpg: &Cpg, call_id: NodeId) -> Option<String> {
    for entry in cpg.call_graph.values() {
        for cs in &entry.calls {
            if cs.call_site == Some(call_id) {
                return Some(cs.callee.clone());
            }
        }
    }
    // Fallback: first identifier child of the call node
    cpg.ast.get(&call_id)?.children.iter().find_map(|&cid| {
        let c = cpg.ast.get(&cid)?;
        if c.kind == IrNodeKind::Identifier {
            c.text.clone()
        } else {
            None
        }
    })
}

fn build_forward_edges(cpg: &Cpg) -> HashMap<NodeId, Vec<NodeId>> {
    let mut fwd: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
    for edge in &cpg.dataflow.edges {
        if matches!(
            edge.edge_type.as_str(),
            "REACHING_DEF" | "CALL_RETURN" | "INTERPROCEDURAL_FLOW"
        ) {
            fwd.entry(edge.source).or_default().push(edge.destination);
        }
    }
    fwd
}
