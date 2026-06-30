use std::collections::HashMap;
use web_sitter::{Cpg, IrNodeKind, NodeId};
use web_sitter::security_patterns::HEAP_ALLOCATORS;

/// The known or inferred allocation size of a node.
#[derive(Clone, Debug, PartialEq)]
pub enum SizeValue {
    /// Statically-known concrete byte count.
    Concrete(i64),
    /// Size is determined by an expression we couldn't fold (the expression text is stored).
    Symbolic(String),
    /// Size is unknown.
    Unknown,
}

/// Buffer / allocation size index built from the CPG.
///
/// Sources of size information (in priority order):
/// 1. `IrNode.array_size` / `array_size_expr` — static array declarators
/// 2. `IrNode.string_length` — string literal byte counts (+ NUL terminator)
/// 3. Heap allocator call arguments — using the `HEAP_ALLOCATORS` table
/// 4. Backward SIZE_FLOW edges — `size_var → array_var` emitted by dfg.rs
pub struct AllocSizeIndex {
    /// node_id → inferred size value
    pub sizes: HashMap<NodeId, SizeValue>,
    /// SIZE_FLOW backward map: destination node → source size-expression nodes
    pub size_sources: HashMap<NodeId, Vec<NodeId>>,
}

impl AllocSizeIndex {
    pub fn build(cpg: &Cpg) -> Self {
        let mut sizes: HashMap<NodeId, SizeValue> = HashMap::new();
        let mut size_sources: HashMap<NodeId, Vec<NodeId>> = HashMap::new();

        // Index SIZE_FLOW edges: source is the size expression, dest is the sized variable.
        for edge in &cpg.dataflow.edges {
            if edge.edge_type == "SIZE_FLOW" {
                size_sources
                    .entry(edge.destination)
                    .or_default()
                    .push(edge.source);
            }
        }

        for (node_id, node) in &cpg.ast {
            // 1. Static array size from IrNode fields
            if let Some(sz) = node.array_size {
                sizes.insert(*node_id, SizeValue::Concrete(sz));
                continue;
            }
            if let Some(ref expr) = node.array_size_expr {
                let stripped = expr.trim();
                sizes.insert(
                    *node_id,
                    stripped
                        .parse::<i64>()
                        .map(SizeValue::Concrete)
                        .unwrap_or_else(|_| SizeValue::Symbolic(stripped.to_owned())),
                );
                continue;
            }

            // 2. String literals — include the NUL terminator byte
            if node.kind == IrNodeKind::Literal {
                if let Some(len) = node.string_length {
                    sizes.insert(*node_id, SizeValue::Concrete(len as i64 + 1));
                }
                continue;
            }

            // 3. Heap allocator calls
            if node.kind == IrNodeKind::Call {
                if let Some(sv) = infer_heap_alloc_size(cpg, *node_id, node) {
                    sizes.insert(*node_id, sv);
                }
            }
        }

        Self { sizes, size_sources }
    }

    /// Size value for `node_id`.  Falls back to checking SIZE_FLOW backward sources.
    pub fn size_of(&self, node_id: NodeId) -> SizeValue {
        if let Some(sv) = self.sizes.get(&node_id) {
            return sv.clone();
        }
        // Check SIZE_FLOW backward: find a concrete-size source expression
        for &src in self.size_sources.get(&node_id).into_iter().flatten() {
            if let Some(sv) = self.sizes.get(&src) {
                return sv.clone();
            }
        }
        SizeValue::Unknown
    }

    /// Returns `Some(n)` only when a concrete byte count is known.
    pub fn concrete_size(&self, node_id: NodeId) -> Option<i64> {
        match self.size_of(node_id) {
            SizeValue::Concrete(n) => Some(n),
            _ => None,
        }
    }

    /// All SIZE_FLOW source nodes for `node_id` (the expression nodes that bound it).
    pub fn size_source_nodes(&self, node_id: NodeId) -> &[NodeId] {
        self.size_sources
            .get(&node_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn callee_name_for_call(cpg: &Cpg, call_id: NodeId) -> Option<String> {
    for entry in cpg.call_graph.values() {
        for cs in &entry.calls {
            if cs.call_site == Some(call_id) {
                return Some(cs.callee.clone());
            }
        }
    }
    // Fallback: first identifier child text
    cpg.ast
        .get(&call_id)?
        .children
        .iter()
        .find_map(|&cid| {
            let c = cpg.ast.get(&cid)?;
            if c.kind == web_sitter::IrNodeKind::Identifier {
                c.text.clone()
            } else {
                None
            }
        })
}

fn arg_text(cpg: &Cpg, call_node: &web_sitter::AstNode, idx: usize) -> Option<String> {
    let arg_list = call_node.children.iter().find_map(|&cid| {
        let c = cpg.ast.get(&cid)?;
        if matches!(c.node_type.as_str(), "argument_list" | "arguments") {
            Some(c)
        } else {
            None
        }
    })?;
    let arg_id = *arg_list.children.get(idx)?;
    cpg.ast.get(&arg_id)?.text.clone()
}

fn infer_heap_alloc_size(
    cpg: &Cpg,
    call_id: NodeId,
    node: &web_sitter::AstNode,
) -> Option<SizeValue> {
    let callee = callee_name_for_call(cpg, call_id)?;

    for &(name, ref spec) in HEAP_ALLOCATORS {
        if callee != name && !callee.ends_with(&format!("::{name}")) {
            continue;
        }
        if spec.size_arg < 0 {
            // e.g. strdup — size derived from the string length at runtime
            return Some(SizeValue::Unknown);
        }
        let size_idx = spec.size_arg as usize;

        // calloc(count, elem_size): total = count × elem_size
        if name == "calloc" || name == "xcalloc" || name == "g_new" || name == "g_new0" {
            let count_text = arg_text(cpg, node, 0);
            let elem_text = arg_text(cpg, node, 1);
            return Some(match (
                count_text.as_deref().and_then(|s| s.trim().parse::<i64>().ok()),
                elem_text.as_deref().and_then(|s| s.trim().parse::<i64>().ok()),
            ) {
                (Some(c), Some(e)) => SizeValue::Concrete(c.saturating_mul(e)),
                _ => SizeValue::Symbolic(format!(
                    "{}*{}",
                    count_text.unwrap_or_default(),
                    elem_text.unwrap_or_default()
                )),
            });
        }

        let size_text = arg_text(cpg, node, size_idx)?;
        return Some(
            size_text
                .trim()
                .parse::<i64>()
                .map(SizeValue::Concrete)
                .unwrap_or_else(|_| SizeValue::Symbolic(size_text)),
        );
    }
    None
}
