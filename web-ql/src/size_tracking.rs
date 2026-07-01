use std::collections::HashMap;
use web_sitter::{Cpg, IrNodeKind, LiteralKind, NodeId};
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
/// 1. `IrNode.array_size` / `array_size_expr` — static array declarators (C/C++)
/// 2. `IrNode.string_length`, falling back to content-length decoded from
///    `IrNode.text` — string/byte-string literal byte counts (+ NUL terminator
///    for C-family languages), across every language, not just the ones whose
///    raw tree-sitter string-literal kind happens to be exactly `"string_literal"`
/// 3. Collection literals (list/tuple/set/dict, array/slice, composite/struct
///    literals, array initializers) — element count, keyed off the raw node
///    kind since many of these aren't (and shouldn't be) `IrNodeKind::Literal`
/// 4. Heap allocator call arguments — using the `HEAP_ALLOCATORS` table
/// 5. Backward SIZE_FLOW edges — `size_var → array_var` emitted by dfg.rs
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

            // 2. String / byte-string literals. C/C++ strings are NUL-terminated
            // in memory, which matters for buffer-overflow-style size reasoning
            // (matching a `malloc(strlen(s) + 1)` pattern), so that byte is kept
            // in the reported size — but only there; Python/JS/Go/Rust/Java
            // strings have no such runtime terminator, so their reported size
            // is the plain content length.
            if node.kind == IrNodeKind::Literal
                && matches!(node.lit_kind, Some(LiteralKind::String) | Some(LiteralKind::Bytes))
            {
                let len = node
                    .string_length
                    .map(|l| l as i64)
                    .or_else(|| node.text.as_deref().map(literal_content_length));
                if let Some(len) = len {
                    let nul_terminated = matches!(cpg.language.as_str(), "c" | "cpp");
                    sizes.insert(*node_id, SizeValue::Concrete(if nul_terminated { len + 1 } else { len }));
                }
                continue;
            }

            // 3. Collection literals — element count.
            if let Some(n) = collection_element_count(cpg, node) {
                sizes.insert(*node_id, SizeValue::Concrete(n));
                continue;
            }

            // 4. Heap allocator calls
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

/// Approximate the content length of a string/byte-string literal from its
/// raw source text: strip a leading language prefix (`b`, `r`, `f`, `u`, or
/// combinations like `rb`/`br`/`rf`, case-insensitive — Python/Rust byte and
/// raw strings, Python f-strings) and the surrounding quote characters
/// (`"""`/`'''` triple-quoted, or a single `"`/`'`/`` ` ``), then counts the
/// remaining characters. This doesn't unescape `\n`-style escape sequences —
/// good enough for a size *estimate*, consistent with the existing C/C++
/// path (which decodes escapes properly via `decode_string_literal`, a
/// web-sitter-internal helper not exposed to this crate).
fn literal_content_length(text: &str) -> i64 {
    let t = text.trim();
    let prefix_len = t.chars().take_while(|c| c.is_ascii_alphabetic()).count();
    let rest = &t[prefix_len..];
    let rest = rest.strip_prefix('#').unwrap_or(rest); // Rust raw-string hash delimiter, best-effort
    if (rest.starts_with("\"\"\"") && rest.ends_with("\"\"\"") && rest.len() >= 6)
        || (rest.starts_with("'''") && rest.ends_with("'''") && rest.len() >= 6)
    {
        return rest.chars().count() as i64 - 6;
    }
    let mut chars = rest.chars();
    match (chars.next(), chars.next_back()) {
        (Some(a), Some(b)) if a == b && matches!(a, '"' | '\'' | '`') && rest.chars().count() >= 2 => {
            rest.chars().count() as i64 - 2
        }
        _ => rest.chars().count() as i64,
    }
}

/// Element count for a collection literal (list/tuple/set/dict, array/slice,
/// struct/composite literal, array initializer), matched by the raw
/// tree-sitter node kind rather than `IrNodeKind` — most of these aren't (and
/// shouldn't be) classified as `IrNodeKind::Literal`, so this runs
/// independently of the string-literal branch above.
fn collection_element_count(cpg: &Cpg, node: &web_sitter::AstNode) -> Option<i64> {
    match node.node_type.as_str() {
        // Python: list/tuple/set literals, dict literals (each `pair` child is one entry).
        "list" | "tuple" | "set" | "dictionary" => Some(node.children.len() as i64),
        // JS/TS: array literal; object literal (each `pair`/shorthand property is one entry).
        "array" | "object" => Some(node.children.len() as i64),
        // Rust: array expression `[1, 2, 3]`.
        "array_expression" => Some(node.children.len() as i64),
        // Java: array initializer `{1, 2, 3}`.
        "array_initializer" => Some(node.children.len() as i64),
        // C/C++: brace initializer list `{1, 2, 3}`.
        "initializer_list" => Some(node.children.len() as i64),
        // Go: `composite_literal` wraps an optional type node plus a
        // `literal_value` (the `{...}` braces) — descend into literal_value's
        // own children for the element count, since composite_literal's direct
        // children are just [type?, literal_value], not the elements themselves.
        "composite_literal" => {
            let literal_value = node.children.iter().find_map(|&cid| {
                let c = cpg.ast.get(&cid)?;
                (c.node_type == "literal_value").then_some(c)
            });
            literal_value
                .map(|lv| lv.children.len() as i64)
                .or(Some(node.children.len() as i64))
        }
        _ => None,
    }
}

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
