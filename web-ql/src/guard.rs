//! Shared symbolic guard-verification primitives.
//!
//! A *guard* is a control-flow gate: the value reaching a sink/target is
//! unchanged, but the target is only reachable once a condition has been
//! satisfied (`if (p != NULL) { *p = 1; }`, `if (i < len) { a[i]; }`,
//! `if (d != 0) { x / d; }`). This module generalizes the symbolic
//! comparison-direction/polarity/magnitude verification originally built for
//! `strlen`-family length guards (see git history of `taint.rs`) so the same
//! rigor applies to every guard shape in the codebase — null checks,
//! zero-divisor checks, and bounds/index checks — instead of each CWE rule
//! (or the taint engine's `guards:` clause) re-implementing its own coarse
//! "some conditional mentions the value" presence check.
//!
//! Callers (both `taint.rs`'s `guards:` handling and the WQL-exposed
//! `excludes_zero`/`bounds_value` methods in `engine.rs`) resolve their own
//! `value_source` and, for `upper_bounds`, their own `capacity` (the
//! resolution convention differs per rule: a sink call's destination
//! argument, a subscripted array's own declaration, etc.) — this module only
//! verifies that the *condition itself* actually establishes the claimed
//! fact on the branch that reaches the target.

use std::collections::HashSet;
use web_sitter::{Cpg, IrNodeKind, NodeId};

use crate::dfg::DfgIndex;
use crate::symbolic::SymbolicEval;

/// Length-returning functions with known, fixed semantics: the engine can
/// find the comparison they sit in and work out what it establishes.
/// Opaque user-defined validators can only be recognized by name/presence.
pub const KNOWN_LENGTH_FUNCTIONS: &[&str] = &["strlen", "strnlen", "wcslen"];

/// True if `ancestor` is `node` itself or one of its AST ancestors.
pub fn is_ancestor(cpg: &Cpg, ancestor: NodeId, node: NodeId) -> bool {
    let mut cur = node;
    for _ in 0..500 {
        if cur == ancestor {
            return true;
        }
        match cpg.ast.get(&cur).and_then(|n| n.parent_id) {
            Some(p) if p != cur => cur = p,
            _ => return false,
        }
    }
    false
}

/// Walk up from `from` looking for the nearest enclosing comparison
/// `BinaryOp`, stopping at `stop_at` (a Conditional's condition root — don't
/// walk past it into unrelated code). Returns
/// `(binop, value_side, bound_side, operator, flipped)` where `value_side` is
/// whichever operand contains `from`, `bound_side` is the other operand, and
/// `flipped` is true when `from` was on the right (so the caller must mirror
/// the operator to read the comparison as `value <op> bound`).
pub fn find_enclosing_comparison(
    cpg: &Cpg,
    from: NodeId,
    stop_at: NodeId,
) -> Option<(NodeId, NodeId, NodeId, String, bool)> {
    let mut cur = from;
    for _ in 0..200 {
        if cur == stop_at {
            return None;
        }
        let node = cpg.ast.get(&cur)?;
        if node.kind == IrNodeKind::BinaryOp && node.children.len() >= 2 {
            if let Some(op) = node.operator.as_deref() {
                if matches!(op, "<" | "<=" | ">" | ">=" | "==" | "!=") {
                    let lhs = node.children[0];
                    let rhs = *node.children.last().unwrap();
                    if is_ancestor(cpg, lhs, from) {
                        return Some((cur, lhs, rhs, op.to_owned(), false));
                    }
                    if is_ancestor(cpg, rhs, from) {
                        return Some((cur, rhs, lhs, op.to_owned(), true));
                    }
                }
            }
        }
        match node.parent_id {
            Some(p) if p != cur => cur = p,
            _ => return None,
        }
    }
    None
}

pub fn flip_operator(op: &str) -> &'static str {
    match op {
        "<" => ">",
        "<=" => ">=",
        ">" => "<",
        ">=" => "<=",
        "==" => "==",
        _ => "!=",
    }
}

pub fn negate_operator(op: &str) -> &'static str {
    match op {
        "<" => ">=",
        "<=" => ">",
        ">" => "<=",
        ">=" => "<",
        "==" => "!=",
        _ => "==",
    }
}

/// Which branch of `cond_node` (a Conditional) reaches `target`: `Some(true)`
/// if `target` is inside the "consequence" (then) subtree, `Some(false)` if
/// inside "alternative" (else) — or, when `target` is outside both (the
/// common `if (cond) return;` early-exit idiom, where the sink sits after
/// the whole if-statement), `Some(false)` on the assumption that the
/// consequence branch terminates (return/break/continue/goto) rather than
/// falling through itself. Doesn't verify that assumption structurally; a
/// non-terminating consequence with no `alternative` is rare enough in
/// practice that getting it wrong here just means an occasional guard isn't
/// recognized (a missed suppression, not a wrong one).
pub fn branch_polarity(cpg: &Cpg, cond_node: NodeId, target: NodeId) -> Option<bool> {
    let node = cpg.ast.get(&cond_node)?;
    let mut consequence = None;
    let mut alternative = None;
    for (i, &child) in node.children.iter().enumerate() {
        match node.field_names.get(i).and_then(|f| f.as_deref()) {
            Some("consequence") => consequence = Some(child),
            Some("alternative") => alternative = Some(child),
            _ => {}
        }
    }
    if let Some(c) = consequence {
        if is_ancestor(cpg, c, target) {
            return Some(true);
        }
    }
    if let Some(a) = alternative {
        if is_ancestor(cpg, a, target) {
            return Some(false);
        }
    }
    Some(false)
}

/// The "condition" field child of a Conditional node (falling back to its
/// first child) — the boolean expression actually being tested.
pub fn condition_expr_of(cpg: &Cpg, cond_node: NodeId) -> Option<NodeId> {
    let node = cpg.ast.get(&cond_node)?;
    node.children
        .iter()
        .enumerate()
        .find_map(|(i, &cid)| {
            if node.field_names.get(i).and_then(|f| f.as_deref()) == Some("condition") {
                Some(cid)
            } else {
                None
            }
        })
        .or_else(|| node.children.first().copied())
}

/// Unwrap a parenthesized expression down to its inner value.
fn strip_parens(cpg: &Cpg, mut id: NodeId) -> NodeId {
    while let Some(node) = cpg.ast.get(&id) {
        if node.is_parenthesized() {
            if let Some(&cid) = node.children.last() {
                id = cid;
                continue;
            }
        }
        break;
    }
    id
}

/// True if `expr` *is* `value_source`, or a value that `value_source`'s
/// definition reaches via DFG (i.e. the same value, referenced again).
///
/// Mirrors the "subtree extension" the WQL-level `.dfg_reaches()` predicate
/// applies (`DfgPredicate::ReachesFlow` in engine.rs): a raw `dfg.reaches()`
/// on the literal node ids often misses the connection, because the actual
/// REACHING_DEF edge for a compound expression's value (e.g. `p = malloc(n)`)
/// is attached to one of its descendant identifier/argument nodes (`n`
/// inside `malloc(n)`), not the `Call` node itself — so a coarse WQL
/// predicate like `alloc.dfg_reaches(nc)` (`alloc` bound to the `malloc(...)`
/// `Call`) only succeeds because the engine checks reachability from every
/// node in `alloc`'s subtree, not just `alloc`'s own id. Without the same
/// extension here, every value-occurrence search below would silently fail
/// for exactly the allocation/call-result values these guards exist to
/// verify.
fn occurs_as(cpg: &Cpg, dfg: &DfgIndex, expr: NodeId, value_source: NodeId) -> bool {
    if expr == value_source || dfg.reaches(value_source, expr) {
        return true;
    }
    let expr_sub = crate::engine::ast_subtree(cpg, expr);
    crate::engine::ast_subtree(cpg, value_source)
        .iter()
        .any(|&f| {
            dfg.reachable_from(f)
                .iter()
                .any(|r| expr_sub.contains(r) && *r != value_source)
        })
}

/// Resolve a `Call` node's callee name via the call graph (falling back to
/// its own `name` field), matching the resolution `taint.rs` uses elsewhere.
fn callee_name_of(cpg: &Cpg, call_id: NodeId) -> Option<String> {
    let node = cpg.ast.get(&call_id)?;
    cpg.call_graph
        .values()
        .flat_map(|e| &e.calls)
        .find(|cs| cs.call_site == Some(call_id))
        .map(|cs| cs.callee.clone())
        .or_else(|| node.name.clone())
}

/// Argument nodes of a single `Call`, descending into the `argument_list`/
/// `arguments` container child most languages wrap arguments in.
fn call_argument_nodes(cpg: &Cpg, call_id: NodeId) -> Vec<NodeId> {
    let Some(node) = cpg.ast.get(&call_id) else {
        return Vec::new();
    };
    node.children
        .iter()
        .find_map(|&cid| {
            let child = cpg.ast.get(&cid)?;
            if matches!(child.node_type.as_str(), "argument_list" | "arguments") {
                Some(child.children.iter().copied().collect::<Vec<_>>())
            } else {
                None
            }
        })
        .unwrap_or_else(|| node.children.iter().copied().collect())
}

/// Find the node within `cond_node`'s *test expression* (its "condition"
/// field — NOT the consequence/alternative bodies) that represents an
/// occurrence of `value_source`: a direct occurrence of the value itself (an
/// expression it DFG-reaches, or itself), or — since string bounds checks
/// conventionally wrap the value in a length call (`strlen(x) <
/// sizeof(dst)`) — a call to one of `KNOWN_LENGTH_FUNCTIONS` whose argument
/// is the value. Tries the wrapped form first so that when a condition
/// contains both (e.g. comparing the wrapped length elsewhere), the more
/// specific bounds-relevant occurrence wins.
///
/// Deliberately scoped to just the test expression: `value_source` (e.g. a
/// divisor's declaration) DFG-reaches every use of that variable in the
/// function, including the very division/dereference/subscript the guard is
/// supposed to be protecting — searching `cond_node`'s whole subtree (rather
/// than only its condition) would let the search latch onto *that*
/// occurrence instead of the one actually inside the test, and
/// `find_enclosing_comparison` would then correctly report "no enclosing
/// comparison" for it (it isn't part of one), silently defeating the guard.
fn find_value_occurrence(
    cpg: &Cpg,
    dfg: &DfgIndex,
    cond_node: NodeId,
    value_source: NodeId,
) -> Option<NodeId> {
    let root = condition_expr_of(cpg, cond_node).unwrap_or(cond_node);
    let mut stack = vec![root];
    let mut seen = HashSet::new();
    let mut direct_fallback = None;
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        let Some(node) = cpg.ast.get(&id) else {
            continue;
        };
        if node.kind == IrNodeKind::Call {
            if let Some(name) = callee_name_of(cpg, id) {
                if KNOWN_LENGTH_FUNCTIONS.contains(&name.as_str()) {
                    let args = call_argument_nodes(cpg, id);
                    if args.iter().any(|&a| occurs_as(cpg, dfg, a, value_source)) {
                        return Some(id);
                    }
                }
            }
        }
        // Restrict the direct-occurrence fallback to `Identifier` leaves.
        // `occurs_as`'s subtree-extended reachability check makes almost any
        // *compound* ancestor node (the whole condition's `BinaryOp`, or
        // `cond_node` itself) spuriously "occur as" the value too — its
        // subtree merely *contains* a real occurrence somewhere inside it.
        // Matching at that coarse a level would hand
        // `find_enclosing_comparison` a node that IS the search's own
        // `stop_at` (or an ancestor of the real comparison), so it would
        // immediately fail to find anything. Only a leaf identifier is
        // actually "the value, referenced again".
        if node.kind == IrNodeKind::Identifier
            && direct_fallback.is_none()
            && occurs_as(cpg, dfg, id, value_source)
        {
            direct_fallback = Some(id);
        }
        stack.extend(node.children.iter().copied());
    }
    direct_fallback
}

/// True if the conditional `cond_node` establishes, on the branch that
/// reaches `target`, that `value_source`'s value is nonzero — covers both
/// direct comparisons against a zero-valued expression (`p == NULL`,
/// `p != NULL`, `d == 0`, `d != 0`; `NULL` symbolically folds to `0`) and the
/// bare-truthiness idiom (`if (p) ...`, `if (!p) return; ...`). Shared by
/// null-pointer guards and zero-divisor guards — both are the same "value
/// excludes zero" fact, just applied to different sink shapes.
///
/// Only checks the exact top-level condition expression for the bare-
/// truthiness case (not inside `&&`/`||` combinations) — De Morgan-aware
/// range analysis over compound conditions is a separate, not-yet-built
/// gap. Direct comparisons are found anywhere in the condition's subtree
/// (so `if (p != NULL && p->ok)` is still recognized via the comparison
/// branch below).
pub fn excludes_zero(
    cpg: &Cpg,
    dfg: &DfgIndex,
    value_source: NodeId,
    cond_node: NodeId,
    target: NodeId,
) -> bool {
    let Some(polarity) = branch_polarity(cpg, cond_node, target) else {
        return false;
    };

    if let Some(occurrence) = find_value_occurrence(cpg, dfg, cond_node, value_source) {
        if let Some((_binop, _value_side, bound_side, op, flipped)) =
            find_enclosing_comparison(cpg, occurrence, cond_node)
        {
            let mut se = SymbolicEval::new(cpg);
            if se.eval_int(bound_side) == Some(0) {
                let mut op = op.as_str();
                if flipped {
                    op = flip_operator(op);
                }
                let op = if polarity { op } else { negate_operator(op) };
                return op == "!=";
            }
        }
    }

    // Bare truthiness: `if (value) ...` / `if (!value) return; ...`. Only
    // matches when the (optionally negated) condition is *exactly* an
    // Identifier occurrence of the value — not any expression that merely
    // contains one, which `occurs_as`'s subtree-extended reachability would
    // otherwise match too eagerly (e.g. a `b == 0` comparison itself, which
    // must instead be handled by the comparison branch above so its
    // operator is actually read).
    if let Some(cond_expr) = condition_expr_of(cpg, cond_node) {
        let cond_expr = strip_parens(cpg, cond_expr);
        if let Some(node) = cpg.ast.get(&cond_expr) {
            if node.kind == IrNodeKind::UnaryOp && node.operator.as_deref() == Some("!") {
                if let Some(&inner) = node.children.first() {
                    let inner = strip_parens(cpg, inner);
                    if is_identifier_occurrence(cpg, dfg, inner, value_source) {
                        return !polarity;
                    }
                }
            } else if is_identifier_occurrence(cpg, dfg, cond_expr, value_source) {
                return polarity;
            }
        }
    }

    false
}

/// Like `occurs_as`, but only matches when `expr` is itself an `Identifier`
/// node — see the comment on `find_value_occurrence`'s equivalent
/// restriction for why the unrestricted subtree-extended check would
/// otherwise match on coarse ancestor/compound nodes.
fn is_identifier_occurrence(cpg: &Cpg, dfg: &DfgIndex, expr: NodeId, value_source: NodeId) -> bool {
    cpg.ast
        .get(&expr)
        .is_some_and(|n| n.kind == IrNodeKind::Identifier)
        && occurs_as(cpg, dfg, expr, value_source)
}

/// True if the conditional `cond_node` establishes, on the branch that
/// reaches `target`, that `value_source` (optionally wrapped in a
/// `strlen`-family call) is bounded above by `capacity` — the caller
/// resolves `capacity` itself (the convention for "the actual limit" differs
/// per rule: a sink call's destination-buffer argument, a subscripted
/// array's own declared size, ...). When `capacity` is `None` (not
/// statically resolvable), falls back to verifying only that the
/// comparison's direction is a valid upper-bound shape — still real
/// symbolic verification (rejects `if (len > n)`-style non-bounds as a
/// guard), just without the numeric cross-check.
pub fn upper_bounds(
    cpg: &Cpg,
    dfg: &DfgIndex,
    value_source: NodeId,
    cond_node: NodeId,
    target: NodeId,
    capacity: Option<i64>,
) -> bool {
    let Some(occurrence) = find_value_occurrence(cpg, dfg, cond_node, value_source) else {
        return false;
    };
    let Some((_binop, value_side, bound_side, op, flipped)) =
        find_enclosing_comparison(cpg, occurrence, cond_node)
    else {
        return false;
    };

    let mut op = op.as_str();
    if flipped {
        op = flip_operator(op);
    }
    match branch_polarity(cpg, cond_node, target) {
        Some(true) => {}
        Some(false) => op = negate_operator(op),
        None => return false,
    }
    if op != "<" && op != "<=" {
        return false;
    }

    let offset = extract_offset(cpg, value_side, occurrence).unwrap_or(0);

    let Some(capacity) = capacity else {
        return true;
    };
    let mut se = SymbolicEval::new(cpg);
    let Some(bound_val) = se.eval_int(bound_side) else {
        return true;
    };
    let threshold = capacity.saturating_add(offset);
    if op == "<" {
        bound_val <= threshold
    } else {
        bound_val < threshold
    }
}

/// If `value_expr` is exactly `occurrence` (offset 0) or
/// `occurrence + CONST` / `CONST + occurrence` (offset `CONST`), return the
/// offset — handles the common null-terminator idiom (`strlen(x) + 1`). Any
/// other shape returns `None`, treated by the caller as offset 0 (a wrongly-
/// assumed offset of 0 instead of a positive one under-credits the guard,
/// never over-credits it).
fn extract_offset(cpg: &Cpg, value_expr: NodeId, occurrence: NodeId) -> Option<i64> {
    if value_expr == occurrence {
        return Some(0);
    }
    let node = cpg.ast.get(&value_expr)?;
    if node.is_parenthesized() {
        return extract_offset(cpg, *node.children.first()?, occurrence);
    }
    if node.kind == IrNodeKind::BinaryOp && node.children.len() >= 2 {
        let op = node.operator.as_deref()?;
        let lhs = node.children[0];
        let rhs = *node.children.last().unwrap();
        let mut se = SymbolicEval::new(cpg);
        if lhs == occurrence && op == "+" {
            return se.eval_int(rhs);
        }
        if lhs == occurrence && op == "-" {
            return se.eval_int(rhs).map(|c| -c);
        }
        if rhs == occurrence && op == "+" {
            return se.eval_int(lhs);
        }
    }
    None
}
