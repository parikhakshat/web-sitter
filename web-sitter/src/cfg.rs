use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::{BTreeMap, BTreeSet};

use crate::{AstNode, BasicBlock, IrNodeKind, LoopKind, NodeId, TryKind, security_patterns as sp};

pub fn collect_noreturn_functions(graph: &BTreeMap<NodeId, AstNode>) -> BTreeSet<String> {
    collect_noreturn_functions_with_extra(graph, &[])
}

/// Returns true if `node` carries a `noreturn` / `_Noreturn` / `[[noreturn]]`
/// annotation.  First walks child attribute nodes (preferred, avoids FPs from
/// identifier names like `noreturn_handler`); falls back to a word-boundary
/// text search when no attribute children exist (synthetic/test ASTs).
fn has_noreturn_attribute(graph: &BTreeMap<NodeId, AstNode>, node: &AstNode) -> bool {
    for child_id in &node.children {
        let Some(child) = graph.get(child_id) else {
            continue;
        };
        let kind = child.node_type.as_str();
        // C23 / GNU attribute nodes
        if matches!(
            kind,
            "attribute"
                | "attribute_specifier"
                | "attribute_declaration"
                | "gnu_asm_qualifier"
                | "type_qualifier"
        ) {
            if let Some(text) = &child.text {
                let lower = text.to_ascii_lowercase();
                if lower.contains("noreturn") || lower.contains("_noreturn") {
                    return true;
                }
            }
        }
        // _Noreturn keyword appears as a type qualifier child on the declaration itself
        if kind == "type_qualifier" || kind == "_Noreturn" {
            if let Some(text) = &child.text {
                let lower = text.to_ascii_lowercase();
                if lower == "_noreturn" || lower == "noreturn" {
                    return true;
                }
            }
        }
    }
    // Fallback for synthetic ASTs (no children): scan the node's own text using
    // a word-boundary check to avoid firing on `noreturn_handler` identifiers.
    if node.children.is_empty() {
        if let Some(text) = &node.text {
            return text_has_noreturn_token(text);
        }
    }
    false
}

/// True when `text` contains `noreturn` or `_Noreturn` as a standalone token
/// (not as part of a longer identifier like `noreturn_handler`).
fn text_has_noreturn_token(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    for candidate in ["noreturn", "_noreturn"] {
        if let Some(pos) = lower.find(candidate) {
            let before_ok = pos == 0 || !lower.as_bytes()[pos - 1].is_ascii_alphanumeric();
            let after_pos = pos + candidate.len();
            let after_ok = after_pos >= lower.len()
                || !lower.as_bytes()[after_pos].is_ascii_alphanumeric()
                    && lower.as_bytes()[after_pos] != b'_';
            if before_ok && after_ok {
                return true;
            }
        }
    }
    false
}

/// Like [`collect_noreturn_functions`] but merges an additional caller-supplied
/// list (e.g. from `TaintConfig::noreturn_functions`).
pub fn collect_noreturn_functions_with_extra(
    graph: &BTreeMap<NodeId, AstNode>,
    extra: &[String],
) -> BTreeSet<String> {
    let mut noreturn: BTreeSet<String> = sp::NORETURN_FUNCTIONS
        .iter()
        .map(|s| s.to_string())
        .collect();
    noreturn.extend(extra.iter().cloned());

    for node in graph.values() {
        if !matches!(
            node.node_type.as_str(),
            "declaration" | "function_definition"
        ) {
            continue;
        }
        if !has_noreturn_attribute(graph, node) {
            continue;
        }
        if let Some(text) = &node.text {
            if let Some(name) = extract_function_name(text) {
                noreturn.insert(name);
            }
        }
    }

    noreturn
}

pub fn build_cfg(
    graph: &mut BTreeMap<NodeId, AstNode>,
    basic_blocks: &mut BTreeMap<String, BasicBlock>,
) {
    build_cfg_with_start(graph, basic_blocks, 0);
}

pub fn build_cfg_with_start(
    graph: &mut BTreeMap<NodeId, AstNode>,
    basic_blocks: &mut BTreeMap<String, BasicBlock>,
    next_bb_id: usize,
) {
    let function_ids: Vec<NodeId> = graph
        .iter()
        .filter_map(|(id, node)| node.is_method_def().then_some(*id))
        .collect();
    build_cfg_for_functions_with_start(
        graph,
        basic_blocks,
        &function_ids.into_iter().collect(),
        next_bb_id,
    );
}

pub fn build_cfg_for_functions_with_start(
    graph: &mut BTreeMap<NodeId, AstNode>,
    basic_blocks: &mut BTreeMap<String, BasicBlock>,
    function_ids: &BTreeSet<NodeId>,
    next_bb_id: usize,
) {
    build_cfg_for_functions_with_start_and_noreturn(
        graph,
        basic_blocks,
        function_ids,
        next_bb_id,
        &[],
    );
}

/// Like [`build_cfg_for_functions_with_start`] but merges `extra_noreturn`
/// into the noreturn set so user-defined termination functions are recognised
/// when building CFG edges.
pub fn build_cfg_for_functions_with_start_and_noreturn(
    graph: &mut BTreeMap<NodeId, AstNode>,
    basic_blocks: &mut BTreeMap<String, BasicBlock>,
    function_ids: &BTreeSet<NodeId>,
    next_bb_id: usize,
    extra_noreturn: &[String],
) {
    let noreturn_functions: FxHashSet<String> =
        collect_noreturn_functions_with_extra(graph, extra_noreturn)
            .into_iter()
            .collect();

    let mut builder = CfgBuilder {
        graph,
        basic_blocks,
        noreturn_functions,
        next_bb_id,
    };

    for function_id in function_ids {
        builder.process_function(*function_id);
    }
}

struct CfgBuilder<'a> {
    graph: &'a mut BTreeMap<NodeId, AstNode>,
    basic_blocks: &'a mut BTreeMap<String, BasicBlock>,
    noreturn_functions: FxHashSet<String>,
    next_bb_id: usize,
}

struct FunctionState {
    label_blocks: FxHashMap<String, String>,
    pending_gotos: Vec<(String, String)>,
    break_stack: Vec<(BreakKind, Option<String>, String)>,
    exit_bb_id: String,
    /// Stack of catch landing-pad BB IDs for exception handling (innermost last).
    catch_stack: Vec<String>,
    /// Stack of SEH `__try` exit BB IDs, for `__leave` statement targeting.
    seh_exit_stack: Vec<String>,
    /// Go defer stack: BB IDs of deferred calls, innermost last (LIFO at function exit).
    defer_stack: Vec<String>,
    /// Java/Python labeled-block exit BBs: label → exit BB (for labeled break/continue).
    label_exit_bbs: FxHashMap<String, String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BreakKind {
    Loop,
    Switch,
}

impl<'a> CfgBuilder<'a> {
    fn process_function(&mut self, func_id: NodeId) {
        // Try all known function-body block node types across supported languages.
        let func_body = self.find_child_by_type(func_id, "compound_statement")
            .or_else(|| self.find_child_by_type(func_id, "block"))
            .or_else(|| self.find_child_by_type(func_id, "statement_block"));
        let Some(func_body) = func_body else {
            return;
        };

        let entry_bb_id = self.create_bb(func_id);
        let exit_bb_id = self.create_bb(func_id);
        let mut state = FunctionState {
            label_blocks: FxHashMap::default(),
            pending_gotos: Vec::new(),
            break_stack: Vec::new(),
            exit_bb_id: exit_bb_id.clone(),
            catch_stack: Vec::new(),
            seh_exit_stack: Vec::new(),
            defer_stack: Vec::new(),
            label_exit_bbs: FxHashMap::default(),
        };

        self.add_single_node_to_bb(func_id, &entry_bb_id);
        let mut current_bb_id = entry_bb_id.clone();
        let body_children = self
            .graph
            .get(&func_body)
            .map(|n| n.children.clone())
            .unwrap_or_default();
        for child_id in body_children {
            current_bb_id = self.process_statement(func_id, child_id, current_bb_id, &mut state);
        }

        self.add_successor(&current_bb_id, &exit_bb_id);

        // Wire Go defer chain: deferred calls run in LIFO order at function exit.
        // Chain: exit_bb → defer[N] → defer[N-1] → ... → defer[0].
        if !state.defer_stack.is_empty() {
            let mut prev_bb = exit_bb_id.clone();
            for defer_bb in state.defer_stack.iter().rev() {
                self.add_successor(&prev_bb, defer_bb);
                prev_bb = defer_bb.clone();
            }
        }

        for (goto_bb, label) in &state.pending_gotos {
            if let Some(target) = state.label_blocks.get(label) {
                self.add_successor(goto_bb, target);
            }
        }
    }

    fn process_statement(
        &mut self,
        func_id: NodeId,
        stmt_id: NodeId,
        current_bb_id: String,
        state: &mut FunctionState,
    ) -> String {
        let Some(stmt) = self.graph.get(&stmt_id).cloned() else {
            return current_bb_id;
        };

        match stmt.kind {
            IrNodeKind::Conditional => {
                self.process_if_statement(func_id, stmt_id, current_bb_id, state)
            }
            IrNodeKind::Loop => match stmt.loop_kind.unwrap_or(LoopKind::While) {
                LoopKind::While => {
                    self.process_while_statement(func_id, stmt_id, current_bb_id, state)
                }
                LoopKind::For => {
                    self.process_for_statement(func_id, stmt_id, current_bb_id, state)
                }
                LoopKind::DoWhile => {
                    self.process_do_statement(func_id, stmt_id, current_bb_id, state)
                }
                LoopKind::ForEach => {
                    self.process_range_for_statement(func_id, stmt_id, current_bb_id, state)
                }
            },
            IrNodeKind::Switch => {
                self.process_switch_statement(func_id, stmt_id, current_bb_id, state)
            }
            // Go: type switch and select statements — branch to each arm BB
            IrNodeKind::TypeSwitch | IrNodeKind::SelectStmt => {
                self.process_go_branching_statement(func_id, stmt_id, current_bb_id, state)
            }
            // Rust: match expression — branch to each arm BB
            IrNodeKind::MatchExpr => {
                self.process_match_statement(func_id, stmt_id, current_bb_id, state)
            }
            IrNodeKind::SehLeave => {
                self.process_seh_leave_statement(func_id, stmt_id, current_bb_id, state)
            }
            IrNodeKind::Break | IrNodeKind::Continue => {
                self.process_jump_statement(func_id, stmt_id, current_bb_id, state)
            }
            IrNodeKind::Return => {
                self.process_return_statement(func_id, stmt_id, current_bb_id, state)
            }
            IrNodeKind::Goto => {
                self.process_goto_statement(func_id, stmt_id, current_bb_id, state)
            }
            IrNodeKind::Label => {
                self.process_labeled_statement(func_id, stmt_id, current_bb_id, state)
            }
            IrNodeKind::Block => {
                let mut bb = current_bb_id;
                let children = stmt.children.clone();
                for child_id in children {
                    bb = self.process_statement(func_id, child_id, bb, state);
                }
                bb
            }
            // Go: statement_list is a transparent container inside block nodes
            IrNodeKind::Unknown if stmt.node_type == "statement_list" => {
                let mut bb = current_bb_id;
                for child_id in stmt.children {
                    bb = self.process_statement(func_id, child_id, bb, state);
                }
                bb
            }
            // ExprStmt wraps a single expression; pass through so nested branching
            // constructs (match, type_switch) can be handled by their own processors.
            IrNodeKind::ExprStmt => {
                self.add_single_node_to_bb(stmt_id, &current_bb_id);
                let mut bb = current_bb_id;
                for child_id in stmt.children {
                    bb = self.process_statement(func_id, child_id, bb, state);
                }
                bb
            }
            IrNodeKind::Case | IrNodeKind::SwitchDefault => {
                self.add_node_to_bb(stmt_id, &current_bb_id);
                let mut bb = current_bb_id;
                for child_id in stmt.children {
                    let Some(child) = self.graph.get(&child_id) else {
                        continue;
                    };
                    if matches!(child.node_type.as_str(), "case" | "default" | ":") {
                        continue;
                    }
                    if child.kind.is_expression() {
                        self.add_node_to_bb(child_id, &bb);
                    } else {
                        bb = self.process_statement(func_id, child_id, bb, state);
                    }
                }
                bb
            }
            // ── Exception handling ────────────────────────────────────────────
            IrNodeKind::Try => match stmt.try_kind.unwrap_or(TryKind::Standard) {
                TryKind::Seh => {
                    self.process_seh_try_statement(func_id, stmt_id, current_bb_id, state)
                }
                TryKind::Standard | TryKind::WithResources => {
                    self.process_try_statement(func_id, stmt_id, current_bb_id, state)
                }
            },
            IrNodeKind::Throw => {
                self.process_throw_statement(func_id, stmt_id, current_bb_id, state)
            }
            // ── C++20 coroutine suspend points ────────────────────────────────
            IrNodeKind::UnaryOp
                if matches!(
                    stmt.node_type.as_str(),
                    "co_await_expression" | "co_yield_expression"
                ) =>
            {
                // Suspend point: add to current BB and add a resume edge back to
                // the next statement (conservative: the awaited value is Top).
                self.add_node_to_bb(stmt_id, &current_bb_id);
                let resume_bb = self.create_bb(func_id);
                self.add_successor(&current_bb_id, &resume_bb);
                // Also link to function exit (suspension may propagate cancellation).
                self.add_successor(&current_bb_id, &state.exit_bb_id);
                resume_bb
            }

            // ── Go-specific statements ────────────────────────────────────────
            // `go expr` — goroutine launch: linear, the spawned goroutine runs
            // concurrently; the current goroutine continues.
            IrNodeKind::GoStmt | IrNodeKind::SendStmt | IrNodeKind::ReceiveExpr => {
                self.add_node_to_bb(stmt_id, &current_bb_id);
                current_bb_id
            }

            // `defer expr` — registers a deferred call; executes at function exit
            // in LIFO order. Register the node in the current BB (eval of args
            // happens here) and record a defer BB that the function exit wires.
            IrNodeKind::DeferStmt => {
                self.add_node_to_bb(stmt_id, &current_bb_id);
                let defer_bb = self.create_bb(func_id);
                self.add_node_to_bb(stmt_id, &defer_bb);
                state.defer_stack.push(defer_bb);
                current_bb_id
            }

            // `fallthrough` — unconditionally transfers control to the next
            // switch case body. We close the current case path here; the parent
            // `process_switch_statement` wires successor BBs.
            IrNodeKind::Fallthrough => {
                self.add_node_to_bb(stmt_id, &current_bb_id);
                // Return a dead BB; the Fallthrough terminates the case block.
                self.create_bb(func_id)
            }

            // ── Python-specific statements ────────────────────────────────────
            // `with expr [as name]:` — context manager: __enter__ on entry,
            // __exit__ on both normal and exceptional exit (like try/finally).
            IrNodeKind::With => {
                self.process_with_statement(func_id, stmt_id, current_bb_id, state)
            }

            // `assert expr[, msg]` — raises AssertionError on failure.
            // Model as a conditional branch: normal path + exception path to catch.
            IrNodeKind::Assert => {
                self.add_node_to_bb(stmt_id, &current_bb_id);
                if let Some(landing_pad) = state.catch_stack.last().cloned() {
                    if let Some(bb) = self.basic_blocks.get_mut(&current_bb_id) {
                        if !bb.exception_successors.contains(&landing_pad) {
                            bb.exception_successors.push(landing_pad);
                        }
                    }
                } else {
                    self.add_successor(&current_bb_id, &state.exit_bb_id);
                }
                current_bb_id
            }

            // Walrus operator `:=` — def-then-use, linear in control flow.
            IrNodeKind::NamedExpr => {
                self.add_node_to_bb(stmt_id, &current_bb_id);
                current_bb_id
            }

            // Python comprehension — body is a sub-expression; treated as linear.
            IrNodeKind::Comprehension => {
                self.add_node_to_bb(stmt_id, &current_bb_id);
                current_bb_id
            }

            // ── Java-specific statements ──────────────────────────────────────
            // `synchronized(expr) { body }` — monitor enter on entry, monitor exit
            // on normal and exceptional exit. Model like a try/finally block.
            IrNodeKind::Synchronized => {
                self.process_synchronized_statement(func_id, stmt_id, current_bb_id, state)
            }

            // ── JS/TS-specific expressions ────────────────────────────────────
            // `await expr` — async suspension point: like co_await.
            IrNodeKind::AwaitExpr => {
                self.add_node_to_bb(stmt_id, &current_bb_id);
                let resume_bb = self.create_bb(func_id);
                self.add_successor(&current_bb_id, &resume_bb);
                self.add_successor(&current_bb_id, &state.exit_bb_id);
                resume_bb
            }

            // `yield expr` / `yield*` — generator suspend point.
            IrNodeKind::YieldExpr => {
                self.add_node_to_bb(stmt_id, &current_bb_id);
                let resume_bb = self.create_bb(func_id);
                self.add_successor(&current_bb_id, &resume_bb);
                self.add_successor(&current_bb_id, &state.exit_bb_id);
                resume_bb
            }

            // `expr?.member` — optional chain: null/undefined check branch.
            // True path: non-null, continue. False path: short-circuit to null.
            IrNodeKind::OptionalChain => {
                self.add_node_to_bb(stmt_id, &current_bb_id);
                let nonnull_bb = self.create_bb(func_id);
                let merge_bb = self.create_bb(func_id);
                self.add_successor(&current_bb_id, &nonnull_bb);
                self.add_successor(&current_bb_id, &merge_bb); // short-circuit null
                self.add_successor(&nonnull_bb, &merge_bb);
                merge_bb
            }

            // ── Rust-specific expressions ─────────────────────────────────────
            // `loop { body }` — infinite loop with break-value join block.
            IrNodeKind::LoopExpr => {
                self.process_loop_expr(func_id, stmt_id, current_bb_id, state)
            }

            // `expr?` — propagates Err: success path continues, error path returns.
            IrNodeKind::TryExpr => {
                self.add_node_to_bb(stmt_id, &current_bb_id);
                // Error path: early return (jumps to function exit).
                self.add_successor(&current_bb_id, &state.exit_bb_id);
                // Success path: continue in same BB (value is unwrapped).
                current_bb_id
            }

            // `unsafe { body }` — treat as a transparent block; annotate
            // is_unsafe_context on nodes via the cpg_generator pass.
            IrNodeKind::UnsafeBlock => {
                let children = stmt.children.clone();
                let mut bb = current_bb_id;
                self.add_single_node_to_bb(stmt_id, &bb);
                for child_id in children {
                    bb = self.process_statement(func_id, child_id, bb, state);
                }
                bb
            }

            // `break value` — Rust break with an optional value expression.
            // Semantics identical to regular break but the break expression carries a value.
            IrNodeKind::BreakExpr => {
                self.add_node_to_bb(stmt_id, &current_bb_id);
                if let Some((_, _, exit_bb)) = state.break_stack.last() {
                    self.add_successor(&current_bb_id, exit_bb);
                }
                self.create_bb(func_id)
            }

            // Python Yield/Await (when visited as statements)
            IrNodeKind::Yield | IrNodeKind::Await => {
                self.add_node_to_bb(stmt_id, &current_bb_id);
                let resume_bb = self.create_bb(func_id);
                self.add_successor(&current_bb_id, &resume_bb);
                self.add_successor(&current_bb_id, &state.exit_bb_id);
                resume_bb
            }

            // Inline assembly: add to the current block. All volatile asm may branch.
            IrNodeKind::Unknown
                if matches!(
                    stmt.node_type.as_str(),
                    "asm_statement" | "gnu_asm_statement"
                ) =>
            {
                self.add_node_to_bb(stmt_id, &current_bb_id);
                self.add_successor(&current_bb_id, &state.exit_bb_id);
                self.create_bb(func_id)
            }
            _ => {
                self.add_node_to_bb(stmt_id, &current_bb_id);
                if stmt.kind == IrNodeKind::Call {
                    let callee = self.extract_callee_name(stmt_id);
                    if matches!(
                        callee.as_deref(),
                        Some("setjmp") | Some("sigsetjmp") | Some("_setjmp")
                    ) {
                        // Mark this BB as a potential longjmp resume target.
                        if let Some(bb) = self.basic_blocks.get_mut(&current_bb_id) {
                            bb.is_setjmp_target = true;
                        }
                    } else if matches!(
                        callee.as_deref(),
                        Some("longjmp") | Some("siglongjmp") | Some("_longjmp")
                    ) {
                        // Add CFG edges to all setjmp-target blocks in this function
                        // (intraprocedural only; interprocedural is best-effort).
                        let setjmp_bbs: Vec<String> = self
                            .basic_blocks
                            .iter()
                            .filter(|(_, bb)| bb.function == func_id && bb.is_setjmp_target)
                            .map(|(id, _)| id.clone())
                            .collect();
                        for target_bb in setjmp_bbs {
                            self.add_successor(&current_bb_id, &target_bb);
                        }
                        // longjmp is also noreturn on the non-jump path.
                        self.add_successor(&current_bb_id, &state.exit_bb_id);
                        return self.create_bb(func_id);
                    } else if self.call_is_noreturn(stmt_id) {
                        self.add_successor(&current_bb_id, &state.exit_bb_id);
                        return self.create_bb(func_id);
                    }
                }
                current_bb_id
            }
        }
    }

    fn process_jump_statement(
        &mut self,
        func_id: NodeId,
        stmt_id: NodeId,
        current_bb_id: String,
        state: &mut FunctionState,
    ) -> String {
        self.add_node_to_bb(stmt_id, &current_bb_id);
        let stmt_type = self
            .graph
            .get(&stmt_id)
            .map(|n| n.node_type.clone())
            .unwrap_or_default();

        // Check for labeled break/continue (Java, Python loop labels).
        let label_target = self.graph.get(&stmt_id).and_then(|n| {
            n.children.iter().find_map(|cid| {
                let c = self.graph.get(cid)?;
                matches!(c.node_type.as_str(), "statement_identifier" | "identifier")
                    .then(|| c.text.clone())
                    .flatten()
            })
        });

        if stmt_type == "break_statement" {
            if let Some(label) = &label_target {
                // Labeled break: jump to the exit BB of the labeled block.
                if let Some(exit_bb) = state.label_exit_bbs.get(label).cloned() {
                    self.add_successor(&current_bb_id, &exit_bb);
                }
            } else if let Some((_, _, exit_bb)) = state.break_stack.last() {
                self.add_successor(&current_bb_id, exit_bb);
            }
        } else {
            if let Some(label) = &label_target {
                // Labeled continue: jump to the header BB of the labeled loop.
                if let Some(entry_bb) = state.label_blocks.get(label).cloned() {
                    self.add_successor(&current_bb_id, &entry_bb);
                }
            } else {
            for (kind, header_bb, _) in state.break_stack.iter().rev() {
                if *kind == BreakKind::Loop {
                    if let Some(header_bb) = header_bb {
                        self.add_successor(&current_bb_id, header_bb);
                    }
                    break;
                }
            }
            }
        }

        self.create_bb(func_id)
    }

    fn process_return_statement(
        &mut self,
        func_id: NodeId,
        stmt_id: NodeId,
        current_bb_id: String,
        state: &mut FunctionState,
    ) -> String {
        self.add_node_to_bb(stmt_id, &current_bb_id);
        self.add_successor(&current_bb_id, &state.exit_bb_id);
        self.create_bb(func_id)
    }

    fn process_goto_statement(
        &mut self,
        func_id: NodeId,
        stmt_id: NodeId,
        current_bb_id: String,
        state: &mut FunctionState,
    ) -> String {
        self.add_node_to_bb(stmt_id, &current_bb_id);
        let mut label_name = None;
        if let Some(stmt) = self.graph.get(&stmt_id) {
            for child_id in &stmt.children {
                let Some(child) = self.graph.get(child_id) else {
                    continue;
                };
                if matches!(
                    child.node_type.as_str(),
                    "statement_identifier" | "identifier"
                ) {
                    label_name = child.text.clone();
                    break;
                }
            }
        }

        if let Some(label_name) = label_name {
            if let Some(target) = state.label_blocks.get(&label_name) {
                self.add_successor(&current_bb_id, target);
            } else {
                state
                    .pending_gotos
                    .push((current_bb_id.clone(), label_name));
            }
        }

        self.create_bb(func_id)
    }

    fn process_labeled_statement(
        &mut self,
        func_id: NodeId,
        stmt_id: NodeId,
        current_bb_id: String,
        state: &mut FunctionState,
    ) -> String {
        let label_bb_id = self.create_bb(func_id);
        self.add_successor(&current_bb_id, &label_bb_id);

        let mut label_name = None;
        let mut inner_stmt_id = None;
        if let Some(stmt) = self.graph.get(&stmt_id) {
            for child_id in &stmt.children {
                let Some(child) = self.graph.get(child_id) else {
                    continue;
                };
                match child.node_type.as_str() {
                    "statement_identifier" => label_name = child.text.clone(),
                    ":" => {}
                    _ => inner_stmt_id = Some(*child_id),
                }
            }
        }

        // Register the label entry BB before processing the inner statement
        // so that forward gotos/breaks inside can resolve it.
        if let Some(ref name) = label_name {
            state.label_blocks.insert(name.clone(), label_bb_id.clone());
        }

        let exit_bb = if let Some(inner_stmt_id) = inner_stmt_id {
            let exit = self.process_statement(func_id, inner_stmt_id, label_bb_id.clone(), state);
            // Also record the exit BB for labeled break (Java/Python).
            if let Some(ref name) = label_name {
                state.label_exit_bbs.insert(name.clone(), exit.clone());
            }
            exit
        } else {
            label_bb_id
        };
        exit_bb
    }

    fn process_short_circuit_condition(
        &mut self,
        func_id: NodeId,
        cond_id: NodeId,
        entry_bb_id: &str,
        true_bb_id: &str,
        false_bb_id: &str,
    ) {
        let Some(cond) = self.graph.get(&cond_id).cloned() else {
            self.add_successor(entry_bb_id, true_bb_id);
            self.add_successor(entry_bb_id, false_bb_id);
            return;
        };

        if cond.is_parenthesized() {
            if let Some(inner_id) = cond.children.first().copied() {
                self.add_node_to_bb(cond_id, entry_bb_id);
                self.process_short_circuit_condition(
                    func_id,
                    inner_id,
                    entry_bb_id,
                    true_bb_id,
                    false_bb_id,
                );
                return;
            }
        }

        if cond.is_binary_op() {
            let operator = cond.operator.clone().or_else(|| {
                cond.text.as_ref().and_then(|text| {
                    if text.contains("&&") {
                        Some("&&".to_string())
                    } else if text.contains("||") {
                        Some("||".to_string())
                    } else {
                        None
                    }
                })
            });
            if let Some(operator) = operator {
                if matches!(operator.as_str(), "&&" | "||") && cond.children.len() >= 2 {
                    self.add_node_to_bb(cond_id, entry_bb_id);
                    let left_id = cond.children[0];
                    let right_id = cond.children[1];
                    let rhs_bb_id = self.create_bb(func_id);
                    if operator == "&&" {
                        self.process_short_circuit_condition(
                            func_id,
                            left_id,
                            entry_bb_id,
                            &rhs_bb_id,
                            false_bb_id,
                        );
                        self.process_short_circuit_condition(
                            func_id,
                            right_id,
                            &rhs_bb_id,
                            true_bb_id,
                            false_bb_id,
                        );
                    } else {
                        self.process_short_circuit_condition(
                            func_id,
                            left_id,
                            entry_bb_id,
                            true_bb_id,
                            &rhs_bb_id,
                        );
                        self.process_short_circuit_condition(
                            func_id,
                            right_id,
                            &rhs_bb_id,
                            true_bb_id,
                            false_bb_id,
                        );
                    }
                    return;
                }
            }
        }

        self.add_node_to_bb(cond_id, entry_bb_id);
        self.add_successor(entry_bb_id, true_bb_id);
        self.add_successor(entry_bb_id, false_bb_id);
    }

    fn process_if_statement(
        &mut self,
        func_id: NodeId,
        stmt_id: NodeId,
        current_bb_id: String,
        state: &mut FunctionState,
    ) -> String {
        let (init_id, condition_id, consequence_id, alternative_id) =
            self.extract_if_parts(stmt_id);

        if let Some(init_id) = init_id {
            self.add_node_to_bb(init_id, &current_bb_id);
        }

        let then_bb_id = self.create_bb(func_id);
        let merge_bb_id = self.create_bb(func_id);
        let else_entry_bb_id = alternative_id.map(|_| self.create_bb(func_id));
        let false_target = else_entry_bb_id
            .clone()
            .unwrap_or_else(|| merge_bb_id.clone());

        if let Some(condition_id) = condition_id {
            self.process_short_circuit_condition(
                func_id,
                condition_id,
                &current_bb_id,
                &then_bb_id,
                &false_target,
            );
        } else {
            self.add_successor(&current_bb_id, &then_bb_id);
            self.add_successor(&current_bb_id, &false_target);
        }

        let then_end = if let Some(consequence_id) = consequence_id {
            self.process_statement(func_id, consequence_id, then_bb_id.clone(), state)
        } else {
            then_bb_id.clone()
        };
        self.add_successor(&then_end, &merge_bb_id);

        if let (Some(alternative_id), Some(else_bb_id)) = (alternative_id, else_entry_bb_id) {
            let else_end = self.process_statement(func_id, alternative_id, else_bb_id, state);
            self.add_successor(&else_end, &merge_bb_id);
        }

        merge_bb_id
    }

    fn process_while_statement(
        &mut self,
        func_id: NodeId,
        stmt_id: NodeId,
        current_bb_id: String,
        state: &mut FunctionState,
    ) -> String {
        let (condition_id, body_id, _) = self.extract_condition_and_body(stmt_id);
        let header_bb_id = self.create_bb(func_id);
        let body_bb_id = self.create_bb(func_id);
        let exit_bb_id = self.create_bb(func_id);
        self.add_successor(&current_bb_id, &header_bb_id);

        if let Some(condition_id) = condition_id {
            self.process_short_circuit_condition(
                func_id,
                condition_id,
                &header_bb_id,
                &body_bb_id,
                &exit_bb_id,
            );
        } else {
            self.add_successor(&header_bb_id, &body_bb_id);
            self.add_successor(&header_bb_id, &exit_bb_id);
        }

        state.break_stack.push((
            BreakKind::Loop,
            Some(header_bb_id.clone()),
            exit_bb_id.clone(),
        ));
        let body_end = body_id
            .map(|body_id| self.process_statement(func_id, body_id, body_bb_id.clone(), state))
            .unwrap_or(body_bb_id.clone());
        state.break_stack.pop();
        self.add_successor(&body_end, &header_bb_id);

        exit_bb_id
    }

    fn process_for_statement(
        &mut self,
        func_id: NodeId,
        stmt_id: NodeId,
        current_bb_id: String,
        state: &mut FunctionState,
    ) -> String {
        let (init_id, condition_id, update_id, body_id) = self.extract_for_parts(stmt_id);
        let current_bb_id = current_bb_id;
        if let Some(init_id) = init_id {
            self.add_node_to_bb(init_id, &current_bb_id);
        }

        let header_bb_id = self.create_bb(func_id);
        let body_bb_id = self.create_bb(func_id);
        let exit_bb_id = self.create_bb(func_id);
        self.add_successor(&current_bb_id, &header_bb_id);

        if let Some(condition_id) = condition_id {
            self.process_short_circuit_condition(
                func_id,
                condition_id,
                &header_bb_id,
                &body_bb_id,
                &exit_bb_id,
            );
        } else {
            self.add_successor(&header_bb_id, &body_bb_id);
            self.add_successor(&header_bb_id, &exit_bb_id);
        }

        state.break_stack.push((
            BreakKind::Loop,
            Some(header_bb_id.clone()),
            exit_bb_id.clone(),
        ));
        let body_end = body_id
            .map(|body_id| self.process_statement(func_id, body_id, body_bb_id.clone(), state))
            .unwrap_or(body_bb_id.clone());
        state.break_stack.pop();

        if let Some(update_id) = update_id {
            self.add_node_to_bb(update_id, &body_end);
        }
        self.add_successor(&body_end, &header_bb_id);

        exit_bb_id
    }

    fn process_do_statement(
        &mut self,
        func_id: NodeId,
        stmt_id: NodeId,
        current_bb_id: String,
        state: &mut FunctionState,
    ) -> String {
        let (condition_id, body_id, _) = self.extract_condition_and_body(stmt_id);
        let body_bb_id = self.create_bb(func_id);
        let condition_bb_id = self.create_bb(func_id);
        let exit_bb_id = self.create_bb(func_id);
        self.add_successor(&current_bb_id, &body_bb_id);

        state.break_stack.push((
            BreakKind::Loop,
            Some(condition_bb_id.clone()),
            exit_bb_id.clone(),
        ));
        let body_end = body_id
            .map(|body_id| self.process_statement(func_id, body_id, body_bb_id.clone(), state))
            .unwrap_or(body_bb_id.clone());
        state.break_stack.pop();
        self.add_successor(&body_end, &condition_bb_id);

        if let Some(condition_id) = condition_id {
            self.process_short_circuit_condition(
                func_id,
                condition_id,
                &condition_bb_id,
                &body_bb_id,
                &exit_bb_id,
            );
        } else {
            self.add_successor(&condition_bb_id, &exit_bb_id);
        }

        exit_bb_id
    }

    fn process_switch_statement(
        &mut self,
        func_id: NodeId,
        stmt_id: NodeId,
        current_bb_id: String,
        state: &mut FunctionState,
    ) -> String {
        let (init_id, condition_id, body_id) = self.extract_switch_parts(stmt_id);
        let current_bb_id = current_bb_id;
        if let Some(init_id) = init_id {
            self.add_node_to_bb(init_id, &current_bb_id);
        }
        if let Some(condition_id) = condition_id {
            self.add_node_to_bb(condition_id, &current_bb_id);
        }

        let exit_bb_id = self.create_bb(func_id);
        state
            .break_stack
            .push((BreakKind::Switch, None, exit_bb_id.clone()));

        if let Some(body_id) = body_id {
            let body_children = self
                .graph
                .get(&body_id)
                .map(|n| n.children.clone())
                .unwrap_or_default();
            let mut case_bb_id: Option<String> = None;
            for child_id in body_children {
                let Some(child) = self.graph.get(&child_id).cloned() else {
                    continue;
                };
                if matches!(
                    child.node_type.as_str(),
                    "case_statement" | "default_statement"
                ) {
                    let new_case_bb_id = self.create_bb(func_id);
                    self.add_successor(&current_bb_id, &new_case_bb_id);
                    if let Some(prev_case_bb) = &case_bb_id {
                        self.add_successor(prev_case_bb, &new_case_bb_id);
                    }
                    case_bb_id = Some(new_case_bb_id.clone());

                    for case_child_id in child.children {
                        let Some(case_child) = self.graph.get(&case_child_id) else {
                            continue;
                        };
                        if matches!(case_child.node_type.as_str(), "case" | "default" | ":") {
                            continue;
                        }
                        if case_child.node_type.contains("expression") {
                            self.add_node_to_bb(case_child_id, &new_case_bb_id);
                        } else if let Some(bb) = case_bb_id.take() {
                            case_bb_id =
                                Some(self.process_statement(func_id, case_child_id, bb, state));
                        }
                    }
                } else if let Some(bb) = case_bb_id.take() {
                    case_bb_id = Some(self.process_statement(func_id, child_id, bb, state));
                }
            }

            if let Some(case_bb_id) = case_bb_id {
                self.add_successor(&case_bb_id, &exit_bb_id);
            }
        }

        self.add_successor(&current_bb_id, &exit_bb_id);
        state.break_stack.pop();
        exit_bb_id
    }

    /// Process Go type switch and select statements: branch to each arm (TypeCase,
    /// CommCase, SwitchDefault) and merge at exit BB.
    fn process_go_branching_statement(
        &mut self,
        func_id: NodeId,
        stmt_id: NodeId,
        current_bb_id: String,
        state: &mut FunctionState,
    ) -> String {
        self.add_node_to_bb(stmt_id, &current_bb_id);
        let exit_bb_id = self.create_bb(func_id);
        state
            .break_stack
            .push((BreakKind::Switch, None, exit_bb_id.clone()));

        // Collect all direct arm nodes (TypeCase, CommCase, SwitchDefault) and
        // all body/clause wrapper nodes recursively.
        let stmt_children = self
            .graph
            .get(&stmt_id)
            .map(|n| n.children.clone())
            .unwrap_or_default();

        // Walk children recursively to find case arms.
        let mut arm_ids: Vec<NodeId> = Vec::new();
        let mut body_queue: Vec<NodeId> = stmt_children;
        while let Some(child_id) = body_queue.pop() {
            let Some(child) = self.graph.get(&child_id) else {
                continue;
            };
            match child.kind {
                IrNodeKind::TypeCase | IrNodeKind::CommCase | IrNodeKind::SwitchDefault => {
                    arm_ids.push(child_id);
                }
                IrNodeKind::Unknown | IrNodeKind::Block => {
                    body_queue.extend(child.children.iter().copied());
                }
                _ => {
                    // Non-arm, non-body child: add to switch BB as header expression
                    self.add_node_to_bb(child_id, &current_bb_id);
                }
            }
        }

        arm_ids.sort_unstable(); // preserve source order (node IDs are in order)

        for arm_id in arm_ids {
            let arm_bb = self.create_bb(func_id);
            self.add_successor(&current_bb_id, &arm_bb);
            // Process the arm's children as statements
            let arm_children = self
                .graph
                .get(&arm_id)
                .map(|n| n.children.clone())
                .unwrap_or_default();
            self.add_node_to_bb(arm_id, &arm_bb);
            let mut bb = arm_bb;
            for child_id in arm_children {
                let Some(child) = self.graph.get(&child_id) else {
                    continue;
                };
                if child.kind.is_expression() || matches!(
                    child.node_type.as_str(),
                    "type_list" | "case" | "default" | ":"
                ) {
                    self.add_node_to_bb(child_id, &bb);
                } else {
                    bb = self.process_statement(func_id, child_id, bb, state);
                }
            }
            self.add_successor(&bb, &exit_bb_id);
        }

        // Fallthrough edge (no matching arm)
        self.add_successor(&current_bb_id, &exit_bb_id);
        state.break_stack.pop();
        exit_bb_id
    }

    /// Process Rust match expressions: create an arm BB per MatchArm and merge at exit.
    fn process_match_statement(
        &mut self,
        func_id: NodeId,
        stmt_id: NodeId,
        current_bb_id: String,
        state: &mut FunctionState,
    ) -> String {
        self.add_single_node_to_bb(stmt_id, &current_bb_id);
        let exit_bb_id = self.create_bb(func_id);
        state
            .break_stack
            .push((BreakKind::Switch, None, exit_bb_id.clone()));

        // Collect MatchArm nodes recursively through Unknown/Block wrappers
        let stmt_children = self
            .graph
            .get(&stmt_id)
            .map(|n| n.children.clone())
            .unwrap_or_default();
        let mut arm_ids: Vec<NodeId> = Vec::new();
        let mut body_queue: Vec<NodeId> = stmt_children;
        while let Some(child_id) = body_queue.pop() {
            let Some(child) = self.graph.get(&child_id) else { continue; };
            match child.kind {
                IrNodeKind::MatchArm => {
                    arm_ids.push(child_id);
                }
                IrNodeKind::Unknown | IrNodeKind::Block => {
                    let children = child.children.clone();
                    body_queue.extend(children);
                }
                _ => {
                    self.add_node_to_bb(child_id, &current_bb_id);
                }
            }
        }
        arm_ids.sort_unstable();

        for arm_id in arm_ids {
            let arm_bb = self.create_bb(func_id);
            self.add_successor(&current_bb_id, &arm_bb);
            let arm_children = self
                .graph
                .get(&arm_id)
                .map(|n| n.children.clone())
                .unwrap_or_default();
            self.add_node_to_bb(arm_id, &arm_bb);
            let mut bb = arm_bb;
            for child_id in arm_children {
                let Some(child) = self.graph.get(&child_id) else { continue; };
                if child.kind.is_expression() {
                    self.add_node_to_bb(child_id, &bb);
                } else {
                    bb = self.process_statement(func_id, child_id, bb, state);
                }
            }
            self.add_successor(&bb, &exit_bb_id);
        }

        self.add_successor(&current_bb_id, &exit_bb_id);
        state.break_stack.pop();
        exit_bb_id
    }

    /// Python `with` statement: context manager enter/exit (like try/finally).
    /// __enter__ is called on entry; __exit__ on both normal and exceptional exit.
    fn process_with_statement(
        &mut self,
        func_id: NodeId,
        stmt_id: NodeId,
        current_bb_id: String,
        state: &mut FunctionState,
    ) -> String {
        let Some(stmt) = self.graph.get(&stmt_id).cloned() else {
            return current_bb_id;
        };

        // Find the with-clause items and body block.
        let mut body_id: Option<NodeId> = None;
        let mut with_items: Vec<NodeId> = Vec::new();
        for child_id in &stmt.children {
            let Some(child) = self.graph.get(child_id) else { continue; };
            match child.node_type.as_str() {
                "block" => body_id = Some(*child_id),
                "with_clause" | "with_item" => with_items.push(*child_id),
                _ => {}
            }
        }

        // Enter BBs: evaluate with expressions.
        let mut enter_bb = current_bb_id.clone();
        for item_id in &with_items {
            self.add_node_to_bb(*item_id, &enter_bb);
        }

        let exit_bb = self.create_bb(func_id);

        // Body: push landing pad (for __exit__ on exception).
        let landing_pad = self.create_bb(func_id);
        state.catch_stack.push(landing_pad.clone());

        let body_end = if let Some(body_id) = body_id {
            let children = self.graph.get(&body_id).map(|n| n.children.clone()).unwrap_or_default();
            let mut bb = enter_bb.clone();
            for child_id in children {
                bb = self.process_statement(func_id, child_id, bb, state);
            }
            bb
        } else {
            enter_bb.clone()
        };

        state.catch_stack.pop();

        // Normal exit calls __exit__(None, None, None).
        self.add_successor(&body_end, &exit_bb);
        // Exception exit calls __exit__(exc_type, exc_val, exc_tb).
        self.add_successor(&landing_pad, &exit_bb);

        exit_bb
    }

    /// Java `synchronized(expr) { body }` — monitor enter/exit semantics.
    /// Models like a try/finally: monitor released on both normal and exception exit.
    fn process_synchronized_statement(
        &mut self,
        func_id: NodeId,
        stmt_id: NodeId,
        current_bb_id: String,
        state: &mut FunctionState,
    ) -> String {
        let Some(stmt) = self.graph.get(&stmt_id).cloned() else {
            return current_bb_id;
        };

        self.add_node_to_bb(stmt_id, &current_bb_id);
        let exit_bb = self.create_bb(func_id);
        let landing_pad = self.create_bb(func_id);
        state.catch_stack.push(landing_pad.clone());

        // Find and process body block.
        let body_id = stmt.children.iter().find_map(|cid| {
            let child = self.graph.get(cid)?;
            matches!(child.node_type.as_str(), "block").then_some(*cid)
        });

        let body_end = if let Some(body_id) = body_id {
            let children = self.graph.get(&body_id).map(|n| n.children.clone()).unwrap_or_default();
            let mut bb = current_bb_id.clone();
            for child_id in children {
                bb = self.process_statement(func_id, child_id, bb, state);
            }
            bb
        } else {
            current_bb_id
        };

        state.catch_stack.pop();
        self.add_successor(&body_end, &exit_bb);
        self.add_successor(&landing_pad, &exit_bb);
        exit_bb
    }

    /// Rust `loop { body }` — infinite loop with optional break-value join block.
    /// The only exit is via `break` (possibly with a value).
    fn process_loop_expr(
        &mut self,
        func_id: NodeId,
        stmt_id: NodeId,
        current_bb_id: String,
        state: &mut FunctionState,
    ) -> String {
        let Some(stmt) = self.graph.get(&stmt_id).cloned() else {
            return current_bb_id;
        };

        let header_bb = self.create_bb(func_id);
        let exit_bb = self.create_bb(func_id);
        self.add_successor(&current_bb_id, &header_bb);

        state.break_stack.push((BreakKind::Loop, Some(header_bb.clone()), exit_bb.clone()));

        // Body: first block child.
        let body_id = stmt.children.iter().find_map(|cid| {
            let child = self.graph.get(cid)?;
            matches!(child.node_type.as_str(), "block").then_some(*cid)
        });

        let body_end = if let Some(body_id) = body_id {
            let children = self.graph.get(&body_id).map(|n| n.children.clone()).unwrap_or_default();
            let mut bb = header_bb.clone();
            for child_id in children {
                bb = self.process_statement(func_id, child_id, bb, state);
            }
            bb
        } else {
            header_bb.clone()
        };

        state.break_stack.pop();
        // Loop back to header (infinite unless broken).
        self.add_successor(&body_end, &header_bb);
        exit_bb
    }

    fn extract_condition_and_body(
        &self,
        node_id: NodeId,
    ) -> (Option<NodeId>, Option<NodeId>, bool) {
        let Some(node) = self.graph.get(&node_id) else {
            return (None, None, false);
        };
        let mut condition_id = None;
        let mut body_id = None;
        let mut is_compound_body = false;

        for child_id in &node.children {
            let Some(child) = self.graph.get(child_id) else {
                continue;
            };
            match child.node_type.as_str() {
                "compound_statement" => {
                    body_id = Some(*child_id);
                    is_compound_body = true;
                }
                t if t.contains("expression") || t == "parenthesized_expression" => {
                    if condition_id.is_none() {
                        condition_id = Some(*child_id);
                    }
                }
                t if body_id.is_none()
                    && condition_id.is_some()
                    && !matches!(t, "while" | "for" | "do" | "(" | ")" | ";") =>
                {
                    body_id = Some(*child_id);
                }
                _ => {}
            }
        }

        (condition_id, body_id, is_compound_body)
    }

    fn extract_if_parts(
        &self,
        stmt_id: NodeId,
    ) -> (
        Option<NodeId>,
        Option<NodeId>,
        Option<NodeId>,
        Option<NodeId>,
    ) {
        let Some(stmt) = self.graph.get(&stmt_id) else {
            return (None, None, None, None);
        };
        let mut init_id = None;
        let mut condition_id = None;
        let mut consequence_id = None;
        let mut alternative_id = None;

        for child_id in &stmt.children {
            let Some(child) = self.graph.get(child_id) else {
                continue;
            };
            match child.node_type.as_str() {
                "declaration" | "expression_statement" if condition_id.is_none() => {
                    if init_id.is_none() {
                        init_id = Some(*child_id);
                    } else {
                        condition_id = Some(*child_id);
                    }
                }
                t if t.contains("expression") || t == "condition_clause" => {
                    if condition_id.is_none() {
                        condition_id = Some(*child_id);
                    }
                }
                "else_clause" => {
                    for else_child_id in &child.children {
                        let Some(else_child) = self.graph.get(else_child_id) else {
                            continue;
                        };
                        if else_child.node_type != "else" {
                            alternative_id = Some(*else_child_id);
                            break;
                        }
                    }
                }
                "compound_statement" if consequence_id.is_none() => {
                    consequence_id = Some(*child_id)
                }
                t if consequence_id.is_none()
                    && condition_id.is_some()
                    && !matches!(t, "if" | "(" | ")" | "constexpr") =>
                {
                    consequence_id = Some(*child_id);
                }
                _ => {}
            }
        }

        (init_id, condition_id, consequence_id, alternative_id)
    }

    fn extract_for_parts(
        &self,
        stmt_id: NodeId,
    ) -> (
        Option<NodeId>,
        Option<NodeId>,
        Option<NodeId>,
        Option<NodeId>,
    ) {
        let Some(stmt) = self.graph.get(&stmt_id) else {
            return (None, None, None, None);
        };
        let mut init_id = None;
        let mut condition_id = None;
        let mut update_id = None;
        let mut body_id = None;
        let mut expr_count = 0usize;

        for child_id in &stmt.children {
            let Some(child) = self.graph.get(child_id) else {
                continue;
            };
            match child.node_type.as_str() {
                "compound_statement" => body_id = Some(*child_id),
                "declaration" | "expression_statement" if init_id.is_none() => {
                    init_id = Some(*child_id)
                }
                t if t.contains("expression") => {
                    if expr_count == 0 {
                        condition_id = Some(*child_id);
                    } else if expr_count == 1 {
                        update_id = Some(*child_id);
                    }
                    expr_count += 1;
                }
                t if body_id.is_none() && !matches!(t, "for" | "(" | ")" | ";") => {
                    if expr_count >= 1 || init_id.is_some() {
                        body_id = Some(*child_id);
                    }
                }
                _ => {}
            }
        }

        (init_id, condition_id, update_id, body_id)
    }

    fn extract_switch_parts(
        &self,
        stmt_id: NodeId,
    ) -> (Option<NodeId>, Option<NodeId>, Option<NodeId>) {
        let Some(stmt) = self.graph.get(&stmt_id) else {
            return (None, None, None);
        };
        let mut init_id = None;
        let mut condition_id = None;
        let mut body_id = None;

        for child_id in &stmt.children {
            let Some(child) = self.graph.get(child_id) else {
                continue;
            };
            match child.node_type.as_str() {
                "compound_statement" => body_id = Some(*child_id),
                "declaration" | "expression_statement" if condition_id.is_none() => {
                    if init_id.is_none() {
                        init_id = Some(*child_id);
                    } else {
                        condition_id = Some(*child_id);
                    }
                }
                t if t.contains("expression") => condition_id = Some(*child_id),
                _ => {}
            }
        }

        (init_id, condition_id, body_id)
    }

    // ── C++ try/catch/throw ───────────────────────────────────────────────────

    fn process_try_statement(
        &mut self,
        func_id: NodeId,
        stmt_id: NodeId,
        current_bb_id: String,
        state: &mut FunctionState,
    ) -> String {
        let Some(stmt) = self.graph.get(&stmt_id).cloned() else {
            return current_bb_id;
        };

        // Collect the try body and all catch_clause children.
        let mut try_body_id: Option<NodeId> = None;
        let mut catch_clauses: Vec<NodeId> = Vec::new();
        for child_id in &stmt.children {
            let Some(child) = self.graph.get(child_id) else {
                continue;
            };
            match child.node_type.as_str() {
                "compound_statement" if try_body_id.is_none() => try_body_id = Some(*child_id),
                "catch_clause" => catch_clauses.push(*child_id),
                _ => {}
            }
        }

        let try_exit_bb = self.create_bb(func_id);

        // Create one landing-pad BB per catch clause.
        let landing_pad_bbs: Vec<String> = catch_clauses
            .iter()
            .map(|_| self.create_bb(func_id))
            .collect();

        // The first landing pad is the entry for the catch block sequence.
        let first_landing_pad = landing_pad_bbs
            .first()
            .cloned()
            .unwrap_or(try_exit_bb.clone());

        // Push landing pad onto the catch stack so throw expressions inside can find it.
        state.catch_stack.push(first_landing_pad.clone());

        // Process try body.
        let try_body_end = if let Some(body_id) = try_body_id {
            let body_children = self
                .graph
                .get(&body_id)
                .map(|n| n.children.clone())
                .unwrap_or_default();
            let mut bb = current_bb_id.clone();
            for child_id in body_children {
                // Add exception edge to landing pad for any expression that can throw (A5):
                // call_expression, new_expression, throw_expression, delete_expression.
                let can_throw = self
                    .graph
                    .get(&child_id)
                    .map(|n| {
                        matches!(
                            n.node_type.as_str(),
                            "call_expression"
                                | "new_expression"
                                | "throw_statement"
                                | "delete_expression"
                        )
                    })
                    .unwrap_or(false);
                bb = self.process_statement(func_id, child_id, bb, state);
                if can_throw && !landing_pad_bbs.is_empty() {
                    // Add exception flow edge from current BB to landing pad.
                    if let Some(bb_node) = self.basic_blocks.get_mut(&bb) {
                        if !bb_node.exception_successors.contains(&first_landing_pad) {
                            bb_node.exception_successors.push(first_landing_pad.clone());
                        }
                    }
                }
            }
            bb
        } else {
            current_bb_id
        };
        self.add_successor(&try_body_end, &try_exit_bb);

        // Pop catch stack.
        state.catch_stack.pop();

        // Process each catch clause.
        for (catch_id, landing_pad_bb) in catch_clauses.iter().zip(landing_pad_bbs.iter()) {
            let Some(catch) = self.graph.get(catch_id).cloned() else {
                continue;
            };
            // Find compound_statement body inside catch clause.
            let catch_body_id = catch.children.iter().find_map(|cid| {
                let child = self.graph.get(cid)?;
                (child.node_type == "compound_statement").then_some(*cid)
            });
            let catch_end = if let Some(body_id) = catch_body_id {
                let body_children = self
                    .graph
                    .get(&body_id)
                    .map(|n| n.children.clone())
                    .unwrap_or_default();
                let mut bb = landing_pad_bb.clone();
                for child_id in body_children {
                    bb = self.process_statement(func_id, child_id, bb, state);
                }
                bb
            } else {
                landing_pad_bb.clone()
            };
            self.add_successor(&catch_end, &try_exit_bb);
        }

        try_exit_bb
    }

    // ── MSVC SEH handlers ────────────────────────────────────────────────────

    /// Handle `__try { body } __except(filter) { handler }` and
    /// `__try { body } __finally { cleanup }`.
    ///
    /// * `__except`: landing-pad BB receives exception edges from every call
    ///   inside the try body; handler → try_exit.
    /// * `__finally`: cleanup block always runs (both normal and exception
    ///   exits from the try body flow into the finally BB); finally → try_exit.
    fn process_seh_try_statement(
        &mut self,
        func_id: NodeId,
        stmt_id: NodeId,
        current_bb_id: String,
        state: &mut FunctionState,
    ) -> String {
        let Some(stmt) = self.graph.get(&stmt_id).cloned() else {
            return current_bb_id;
        };

        let mut try_body_id: Option<NodeId> = None;
        let mut except_clause_id: Option<NodeId> = None;
        let mut finally_clause_id: Option<NodeId> = None;

        for child_id in &stmt.children {
            let Some(child) = self.graph.get(child_id) else {
                continue;
            };
            match child.node_type.as_str() {
                "compound_statement" if try_body_id.is_none() => try_body_id = Some(*child_id),
                "seh_except_clause" => except_clause_id = Some(*child_id),
                "seh_finally_clause" => finally_clause_id = Some(*child_id),
                _ => {}
            }
        }

        let try_exit_bb = self.create_bb(func_id);

        if let Some(except_id) = except_clause_id {
            // __except path: behaves like C++ catch.
            let landing_pad_bb = self.create_bb(func_id);
            state.catch_stack.push(landing_pad_bb.clone());
            state.seh_exit_stack.push(try_exit_bb.clone());

            let try_body_end = if let Some(body_id) = try_body_id {
                let body_children = self
                    .graph
                    .get(&body_id)
                    .map(|n| n.children.clone())
                    .unwrap_or_default();
                let mut bb = current_bb_id.clone();
                for child_id in body_children {
                    let is_call = self
                        .graph
                        .get(&child_id)
                        .map(|n| n.node_type == "call_expression")
                        .unwrap_or(false);
                    bb = self.process_statement(func_id, child_id, bb, state);
                    if is_call {
                        if let Some(bb_node) = self.basic_blocks.get_mut(&bb) {
                            if !bb_node.exception_successors.contains(&landing_pad_bb) {
                                bb_node.exception_successors.push(landing_pad_bb.clone());
                            }
                        }
                    }
                }
                bb
            } else {
                current_bb_id.clone()
            };

            state.seh_exit_stack.pop();
            state.catch_stack.pop();
            self.add_successor(&try_body_end, &try_exit_bb);

            // Process __except body.
            let except_body_id = self.graph.get(&except_id).and_then(|n| {
                n.children.iter().find_map(|cid| {
                    let child = self.graph.get(cid)?;
                    (child.node_type == "compound_statement").then_some(*cid)
                })
            });
            let except_end = if let Some(body_id) = except_body_id {
                let body_children = self
                    .graph
                    .get(&body_id)
                    .map(|n| n.children.clone())
                    .unwrap_or_default();
                let mut bb = landing_pad_bb.clone();
                for child_id in body_children {
                    bb = self.process_statement(func_id, child_id, bb, state);
                }
                bb
            } else {
                landing_pad_bb
            };
            self.add_successor(&except_end, &try_exit_bb);
        } else if let Some(finally_id) = finally_clause_id {
            // __finally path: cleanup block always runs.
            // Exception landing pad for the try body.
            let exc_landing_bb = self.create_bb(func_id);
            state.catch_stack.push(exc_landing_bb.clone());
            state.seh_exit_stack.push(try_exit_bb.clone());

            let try_body_end = if let Some(body_id) = try_body_id {
                let body_children = self
                    .graph
                    .get(&body_id)
                    .map(|n| n.children.clone())
                    .unwrap_or_default();
                let mut bb = current_bb_id.clone();
                for child_id in body_children {
                    let is_call = self
                        .graph
                        .get(&child_id)
                        .map(|n| n.node_type == "call_expression")
                        .unwrap_or(false);
                    bb = self.process_statement(func_id, child_id, bb, state);
                    if is_call {
                        if let Some(bb_node) = self.basic_blocks.get_mut(&bb) {
                            if !bb_node.exception_successors.contains(&exc_landing_bb) {
                                bb_node.exception_successors.push(exc_landing_bb.clone());
                            }
                        }
                    }
                }
                bb
            } else {
                current_bb_id.clone()
            };

            state.seh_exit_stack.pop();
            state.catch_stack.pop();

            // Both normal exit and exception path flow into __finally body.
            let finally_body_id = self.graph.get(&finally_id).and_then(|n| {
                n.children.iter().find_map(|cid| {
                    let child = self.graph.get(cid)?;
                    (child.node_type == "compound_statement").then_some(*cid)
                })
            });

            // Create a single finally entry BB; both paths merge into it.
            let finally_entry_bb = self.create_bb(func_id);
            self.add_successor(&try_body_end, &finally_entry_bb);
            self.add_successor(&exc_landing_bb, &finally_entry_bb);

            let finally_end = if let Some(body_id) = finally_body_id {
                let body_children = self
                    .graph
                    .get(&body_id)
                    .map(|n| n.children.clone())
                    .unwrap_or_default();
                let mut bb = finally_entry_bb;
                for child_id in body_children {
                    bb = self.process_statement(func_id, child_id, bb, state);
                }
                bb
            } else {
                finally_entry_bb
            };
            self.add_successor(&finally_end, &try_exit_bb);
        } else {
            // Malformed SEH: just connect body to exit.
            let try_body_end = if let Some(body_id) = try_body_id {
                let body_children = self
                    .graph
                    .get(&body_id)
                    .map(|n| n.children.clone())
                    .unwrap_or_default();
                let mut bb = current_bb_id;
                for child_id in body_children {
                    bb = self.process_statement(func_id, child_id, bb, state);
                }
                bb
            } else {
                current_bb_id
            };
            self.add_successor(&try_body_end, &try_exit_bb);
        }

        try_exit_bb
    }

    /// `__leave` statement: jump to the nearest enclosing SEH try's exit block,
    /// analogous to `break` for loops/switch.
    fn process_seh_leave_statement(
        &mut self,
        func_id: NodeId,
        stmt_id: NodeId,
        current_bb_id: String,
        state: &mut FunctionState,
    ) -> String {
        self.add_node_to_bb(stmt_id, &current_bb_id);
        if let Some(seh_exit) = state.seh_exit_stack.last().cloned() {
            self.add_successor(&current_bb_id, &seh_exit);
        }
        self.create_bb(func_id)
    }

    fn process_throw_statement(
        &mut self,
        func_id: NodeId,
        stmt_id: NodeId,
        current_bb_id: String,
        state: &mut FunctionState,
    ) -> String {
        self.add_node_to_bb(stmt_id, &current_bb_id);
        // Route to innermost enclosing catch landing pad (if any).
        if let Some(landing_pad) = state.catch_stack.last().cloned() {
            if let Some(bb) = self.basic_blocks.get_mut(&current_bb_id) {
                if !bb.exception_successors.contains(&landing_pad) {
                    bb.exception_successors.push(landing_pad);
                }
            }
        }
        // Also add edge to function exit (unhandled throw path).
        self.add_successor(&current_bb_id, &state.exit_bb_id);
        self.create_bb(func_id)
    }

    // ── C++ range-based for ───────────────────────────────────────────────────

    fn process_range_for_statement(
        &mut self,
        func_id: NodeId,
        stmt_id: NodeId,
        current_bb_id: String,
        state: &mut FunctionState,
    ) -> String {
        let Some(stmt) = self.graph.get(&stmt_id).cloned() else {
            return current_bb_id;
        };

        // Extract loop variable declaration and body.
        let mut decl_id: Option<NodeId> = None;
        let mut range_id: Option<NodeId> = None;
        let mut body_id: Option<NodeId> = None;

        for child_id in &stmt.children {
            let Some(child) = self.graph.get(child_id) else {
                continue;
            };
            match child.node_type.as_str() {
                "for" | "(" | ")" | ":" => {}
                "compound_statement" => body_id = Some(*child_id),
                "type_specifier"
                | "auto"
                | "declaration"
                | "structured_binding_declaration"
                | "type_descriptor"
                    if decl_id.is_none() =>
                {
                    decl_id = Some(*child_id);
                }
                _ if body_id.is_none() && decl_id.is_some() && range_id.is_none() => {
                    range_id = Some(*child_id);
                }
                _ if body_id.is_none() && decl_id.is_none() => {
                    decl_id = Some(*child_id);
                }
                _ => {}
            }
        }

        // Structure: header (init + begin/end) → condition → body → increment → condition
        let header_bb = self.create_bb(func_id);
        let cond_bb = self.create_bb(func_id);
        let body_bb = self.create_bb(func_id);
        let exit_bb = self.create_bb(func_id);

        self.add_successor(&current_bb_id, &header_bb);

        // Header: range init and iterator creation.
        if let Some(id) = decl_id {
            self.add_node_to_bb(id, &header_bb);
        }
        if let Some(id) = range_id {
            self.add_node_to_bb(id, &header_bb);
        }
        self.add_successor(&header_bb, &cond_bb);

        // Condition: iterator != end.
        self.add_successor(&cond_bb, &body_bb); // true
        self.add_successor(&cond_bb, &exit_bb); // false

        // Body.
        state
            .break_stack
            .push((BreakKind::Loop, Some(cond_bb.clone()), exit_bb.clone()));
        let body_end = if let Some(bid) = body_id {
            let body_children = self
                .graph
                .get(&bid)
                .map(|n| n.children.clone())
                .unwrap_or_default();
            let mut bb = body_bb;
            for child_id in body_children {
                bb = self.process_statement(func_id, child_id, bb, state);
            }
            bb
        } else {
            body_bb
        };
        state.break_stack.pop();

        // Increment: ++iter → condition.
        self.add_successor(&body_end, &cond_bb);

        exit_bb
    }

    fn create_bb(&mut self, func_id: NodeId) -> String {
        let bb_id = format!("bb_{}", self.next_bb_id);
        self.next_bb_id += 1;
        self.basic_blocks.insert(
            bb_id.clone(),
            BasicBlock {
                block_type: "basic_block".to_string(),
                nodes: Vec::new(),
                successors: Vec::new(),
                exception_successors: Vec::new(),
                function: func_id,
                is_setjmp_target: false,
            },
        );
        bb_id
    }

    fn add_node_to_bb(&mut self, node_id: NodeId, bb_id: &str) {
        let mut stack = vec![node_id];
        let mut seen = FxHashSet::default();
        while let Some(current_id) = stack.pop() {
            if !seen.insert(current_id) {
                continue;
            }
            let children = if let Some(node) = self.graph.get_mut(&current_id) {
                node.basic_block = Some(bb_id.to_string());
                if node.is_method_def() {
                    Vec::new()
                } else {
                    node.children.clone()
                }
            } else {
                continue;
            };
            if let Some(bb) = self.basic_blocks.get_mut(bb_id) {
                if !bb.nodes.contains(&current_id) {
                    bb.nodes.push(current_id);
                }
            }
            stack.extend(children);
        }
    }

    fn add_single_node_to_bb(&mut self, node_id: NodeId, bb_id: &str) {
        if let Some(node) = self.graph.get_mut(&node_id) {
            node.basic_block = Some(bb_id.to_string());
        }
        if let Some(bb) = self.basic_blocks.get_mut(bb_id) {
            if !bb.nodes.contains(&node_id) {
                bb.nodes.push(node_id);
            }
        }
    }

    fn add_successor(&mut self, from_bb: &str, to_bb: &str) {
        if from_bb == to_bb {
            if let Some(bb) = self.basic_blocks.get_mut(from_bb) {
                if !bb.successors.contains(&to_bb.to_string()) {
                    bb.successors.push(to_bb.to_string());
                }
            }
            return;
        }
        if let Some(bb) = self.basic_blocks.get_mut(from_bb) {
            if !bb.successors.contains(&to_bb.to_string()) {
                bb.successors.push(to_bb.to_string());
            }
        }
    }

    fn find_child_by_type(&self, node_id: NodeId, target_type: &str) -> Option<NodeId> {
        let node = self.graph.get(&node_id)?;
        node.children.iter().find_map(|child_id| {
            let child = self.graph.get(child_id)?;
            (child.node_type == target_type).then_some(*child_id)
        })
    }

    fn extract_callee_name(&self, node_id: NodeId) -> Option<String> {
        let node = self.graph.get(&node_id)?;
        if node.node_type != "call_expression" {
            return None;
        }
        node.text
            .as_deref()
            .and_then(|text| text.split('(').next())
            .map(|prefix| {
                prefix
                    .split_whitespace()
                    .last()
                    .unwrap_or_default()
                    .trim_matches('*')
                    .to_string()
            })
            .filter(|s| !s.is_empty())
    }

    fn call_is_noreturn(&self, node_id: NodeId) -> bool {
        let Some(node) = self.graph.get(&node_id) else {
            return false;
        };
        if node.node_type != "call_expression" {
            return false;
        }
        let callee = node
            .text
            .as_deref()
            .and_then(|text| text.split('(').next())
            .map(|prefix| {
                prefix
                    .split_whitespace()
                    .last()
                    .unwrap_or_default()
                    .to_string()
            })
            .unwrap_or_default();
        self.noreturn_functions.contains(&callee)
    }
}

fn extract_function_name(text: &str) -> Option<String> {
    let open = text.rfind('(')?;
    let prefix = &text[..open];
    prefix
        .split_whitespace()
        .last()
        .map(|s| s.trim_matches('*').to_string())
        .filter(|s| !s.is_empty())
}

// ── SCC / condensation ────────────────────────────────────────────────────────

/// Compute Strongly Connected Components of the CFG for the given set of basic
/// blocks using an **iterative** Tarjan's algorithm (no recursion, safe for
/// large functions).
///
/// Returns the SCCs in **reverse-topological order of the condensation** — i.e.
/// `result[0]` has no predecessors in the condensation, so it is processed
/// first in a forward pass.  Within each SCC the BBs are ordered
/// reverse-post-order (RPO) to minimise back-edge revisits during iterative
/// fixpoint computation.
pub fn compute_cfg_sccs(
    basic_blocks: &BTreeMap<String, BasicBlock>,
    function_bbs: &[&str],
) -> Vec<Vec<String>> {
    if function_bbs.is_empty() {
        return vec![];
    }

    // ── Kosaraju's two-pass algorithm (iterative, avoids recursion depth) ──
    //
    // Pass 1: DFS on original graph → push nodes to a stack in finish order.
    // Pass 2: DFS on reversed graph in reverse-finish-order → each DFS tree
    //         is one SCC.

    let bb_set: FxHashSet<&str> = function_bbs.iter().copied().collect();

    // Map bb_id → index for O(1) lookup.
    let bb_to_idx: FxHashMap<&str, usize> = function_bbs
        .iter()
        .enumerate()
        .map(|(i, &bb)| (bb, i))
        .collect();

    let n = function_bbs.len();
    let mut visited = vec![false; n];
    let mut finish_stack: Vec<usize> = Vec::with_capacity(n);

    // Adjacency in original direction.
    let adj: Vec<Vec<usize>> = function_bbs
        .iter()
        .map(|&bb| {
            basic_blocks
                .get(bb)
                .map(|block| {
                    block
                        .successors
                        .iter()
                        .chain(block.exception_successors.iter())
                        .filter_map(|s| {
                            if bb_set.contains(s.as_str()) {
                                bb_to_idx.get(s.as_str()).copied()
                            } else {
                                None
                            }
                        })
                        .collect()
                })
                .unwrap_or_default()
        })
        .collect();

    // Adjacency in reversed direction.
    let mut radj: Vec<Vec<usize>> = vec![vec![]; n];
    for (u, neighbors) in adj.iter().enumerate() {
        for &v in neighbors {
            radj[v].push(u);
        }
    }

    // Pass 1: iterative DFS to compute finish order.
    for start in 0..n {
        if visited[start] {
            continue;
        }
        let mut stack: Vec<(usize, usize)> = vec![(start, 0)]; // (node, next_child_idx)
        visited[start] = true;
        while let Some((u, ci)) = stack.last_mut() {
            let u = *u;
            if *ci < adj[u].len() {
                let v = adj[u][*ci];
                *ci += 1;
                if !visited[v] {
                    visited[v] = true;
                    stack.push((v, 0));
                }
            } else {
                finish_stack.push(u);
                stack.pop();
            }
        }
    }

    // Pass 2: iterative DFS on reversed graph in reverse-finish order.
    let mut comp = vec![usize::MAX; n];
    let mut scc_count = 0usize;
    let mut scc_members: Vec<Vec<usize>> = Vec::new();

    while let Some(start) = finish_stack.pop() {
        if comp[start] != usize::MAX {
            continue;
        }
        let scc_id = scc_count;
        scc_count += 1;
        let mut members = Vec::new();
        let mut stack = vec![start];
        comp[start] = scc_id;
        while let Some(u) = stack.pop() {
            members.push(u);
            for &v in &radj[u] {
                if comp[v] == usize::MAX {
                    comp[v] = scc_id;
                    stack.push(v);
                }
            }
        }
        scc_members.push(members);
    }

    // At this point scc_members is in reverse-topological order of the condensation
    // (Kosaraju's pass 2 naturally gives SCCs in topo order of condensation when
    // finish_stack is consumed in LIFO order).

    // Within each SCC, order BBs by reverse-post-order (RPO) via DFS on the
    // sub-graph restricted to the SCC.
    let mut result: Vec<Vec<String>> = Vec::with_capacity(scc_members.len());
    for members in &scc_members {
        if members.len() == 1 {
            result.push(vec![function_bbs[members[0]].to_string()]);
            continue;
        }
        let member_set: FxHashSet<usize> = members.iter().copied().collect();
        let mut rpo_visited = FxHashSet::default();
        let mut rpo_stack: Vec<usize> = Vec::new();
        // DFS from first member (any entry point within SCC works for RPO).
        let mut dfs = vec![(members[0], 0usize)];
        rpo_visited.insert(members[0]);
        while let Some((u, ci)) = dfs.last_mut() {
            let u = *u;
            if *ci < adj[u].len() {
                let v = adj[u][*ci];
                *ci += 1;
                if member_set.contains(&v) && rpo_visited.insert(v) {
                    dfs.push((v, 0));
                }
            } else {
                rpo_stack.push(u);
                dfs.pop();
            }
        }
        // Append any members not reached by DFS (disconnected within SCC - rare).
        for &m in members {
            if rpo_visited.insert(m) {
                rpo_stack.push(m);
            }
        }
        // RPO = reverse of post-order.
        rpo_stack.reverse();
        result.push(
            rpo_stack
                .iter()
                .map(|&i| function_bbs[i].to_string())
                .collect(),
        );
    }

    result
}

/// Compute a topology-signature hash for a set of SCCs.  Two functions have
/// the same signature iff they have the same number of SCCs, the same SCC
/// sizes in order, and the same inter-SCC edges.  Used to detect whether a
/// change altered the loop structure of a function.
pub fn cfg_topology_sig(basic_blocks: &BTreeMap<String, BasicBlock>, sccs: &[Vec<String>]) -> u64 {
    // Assign SCC index to each BB.
    let mut bb_to_scc: FxHashMap<&str, usize> = FxHashMap::default();
    for (scc_idx, scc) in sccs.iter().enumerate() {
        for bb in scc {
            bb_to_scc.insert(bb.as_str(), scc_idx);
        }
    }

    // FNV-1a hash of: (scc_count, per-scc size, sorted inter-scc edges).
    // Uses a portable inline FNV-1a implementation (no extra crate needed).
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x00000100000001b3;

    let mut hash = FNV_OFFSET;
    let mut mix = |val: u64| {
        for byte in val.to_le_bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
    };

    mix(sccs.len() as u64);
    for scc in sccs {
        mix(scc.len() as u64);
        // Collect inter-SCC edges FROM this SCC (sorted for determinism).
        let mut out_edges: Vec<(usize, usize)> = Vec::new();
        for bb in scc {
            let scc_idx = bb_to_scc[bb.as_str()];
            if let Some(block) = basic_blocks.get(bb) {
                for succ in block
                    .successors
                    .iter()
                    .chain(block.exception_successors.iter())
                {
                    if let Some(&succ_scc) = bb_to_scc.get(succ.as_str()) {
                        if succ_scc != scc_idx {
                            out_edges.push((scc_idx, succ_scc));
                        }
                    }
                }
            }
        }
        out_edges.sort_unstable();
        out_edges.dedup();
        for (a, b) in out_edges {
            mix(a as u64);
            mix(b as u64);
        }
    }

    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_noreturn_annotations() {
        let mut graph = BTreeMap::new();
        graph.insert(
            1,
            AstNode {
                kind: IrNodeKind::MethodDef,
                node_type: "function_definition".to_string(),
                text: Some("__attribute__((noreturn)) void fail(int x)".to_string()),
                ..AstNode::default()
            },
        );
        let noreturn = collect_noreturn_functions(&graph);
        assert!(noreturn.contains("fail"));
    }
}
