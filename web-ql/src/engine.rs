use std::collections::{HashMap, HashSet};
use rayon::prelude::*;
use web_sitter::{CallSite, Cpg, IrNode, IrNodeKind, LiteralKind, NodeId};
use web_profiler as prof;
use crate::ast::{CmpOp, Literal, TypeExpr};
use crate::cfg::FunctionCfg;
use crate::dfg::DfgIndex;
use crate::ir::{
    AstConstraint, BindingEnv, BindingValue, CfgPredicate, CompiledClause, CompiledRule,
    DfgPredicate, FieldConstraint, MethodStep, PlanExpr, QueryPlan, RootBinding, RuleSet,
    SearchPlan,
};
use crate::finding::{Finding, FindingLocation};
use crate::taint::{CrossFileTaintCtx, EndpointRegistry, TaintEngine};

// ── Eval context ──────────────────────────────────────────────────────────────

pub struct EvalContext<'a> {
    pub cpg: &'a Cpg,
    pub dfg: &'a DfgIndex,
    pub cfg_cache: &'a HashMap<NodeId, FunctionCfg>,
    pub summaries: &'a HashMap<String, web_sitter::FunctionSummary>,
    pub registry: &'a EndpointRegistry,
    /// Compiled predicates for recursive calls
    pub predicate_plans: &'a HashMap<String, QueryPlan>,
    /// Ordered parameter names for user-defined predicates (name → [param0, param1, …]).
    pub predicate_params: &'a HashMap<String, Vec<String>>,
    /// Cross-file taint context for interprocedural DFG traversal.
    pub cross_file: Option<&'a CrossFileTaintCtx<'a>>,
}

// ── Top-level runner ──────────────────────────────────────────────────────────

pub struct RuleRunner<'a> {
    pub ctx: EvalContext<'a>,
}

impl<'a> RuleRunner<'a> {
    pub fn new(ctx: EvalContext<'a>) -> Self {
        Self { ctx }
    }

    /// Evaluate all rules against the CPG in parallel, collecting findings.
    ///
    /// Rules are independent — they share only immutable references to the CPG,
    /// DFG, and CFG caches — so rayon can evaluate them concurrently.
    pub fn run(&self, rule_set: &RuleSet) -> Vec<Finding> {
        let _span = prof::span("query.rule_eval_total");
        let lang = self.ctx.cpg.language.as_str();

        let findings: Vec<Finding> = rule_set
            .rules
            .par_iter()
            .filter(|rule| rule_applies_to_language(rule, lang))
            .flat_map(|rule| {
                let _span = prof::span("query.rule_eval");
                prof::count("rules_applied", 1);
                let mut rule_findings = Vec::new();

                for clause in &rule.clauses {
                    match clause {
                        CompiledClause::Search(plan) => {
                            let _s = prof::span("query.search_eval");
                            let matches = self.eval_search(plan);
                            prof::count("nodes_evaluated", matches.len() as u64);
                            for env in matches {
                                rule_findings.push(finding_from_env(rule, &env, self.ctx.cpg, &plan.report_vars));
                            }
                        }
                        CompiledClause::Taint(spec) => {
                            let _s = prof::span("query.taint_check");
                            prof::count("taint_checks", 1);
                            // Build a merged registry: base registry + per-CPG evaluation
                            // of any named source/sink/sanitizer plans from the rule file.
                            let merged = self.build_taint_registry(spec, rule_set);
                            let mut engine = TaintEngine::new(
                                &merged,
                                self.ctx.dfg,
                                self.ctx.cpg,
                                self.ctx.summaries,
                            );
                            if let Some(cf) = self.ctx.cross_file {
                                engine = engine.with_cross_file(cf);
                            }
                            let taint_findings = engine.run(spec);
                            for tf in taint_findings {
                                rule_findings.push(Finding {
                                    rule_id: rule.id.clone(),
                                    severity: rule.severity,
                                    message: rule.message.clone().unwrap_or_default(),
                                    tags: rule.tags.clone(),
                                    location: node_location(tf.source_node, self.ctx.cpg),
                                    matched_nodes: tf.path,
                                });
                            }
                        }
                    }
                }
                rule_findings
            })
            .collect();

        findings
    }

    // ── Taint registry builder ────────────────────────────────────────────────

    /// Build a per-scan `EndpointRegistry` that merges:
    /// 1. The base registry (registered closures, e.g. from builtin security_patterns)
    /// 2. Named source/sink/sanitizer plans from the `RuleSet`, evaluated against
    ///    the current CPG.
    ///
    /// Named plans take precedence over the base registry for the same name.
    fn build_taint_registry(
        &self,
        spec: &crate::ir::TaintSpec,
        rule_set: &RuleSet,
    ) -> EndpointRegistry {
        let mut merged = EndpointRegistry::new();

        // Helper: evaluate a SearchPlan against the current CPG, collecting all
        // node IDs from all root bindings across all matching environments.
        let eval_plan_nodes = |plan: &SearchPlan| -> Vec<NodeId> {
            let envs = self.eval_search(plan);
            let mut ids = Vec::new();
            for env in &envs {
                for binding in &plan.root_bindings {
                    if let Some(BindingValue::Node(nid)) = env.get(&binding.name) {
                        ids.push(*nid);
                    }
                }
            }
            ids.sort_unstable();
            ids.dedup();
            ids
        };

        // Resolve each source endpoint: prefer named plan over base registry.
        for src_ref in &spec.sources {
            if let Some(plan) = rule_set.source_plans.get(&src_ref.name) {
                let nodes = eval_plan_nodes(plan);
                merged.register_static(src_ref.name.clone(), nodes);
            } else {
                // Forward base registry entries for this name by pre-resolving them.
                let base_nodes: Vec<NodeId> = self.ctx.registry
                    .resolve(src_ref, self.ctx.cpg)
                    .into_iter()
                    .map(|r| r.node)
                    .collect();
                merged.register_static(src_ref.name.clone(), base_nodes);
            }
        }

        // Resolve each sink endpoint.
        for sink_ref in &spec.sinks {
            if let Some(plan) = rule_set.sink_plans.get(&sink_ref.name) {
                let nodes = eval_plan_nodes(plan);
                merged.register_static(sink_ref.name.clone(), nodes);
            } else {
                let base_nodes: Vec<NodeId> = self.ctx.registry
                    .resolve(sink_ref, self.ctx.cpg)
                    .into_iter()
                    .map(|r| r.node)
                    .collect();
                merged.register_static(sink_ref.name.clone(), base_nodes);
            }
        }

        // Resolve each sanitizer endpoint.
        for san_ref in &spec.sanitizers {
            if let Some(plan) = rule_set.sanitizer_plans.get(&san_ref.name) {
                let nodes = eval_plan_nodes(plan);
                merged.register_static(san_ref.name.clone(), nodes);
            } else {
                let base_nodes: Vec<NodeId> = self.ctx.registry
                    .resolve(san_ref, self.ctx.cpg)
                    .into_iter()
                    .map(|r| r.node)
                    .collect();
                merged.register_static(san_ref.name.clone(), base_nodes);
            }
        }

        merged
    }

    // ── Search clause evaluation ──────────────────────────────────────────────

    fn eval_search(&self, plan: &SearchPlan) -> Vec<BindingEnv> {
        let mut envs: Vec<BindingEnv> = vec![BindingEnv::new()];
        let last_idx = plan.root_bindings.len().saturating_sub(1);

        for (i, binding) in plan.root_bindings.iter().enumerate() {
            let is_last = i == last_idx;
            let mut next_envs = Vec::new();
            for env in &envs {
                let candidates = candidates_for_binding(self.ctx.cpg, binding);
                for node_id in candidates {
                    let mut child = env.child();
                    child.insert(binding.name.clone(), BindingValue::Node(node_id));
                    // Only evaluate the predicate once all root bindings are bound.
                    // Intermediate bindings are collected unconditionally; the plan
                    // may reference variables that haven't been added yet.
                    if !is_last || self.eval_plan(&plan.plan, &child) {
                        next_envs.push(child);
                    }
                }
            }
            envs = next_envs;
        }

        envs
    }

    // ── Plan evaluation ───────────────────────────────────────────────────────

    fn eval_plan(&self, plan: &QueryPlan, env: &BindingEnv) -> bool {
        match plan {
            QueryPlan::Literal(b) => *b,

            QueryPlan::AndAll(children) => children.iter().all(|c| self.eval_plan(c, env)),

            QueryPlan::OrAny(children) => children.iter().any(|c| self.eval_plan(c, env)),

            QueryPlan::Not(inner) => !self.eval_plan(inner, env),

            QueryPlan::Exists { var, kinds, body } => {
                let candidates = nodes_of_kinds(self.ctx.cpg, kinds);
                candidates.into_iter().any(|node_id| {
                    let mut child = env.child();
                    child.insert(var.clone(), BindingValue::Node(node_id));
                    self.eval_plan(body, &child)
                })
            }

            QueryPlan::Forall { var, kinds, body } => {
                let candidates = nodes_of_kinds(self.ctx.cpg, kinds);
                candidates.into_iter().all(|node_id| {
                    let mut child = env.child();
                    child.insert(var.clone(), BindingValue::Node(node_id));
                    self.eval_plan(body, &child)
                })
            }

            QueryPlan::LetNode { var, expr, body } => {
                match self.eval_plan_expr(expr, env) {
                    EvalValue::Node(id) => {
                        let mut child = env.child();
                        child.insert(var.clone(), BindingValue::Node(id));
                        self.eval_plan(body, &child)
                    }
                    _ => false, // binding didn't resolve to a node
                }
            }

            QueryPlan::AstConstraint(c) => self.eval_ast_constraint(c, env),

            QueryPlan::CfgPredicate(c) => self.eval_cfg_predicate(c, env),

            QueryPlan::DfgPredicate(d) => self.eval_dfg_predicate(d, env),

            QueryPlan::TaintCheck(spec) => {
                let mut engine = TaintEngine::new(
                    self.ctx.registry,
                    self.ctx.dfg,
                    self.ctx.cpg,
                    self.ctx.summaries,
                );
                if let Some(cf) = self.ctx.cross_file {
                    engine = engine.with_cross_file(cf);
                }
                !engine.run(spec).is_empty()
            }

            QueryPlan::MatchesPattern { var, ty, fields } => {
                self.eval_matches_pattern(var, ty, fields, env)
            }

            QueryPlan::PredicateCall { name, args } => {
                if let Some(pred_plan) = self.ctx.predicate_plans.get(name) {
                    // Bind positional args into a child env using the predicate's param names.
                    let param_names = self.ctx.predicate_params.get(name);
                    let mut child = env.child();
                    for (i, arg_expr) in args.iter().enumerate() {
                        let val = self.eval_plan_expr(arg_expr, env);
                        let param_name = param_names
                            .and_then(|ps| ps.get(i))
                            .map(|s| s.as_str())
                            .unwrap_or_else(|| "__arg");
                        let binding = match val {
                            EvalValue::Node(id) => BindingValue::Node(id),
                            EvalValue::Str(s) => BindingValue::Str(s),
                            EvalValue::Int(n) => BindingValue::Int(n),
                            EvalValue::Bool(b) => BindingValue::Bool(b),
                            EvalValue::Null => BindingValue::Null,
                        };
                        child.insert(param_name.to_owned(), binding);
                    }
                    // Clone the plan to satisfy borrow checker (pred_plan borrow ends before child use)
                    let plan = pred_plan.clone();
                    self.eval_plan(&plan, &child)
                } else {
                    false
                }
            }

            QueryPlan::FixpointGroup { names: _, bodies } => {
                // Guard against infinite recursion in user-defined recursive predicates.
                // We evaluate bodies and stop when no new `true` result is derived (fixed point).
                // Uses a thread-local depth counter to cap call depth.
                thread_local! {
                    static FIXPOINT_DEPTH: std::cell::Cell<u32> = std::cell::Cell::new(0);
                }
                let depth = FIXPOINT_DEPTH.with(|d| d.get());
                if depth >= 64 {
                    return false; // recursion cap
                }
                FIXPOINT_DEPTH.with(|d| d.set(depth + 1));
                let result = bodies.iter().any(|b| self.eval_plan(b, env));
                FIXPOINT_DEPTH.with(|d| d.set(depth));
                result
            }
        }
    }

    // ── AST constraint ────────────────────────────────────────────────────────

    fn eval_ast_constraint(&self, c: &AstConstraint, env: &BindingEnv) -> bool {
        let lhs = self.eval_plan_expr(&c.lhs, env);
        let rhs = self.eval_plan_expr(&c.rhs, env);
        compare_values(&lhs, c.op, &rhs)
    }

    // ── CFG predicates ────────────────────────────────────────────────────────

    fn eval_cfg_predicate(&self, pred: &CfgPredicate, env: &BindingEnv) -> bool {
        match pred {
            CfgPredicate::Dominates { a, b } => {
                let (Some(na), Some(nb)) = (env.get_node(a), env.get_node(b)) else {
                    return false;
                };
                self.with_cfg_for_node(na, |cfg| cfg.node_dominates(na, nb))
            }
            CfgPredicate::PostDominates { a, b } => {
                let (Some(na), Some(nb)) = (env.get_node(a), env.get_node(b)) else {
                    return false;
                };
                self.with_cfg_for_node(na, |cfg| cfg.node_post_dominates(na, nb))
            }
            CfgPredicate::SameBlock { a, b } => {
                let (Some(na), Some(nb)) = (env.get_node(a), env.get_node(b)) else {
                    return false;
                };
                self.with_cfg_for_node(na, |cfg| cfg.same_block(na, nb))
            }
            CfgPredicate::CfgReaches { a, b } => {
                let (Some(na), Some(nb)) = (env.get_node(a), env.get_node(b)) else {
                    return false;
                };
                self.with_cfg_for_node(na, |cfg| cfg.node_reaches(na, nb))
            }
            CfgPredicate::InLoop { node } => {
                let Some(n) = env.get_node(node) else { return false };
                self.with_cfg_for_node(n, |cfg| cfg.node_in_loop(n))
            }
            CfgPredicate::InExceptionPath { node } => {
                let Some(n) = env.get_node(node) else { return false };
                self.with_cfg_for_node(n, |cfg| cfg.node_in_exception_path(n))
            }
            CfgPredicate::CfgReachableWithout { from, to, barrier } => {
                let (Some(nf), Some(nt), Some(nb)) =
                    (env.get_node(from), env.get_node(to), env.get_node(barrier))
                else {
                    return false;
                };
                self.with_cfg_for_node(nf, |cfg| cfg.node_cfg_reaches_without(nf, nt, nb))
            }
            CfgPredicate::SameFunction { a, b } => {
                let (Some(na), Some(nb)) = (env.get_node(a), env.get_node(b)) else {
                    return false;
                };
                let fn_a = self.ctx.cpg.ast.get(&na).and_then(|n| n.function_id);
                let fn_b = self.ctx.cpg.ast.get(&nb).and_then(|n| n.function_id);
                fn_a.is_some() && fn_a == fn_b
            }
            CfgPredicate::LoopHasNoExit { node } => {
                let Some(n) = env.get_node(node) else { return false };
                self.with_cfg_for_node(n, |cfg| cfg.node_loop_has_no_exit(n))
            }
        }
    }

    /// Run `f` with the `FunctionCfg` of the function that owns `node`.
    fn with_cfg_for_node<F: FnOnce(&FunctionCfg) -> bool>(&self, node: NodeId, f: F) -> bool {
        let Some(ir_node) = self.ctx.cpg.ast.get(&node) else { return false };
        let Some(fn_id) = ir_node.function_id else { return false };
        let Some(cfg) = self.ctx.cfg_cache.get(&fn_id) else { return false };
        f(cfg)
    }

    // ── DFG predicates ────────────────────────────────────────────────────────

    fn eval_dfg_predicate(&self, pred: &DfgPredicate, env: &BindingEnv) -> bool {
        match pred {
            DfgPredicate::DirectFlow { from, to } => {
                let (Some(nf), Some(nt)) = (env.get_node(from), env.get_node(to)) else {
                    return false;
                };
                self.ctx.dfg.direct_flow(nf, nt)
            }
            DfgPredicate::ReachesFlow { from, to } => {
                let (Some(nf), Some(nt)) = (env.get_node(from), env.get_node(to)) else {
                    return false;
                };
                self.ctx.dfg.reaches(nf, nt)
            }
            DfgPredicate::ReachesWithBarrier { from, to, barrier_kinds } => {
                let (Some(nf), Some(nt)) = (env.get_node(from), env.get_node(to)) else {
                    return false;
                };
                self.ctx.dfg.reaches_with_barrier(nf, nt, barrier_kinds, self.ctx.cpg)
            }
            DfgPredicate::DfgDef { var_name, node } => {
                let Some(n) = env.get_node(node) else { return false };
                // var_name is a literal variable name in the DFG, not a query variable
                self.ctx.dfg.defines_var(n, var_name)
            }
            DfgPredicate::DfgUse { var_name, node } => {
                let Some(n) = env.get_node(node) else { return false };
                self.ctx.dfg.uses_var(n, var_name)
            }
        }
    }

    // ── Pattern matching ──────────────────────────────────────────────────────

    fn eval_matches_pattern(
        &self,
        var: &str,
        ty: &TypeExpr,
        fields: &[FieldConstraint],
        env: &BindingEnv,
    ) -> bool {
        let Some(node_id) = env.get_node(var) else { return false };
        let Some(node) = self.ctx.cpg.ast.get(&node_id) else { return false };

        // Check type matches — NodeType uses raw string comparison against node_type field
        match ty {
            TypeExpr::NodeType(raw) => {
                if node.node_type != raw.to_lowercase() && node.node_type != *raw {
                    return false;
                }
            }
            _ => {
                if let Some(kinds) = crate::types::expand_type(ty) {
                    if !kinds.contains(&node.kind) {
                        return false;
                    }
                }
                // Named types pass kind-check at planning time; skip at runtime
            }
        }

        // Check each field constraint
        for fc in fields {
            let field_val = self.extract_field(node, &fc.field, node_id);
            let constraint_val = self.eval_plan_expr(&fc.constraint, env);
            if !compare_values(&field_val, CmpOp::Eq, &constraint_val) {
                return false;
            }
        }

        true
    }

    fn extract_field(&self, node: &IrNode, field: &str, node_id: NodeId) -> EvalValue {
        match field {
            "name" => node.name.as_deref().map(|s| EvalValue::Str(s.to_owned())).unwrap_or(EvalValue::Null),
            "text" => node.text.as_deref().map(|s| EvalValue::Str(s.to_owned())).unwrap_or(EvalValue::Null),
            "raw_kind" => EvalValue::Str(node.node_type.clone()),
            "lit_kind" => node
                .lit_kind
                .as_ref()
                .map(|k| EvalValue::Str(lit_kind_str(k).to_owned()))
                .unwrap_or(EvalValue::Null),
            "namespace" => node.namespace.as_deref().map(|s| EvalValue::Str(s.to_owned())).unwrap_or(EvalValue::Null),
            "visibility" => node.visibility.as_deref().map(|s| EvalValue::Str(s.to_owned())).unwrap_or(EvalValue::Null),
            "line" => EvalValue::Int(node.line as i64),
            "end_line" => EvalValue::Int(node.end_line as i64),
            _ => {
                let _ = node_id;
                EvalValue::Null
            }
        }
    }

    // ── Plan expression evaluation ────────────────────────────────────────────

    fn eval_plan_expr(&self, expr: &PlanExpr, env: &BindingEnv) -> EvalValue {
        match expr {
            PlanExpr::Lit(lit) => eval_value_of_literal(lit),

            PlanExpr::Var(name) => match env.get(name) {
                Some(BindingValue::Node(id)) => EvalValue::Node(*id),
                Some(BindingValue::Str(s)) => EvalValue::Str(s.clone()),
                Some(BindingValue::Int(n)) => EvalValue::Int(*n),
                Some(BindingValue::Bool(b)) => EvalValue::Bool(*b),
                Some(BindingValue::Null) | None => EvalValue::Null,
                _ => EvalValue::Null,
            },

            PlanExpr::MethodChain { receiver, steps } => {
                let mut val = self.eval_plan_expr(receiver, env);
                for step in steps {
                    val = self.eval_method_step(val, step, env);
                }
                val
            }

            PlanExpr::Compare { lhs, op, rhs } => {
                let lv = self.eval_plan_expr(lhs, env);
                let rv = self.eval_plan_expr(rhs, env);
                EvalValue::Bool(compare_values(&lv, *op, &rv))
            }
        }
    }

    fn eval_method_step(
        &self,
        val: EvalValue,
        step: &MethodStep,
        env: &BindingEnv,
    ) -> EvalValue {
        let node_id = match val {
            EvalValue::Node(id) => id,
            _ => return EvalValue::Null,
        };
        let node = match self.ctx.cpg.ast.get(&node_id) {
            Some(n) => n,
            None => return EvalValue::Null,
        };

        match step.method.as_str() {
            // ── Universal node properties ─────────────────────────────────────
            "name" => node.name.as_deref().map(|s| EvalValue::Str(s.to_owned())).unwrap_or(EvalValue::Null),
            "text" => node.text.as_deref().map(|s| EvalValue::Str(s.to_owned())).unwrap_or(EvalValue::Null),
            "raw_kind" => EvalValue::Str(node.node_type.clone()),
            "namespace" => node.namespace.as_deref().map(|s| EvalValue::Str(s.to_owned())).unwrap_or(EvalValue::Null),
            "class_context" => node.class_context.as_deref().map(|s| EvalValue::Str(s.to_owned())).unwrap_or(EvalValue::Null),
            "visibility" => node.visibility.as_deref().map(|s| EvalValue::Str(s.to_owned())).unwrap_or(EvalValue::Null),
            "line" => EvalValue::Int(node.line as i64),
            "end_line" => EvalValue::Int(node.end_line as i64),
            "file" => self.ctx.cpg.source_file.as_deref().map(|s| EvalValue::Str(s.to_owned())).unwrap_or(EvalValue::Null),
            "is_some" => EvalValue::Bool(true), // node was valid if we got here
            "is_none" => EvalValue::Bool(false),

            // ── Tree navigation ───────────────────────────────────────────────
            "parent" => node.parent_id.map(EvalValue::Node).unwrap_or(EvalValue::Null),

            "function_id" => node.function_id.map(EvalValue::Node).unwrap_or(EvalValue::Null),

            "basic_block" => {
                // Returns the block ID (as an integer) for the block containing this node
                let Some(fn_id) = node.function_id else { return EvalValue::Null };
                let Some(cfg) = self.ctx.cfg_cache.get(&fn_id) else { return EvalValue::Null };
                match cfg.block_id_for_node(node_id) {
                    Some(block_id) => EvalValue::Int(block_id as i64),
                    None => EvalValue::Null,
                }
            }

            "child" => {
                let n = step
                    .args
                    .first()
                    .and_then(|a| eval_as_index(self.eval_plan_expr(a, env)))
                    .unwrap_or(0);
                node.children.get(n).copied().map(EvalValue::Node).unwrap_or(EvalValue::Null)
            }

            "ancestor" => {
                // Walk up parent_id chain, return first ancestor matching type arg
                let ty_str = step.args.first()
                    .map(|a| self.eval_plan_expr(a, env))
                    .and_then(|v| if let EvalValue::Str(s) = v { Some(s) } else { None });
                self.find_ancestor(node_id, ty_str.as_deref())
            }

            "has_ancestor" => {
                let ty_str = step.args.first()
                    .map(|a| self.eval_plan_expr(a, env))
                    .and_then(|v| if let EvalValue::Str(s) = v { Some(s) } else { None });
                EvalValue::Bool(!matches!(self.find_ancestor(node_id, ty_str.as_deref()), EvalValue::Null))
            }

            "descendant" => {
                // BFS over children, return first descendant matching type arg
                let ty_str = step.args.first()
                    .map(|a| self.eval_plan_expr(a, env))
                    .and_then(|v| if let EvalValue::Str(s) = v { Some(s) } else { None });
                self.find_descendant(node_id, ty_str.as_deref())
            }

            "has_descendant" => {
                let ty_str = step.args.first()
                    .map(|a| self.eval_plan_expr(a, env))
                    .and_then(|v| if let EvalValue::Str(s) = v { Some(s) } else { None });
                EvalValue::Bool(!matches!(self.find_descendant(node_id, ty_str.as_deref()), EvalValue::Null))
            }

            "children" => {
                // Return first child (list not representable; use child(n) for indexed access)
                node.children.first().copied().map(EvalValue::Node).unwrap_or(EvalValue::Null)
            }

            // ── Call node methods ─────────────────────────────────────────────
            "arg" => {
                let n = step
                    .args
                    .first()
                    .and_then(|a| eval_as_index(self.eval_plan_expr(a, env)))
                    .unwrap_or(0);
                node.children.get(n).copied().map(EvalValue::Node).unwrap_or(EvalValue::Null)
            }

            "arg_count" => EvalValue::Int(node.argument_count.unwrap_or(0) as i64),

            "has_arg" => {
                // has_arg(target_node) — true if target_node is in call's children
                let target = step.args.first()
                    .map(|a| self.eval_plan_expr(a, env))
                    .and_then(|v| if let EvalValue::Node(id) = v { Some(id) } else { None });
                match target {
                    Some(target_id) => EvalValue::Bool(node.children.contains(&target_id)),
                    None => EvalValue::Bool(false),
                }
            }

            "callee_name" => {
                // Simple (unqualified) callee name for this Call node.
                callee_site_for_node(self.ctx.cpg, node_id)
                    .map(|cs| EvalValue::Str(cs.callee.clone()))
                    .unwrap_or_else(|| {
                        node.name.as_deref().map(|s| EvalValue::Str(s.to_owned())).unwrap_or(EvalValue::Null)
                    })
            }

            "qualified_callee" => {
                // Fully-qualified callee name (e.g. "std::string::append", "com.example.Foo.bar").
                // Falls back to simple callee name when no qualified form is available.
                callee_site_for_node(self.ctx.cpg, node_id)
                    .map(|cs| {
                        let name = cs.qualified_callee.as_deref().unwrap_or(cs.callee.as_str());
                        EvalValue::Str(name.to_owned())
                    })
                    .unwrap_or_else(|| {
                        node.name.as_deref().map(|s| EvalValue::Str(s.to_owned())).unwrap_or(EvalValue::Null)
                    })
            }

            "callee_kind" => {
                // Returns the callee kind string for this Call node.
                callee_site_for_node(self.ctx.cpg, node_id)
                    .map(|cs| {
                        use web_sitter::FunctionKind;
                        let kind_str = match cs.callee_kind {
                            FunctionKind::Internal => "internal",
                            FunctionKind::WorkspaceLocal => "workspace_local",
                            FunctionKind::ExternalDecl => "external_decl",
                            FunctionKind::LibrarySymbol => "library",
                        };
                        EvalValue::Str(kind_str.to_owned())
                    })
                    .unwrap_or_else(|| EvalValue::Str("unknown".to_owned()))
            }

            "receiver" => {
                // The implicit receiver object (first child if it's a member access)
                node.children.first().copied().map(EvalValue::Node).unwrap_or(EvalValue::Null)
            }

            "return_value" => {
                // Treat the call node itself as the return value expression
                EvalValue::Node(node_id)
            }

            // ── MethodDef node methods ────────────────────────────────────────
            "is_constructor" => EvalValue::Bool(node.is_constructor.unwrap_or(false)),
            "is_destructor" => EvalValue::Bool(node.is_destructor.unwrap_or(false)),
            "is_virtual" => EvalValue::Bool(node.is_virtual.unwrap_or(false)),

            "return_type" => {
                node.signature.as_deref().map(|s| EvalValue::Str(s.to_owned())).unwrap_or(EvalValue::Null)
            }

            "param" => {
                // param(n) — nth parameter of a MethodDef (child at index n)
                let n = step
                    .args
                    .first()
                    .and_then(|a| eval_as_index(self.eval_plan_expr(a, env)))
                    .unwrap_or(0);
                // Parameters are children of kind ParamDef
                let params: Vec<NodeId> = node.children.iter()
                    .copied()
                    .filter(|&child_id| {
                        self.ctx.cpg.ast.get(&child_id)
                            .map_or(false, |c| c.kind == IrNodeKind::ParamDef)
                    })
                    .collect();
                params.get(n).copied().map(EvalValue::Node).unwrap_or(EvalValue::Null)
            }

            "param_count" => {
                let count = node.children.iter()
                    .filter(|&&child_id| {
                        self.ctx.cpg.ast.get(&child_id)
                            .map_or(false, |c| c.kind == IrNodeKind::ParamDef)
                    })
                    .count();
                EvalValue::Int(count as i64)
            }

            // ── Literal node methods ──────────────────────────────────────────
            "lit_kind" => node
                .lit_kind
                .as_ref()
                .map(|k| EvalValue::Str(lit_kind_str(k).to_owned()))
                .unwrap_or(EvalValue::Null),

            "string_value" => {
                // Returns the string content for String/Template literals
                match &node.lit_kind {
                    Some(LiteralKind::String) | Some(LiteralKind::Template) => {
                        node.text.as_deref().map(|s| EvalValue::Str(s.to_owned())).unwrap_or(EvalValue::Null)
                    }
                    _ => node.text.as_deref().map(|s| EvalValue::Str(s.to_owned())).unwrap_or(EvalValue::Null),
                }
            }

            "int_value" => {
                // Parse the text content as an integer
                node.text.as_deref()
                    .and_then(|s| s.parse::<i64>().ok())
                    .map(EvalValue::Int)
                    .unwrap_or(EvalValue::Null)
            }

            // ── ClassDef node methods ─────────────────────────────────────────
            "base_classes" => {
                // Return first base class name (full list not representable as scalar)
                node.base_classes.as_ref()
                    .and_then(|classes| classes.first())
                    .map(|s| EvalValue::Str(s.clone()))
                    .unwrap_or(EvalValue::Null)
            }

            "implements" => {
                // For Java-style: same as base_classes (interface list stored there)
                node.base_classes.as_ref()
                    .and_then(|classes| classes.first())
                    .map(|s| EvalValue::Str(s.clone()))
                    .unwrap_or(EvalValue::Null)
            }

            // ── Identifier node methods ───────────────────────────────────────
            "refers_to" => {
                // Returns the resolved declaration node for this Call or identifier node.
                // Uses the already-resolved callee_id from the call graph, which avoids
                // a linear scan and correctly handles qualified names.
                callee_site_for_node(self.ctx.cpg, node_id)
                    .and_then(|cs| cs.callee_id)
                    .map(EvalValue::Node)
                    .unwrap_or(EvalValue::Null)
            }

            // ── Language metadata (stub — no metadata fields on IrNode yet) ──
            "cpp_meta" | "go_meta" | "python_meta" | "java_meta"
            | "js_meta" | "ts_meta" | "rust_meta" => EvalValue::Null,

            _ => EvalValue::Null,
        }
    }

    // ── Tree-walk helpers ─────────────────────────────────────────────────────

    /// Walk up the parent_id chain from `node_id`; return the first ancestor
    /// whose `node_type` matches `ty_str` (case-insensitive). If `ty_str` is
    /// `None`, return the immediate parent.
    fn find_ancestor(&self, node_id: NodeId, ty_str: Option<&str>) -> EvalValue {
        let ty_lc = ty_str.map(|s| s.to_lowercase());
        let mut cur_id = node_id;
        let mut steps = 0usize;
        loop {
            steps += 1;
            if steps > 512 {
                break; // guard against malformed parent chains
            }
            let Some(cur) = self.ctx.cpg.ast.get(&cur_id) else { break };
            let Some(parent_id) = cur.parent_id else { break };
            if parent_id == cur_id {
                break; // self-loop guard
            }
            let Some(parent) = self.ctx.cpg.ast.get(&parent_id) else { break };
            let matches = match &ty_lc {
                None => true, // no type filter → return immediate parent
                Some(ty) => {
                    parent.node_type == *ty
                        || format!("{:?}", parent.kind).to_lowercase() == *ty
                }
            };
            if matches {
                return EvalValue::Node(parent_id);
            }
            cur_id = parent_id;
        }
        EvalValue::Null
    }

    /// BFS over children from `node_id`; return the first descendant whose
    /// `node_type` matches `ty_str`. If `ty_str` is `None`, return first child.
    fn find_descendant(&self, node_id: NodeId, ty_str: Option<&str>) -> EvalValue {
        use std::collections::VecDeque;
        let ty_lc = ty_str.map(|s| s.to_lowercase());
        let mut queue: VecDeque<NodeId> = VecDeque::new();
        let mut visited: HashSet<NodeId> = HashSet::new();
        queue.push_back(node_id);
        visited.insert(node_id);
        // Skip the root itself
        let Some(root) = self.ctx.cpg.ast.get(&node_id) else { return EvalValue::Null };
        for &child_id in &root.children {
            if visited.insert(child_id) {
                queue.push_back(child_id);
            }
        }
        while let Some(cur_id) = queue.pop_front() {
            if cur_id == node_id {
                continue;
            }
            let Some(cur) = self.ctx.cpg.ast.get(&cur_id) else { continue };
            let matches = match &ty_lc {
                None => true,
                Some(ty) => {
                    cur.node_type == *ty
                        || format!("{:?}", cur.kind).to_lowercase() == *ty
                }
            };
            if matches {
                return EvalValue::Node(cur_id);
            }
            for &child_id in &cur.children {
                if visited.insert(child_id) {
                    queue.push_back(child_id);
                }
            }
        }
        EvalValue::Null
    }
}

// ── Evaluation values ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum EvalValue {
    Node(NodeId),
    Str(String),
    Int(i64),
    Bool(bool),
    Null,
}

fn eval_value_of_literal(lit: &Literal) -> EvalValue {
    match lit {
        Literal::Int(n) => EvalValue::Int(*n),
        Literal::Bool(b) => EvalValue::Bool(*b),
        Literal::Str(s) => EvalValue::Str(s.clone()),
        Literal::Null => EvalValue::Null,
        _ => EvalValue::Null,
    }
}

fn compare_values(lhs: &EvalValue, op: CmpOp, rhs: &EvalValue) -> bool {
    match op {
        CmpOp::Eq => values_equal(lhs, rhs),
        CmpOp::Ne => !values_equal(lhs, rhs),
        CmpOp::Lt => numeric_cmp(lhs, rhs).map_or(false, |o| o < 0),
        CmpOp::Gt => numeric_cmp(lhs, rhs).map_or(false, |o| o > 0),
        CmpOp::Le => numeric_cmp(lhs, rhs).map_or(false, |o| o <= 0),
        CmpOp::Ge => numeric_cmp(lhs, rhs).map_or(false, |o| o >= 0),
        CmpOp::In => match (lhs, rhs) {
            (EvalValue::Str(s), EvalValue::Str(list)) => list.contains(s.as_str()),
            _ => false,
        },
    }
}

fn values_equal(a: &EvalValue, b: &EvalValue) -> bool {
    match (a, b) {
        (EvalValue::Str(x), EvalValue::Str(y)) => x == y,
        (EvalValue::Int(x), EvalValue::Int(y)) => x == y,
        (EvalValue::Bool(x), EvalValue::Bool(y)) => x == y,
        (EvalValue::Node(x), EvalValue::Node(y)) => x == y,
        (EvalValue::Null, EvalValue::Null) => true,
        _ => false,
    }
}

fn numeric_cmp(a: &EvalValue, b: &EvalValue) -> Option<i64> {
    match (a, b) {
        (EvalValue::Int(x), EvalValue::Int(y)) => Some(x - y),
        _ => None,
    }
}

fn eval_as_index(val: EvalValue) -> Option<usize> {
    if let EvalValue::Int(i) = val { Some(i as usize) } else { None }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Find the `CallSite` record in the call graph that corresponds to the given call-expression
/// node ID. The call graph is keyed by function_def NodeId; each entry has a `calls` list
/// with `CallSite.call_site = Some(call_expr_node_id)`. This is the canonical way to look
/// up call-site metadata (callee name, qualified name, kind, resolved ID) for a Call node.
fn callee_site_for_node<'a>(cpg: &'a Cpg, call_node_id: NodeId) -> Option<&'a CallSite> {
    for entry in cpg.call_graph.values() {
        for cs in &entry.calls {
            if cs.call_site == Some(call_node_id) {
                return Some(cs);
            }
        }
    }
    None
}

/// Return candidate node IDs for a root binding, respecting NodeType raw matching.
fn candidates_for_binding(cpg: &Cpg, binding: &RootBinding) -> Vec<NodeId> {
    if !binding.kinds.is_empty() {
        return nodes_of_kinds(cpg, &binding.kinds);
    }
    // NodeType("raw_ts_kind") — filter by raw node_type string
    if let TypeExpr::NodeType(raw) = &binding.ty {
        let raw_lc = raw.to_lowercase();
        return cpg
            .ast
            .iter()
            .filter(|(_, n)| n.node_type == raw_lc || n.node_type == *raw)
            .map(|(id, _)| *id)
            .collect();
    }
    // Named / unresolved types — fall back to all nodes
    cpg.ast.keys().copied().collect()
}

fn nodes_of_kinds(cpg: &Cpg, kinds: &[IrNodeKind]) -> Vec<NodeId> {
    if kinds.is_empty() {
        return cpg.ast.keys().copied().collect();
    }
    cpg.ast
        .iter()
        .filter(|(_, n)| kinds.contains(&n.kind))
        .map(|(id, _)| *id)
        .collect()
}

fn rule_applies_to_language(rule: &CompiledRule, lang: &str) -> bool {
    let Some(langs) = &rule.languages else { return true };
    langs.iter().any(|l| l.to_string() == lang)
}

fn finding_from_env(
    rule: &CompiledRule,
    env: &BindingEnv,
    cpg: &Cpg,
    report_vars: &[String],
) -> Finding {
    let matched_nodes: Vec<NodeId> = env
        .bindings
        .values()
        .filter_map(|v| match v {
            BindingValue::Node(id) => Some(*id),
            _ => None,
        })
        .collect();

    // Use the first report_var that resolves to a Node for the primary location.
    // This gives deterministic, rule-author-controlled location anchoring.
    let primary_node = report_vars
        .iter()
        .find_map(|var| env.get_node(var))
        .or_else(|| matched_nodes.first().copied());

    let location = primary_node
        .map(|id| node_location(id, cpg))
        .unwrap_or_default();

    Finding {
        rule_id: rule.id.clone(),
        severity: rule.severity,
        message: rule.message.clone().unwrap_or_default(),
        tags: rule.tags.clone(),
        location,
        matched_nodes,
    }
}

fn node_location(node_id: NodeId, cpg: &Cpg) -> FindingLocation {
    if let Some(node) = cpg.ast.get(&node_id) {
        FindingLocation {
            file: cpg.source_file.clone().unwrap_or_default(),
            line: node.line,
            end_line: node.end_line,
            column: node.column,
            end_column: node.end_column,
        }
    } else {
        FindingLocation::default()
    }
}

fn lit_kind_str(kind: &LiteralKind) -> &'static str {
    match kind {
        LiteralKind::String => "String",
        LiteralKind::Integer => "Int",
        LiteralKind::Float => "Float",
        LiteralKind::Bool => "Bool",
        LiteralKind::Char => "Char",
        LiteralKind::Null => "Null",
        LiteralKind::Bytes => "Bytes",
        LiteralKind::Ellipsis => "Ellipsis",
        LiteralKind::Regex => "Regex",
        LiteralKind::Template => "Template",
        LiteralKind::BigInt => "BigInt",
    }
}
