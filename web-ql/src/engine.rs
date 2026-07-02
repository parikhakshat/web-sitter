use std::collections::{HashMap, HashSet};
use rayon::prelude::*;
use web_sitter::{Cpg, IrNode, IrNodeKind, LiteralKind, NodeId};
use web_profiler as prof;
use crate::alias::AliasIndex;
use crate::ast::{CmpOp, Literal, TypeExpr};
use crate::cfg::FunctionCfg;
use crate::dfg::DfgIndex;
use crate::kind_index::KindIndex;
use crate::ir::{
    AstConstraint, BindingEnv, BindingValue, CfgPredicate, CompiledClause, CompiledRule,
    DfgPredicate, FieldConstraint, MethodStep, PlanExpr, QueryPlan, RootBinding, RuleSet,
    SearchPlan,
};
use crate::finding::{Finding, FindingLocation};
use crate::nullability::NullabilityIndex;
use crate::size_tracking::{AllocSizeIndex, SizeValue};
use crate::symbolic::SymbolicEval;
use crate::taint::{CrossFileTaintCtx, EndpointRegistry, TaintEngine};

// ── Eval context ──────────────────────────────────────────────────────────────

pub struct EvalContext<'a> {
    pub cpg: &'a Cpg,
    /// The file `cpg`/`dfg` were parsed from. Needed to address entries in
    /// `cross_file`'s workspace-wide, `NodeRef`-keyed map correctly.
    pub current_file: &'a std::path::Path,
    pub dfg: &'a DfgIndex,
    pub cfg_cache: &'a HashMap<NodeId, FunctionCfg>,
    /// Node-kind / raw-node-type / call-site index, built once per file.
    pub kind_index: &'a KindIndex,
    /// Pointer alias analysis (built from POINTS_TO edges).
    pub alias: &'a AliasIndex,
    /// Buffer / allocation size index.
    pub sizes: &'a AllocSizeIndex,
    /// Null-value propagation index.
    pub nullability: &'a NullabilityIndex,
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
                let _span = prof::span_dyn(format!("rule.{}", rule.id));
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
                                self.ctx.current_file,
                                self.ctx.summaries,
                            )
                            .with_cfg_cache(self.ctx.cfg_cache)
                            .with_sizes(self.ctx.sizes);
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

        // Resolve one endpoint ref: prefer a named plan (evaluated against the current
        // CPG) over forwarding pre-resolved base-registry entries.
        let resolve_one = |endpoint_ref: &crate::ir::TaintEndpointRef,
                            named_plans: &HashMap<String, SearchPlan>|
         -> (String, Vec<NodeId>) {
            let nodes = if let Some(plan) = named_plans.get(&endpoint_ref.name) {
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
            } else {
                self.ctx.registry
                    .resolve(endpoint_ref, self.ctx.cpg)
                    .into_iter()
                    .map(|r| r.node)
                    .collect()
            };
            (endpoint_ref.name.clone(), nodes)
        };

        // Sources, sinks, and sanitizers are fully independent of each other — and
        // each endpoint ref within a category is independent too — so resolve all
        // three categories concurrently, then merge sequentially (EndpointRegistry's
        // register_static takes &mut self).
        let (sources, (sinks, sanitizers)) = rayon::join(
            || {
                spec.sources
                    .par_iter()
                    .map(|r| resolve_one(r, &rule_set.source_plans))
                    .collect::<Vec<_>>()
            },
            || {
                rayon::join(
                    || {
                        spec.sinks
                            .par_iter()
                            .map(|r| resolve_one(r, &rule_set.sink_plans))
                            .collect::<Vec<_>>()
                    },
                    || {
                        spec.sanitizers
                            .par_iter()
                            .map(|r| resolve_one(r, &rule_set.sanitizer_plans))
                            .collect::<Vec<_>>()
                    },
                )
            },
        );

        for (name, nodes) in sources.into_iter().chain(sinks).chain(sanitizers) {
            merged.register_static(name, nodes);
        }

        // `merged` only has statically pre-resolved source/sink/sanitizer node
        // lists so far — it has no propagator closures at all, which would
        // silently drop both any rule-declared `propagators:` reference AND
        // the default per-language STDLIB propagators applied in
        // `TaintEngine::run`. Carry the base registry's propagators over.
        merged.merge_propagators_from(self.ctx.registry);

        merged
    }

    // ── Search clause evaluation ──────────────────────────────────────────────

    fn eval_search(&self, plan: &SearchPlan) -> Vec<BindingEnv> {
        // Multi-root patterns (e.g. `find outer: Conditional, inner: Conditional
        // where outer.has_descendant(inner.id())`) evaluate a cross product of
        // candidate nodes per binding, so the work is O(product of candidate
        // counts) — quadratic or worse for patterns with two or more root
        // bindings over a common, high-population kind. A single file with a
        // large candidate set can dominate wall time on one thread while every
        // other (file, rule) task sits idle, since parallelism elsewhere is only
        // per-file / per-rule. Once the cross product for a binding step is large
        // enough to be worth the dispatch overhead, evaluate it in parallel so
        // rayon's work-stealing pool can pull other threads into this one rule.
        const PARALLEL_THRESHOLD: usize = 64;

        let mut envs: Vec<BindingEnv> = vec![BindingEnv::new()];
        let last_idx = plan.root_bindings.len().saturating_sub(1);

        for (i, binding) in plan.root_bindings.iter().enumerate() {
            let is_last = i == last_idx;
            let candidates = candidates_for_binding(self.ctx.kind_index, binding);

            envs = if envs.len().saturating_mul(candidates.len()) >= PARALLEL_THRESHOLD {
                envs.par_iter()
                    .flat_map_iter(|env| {
                        candidates.iter().filter_map(move |&node_id| {
                            let mut child = env.child();
                            child.insert(binding.name.clone(), BindingValue::Node(node_id));
                            // Only evaluate the predicate once all root bindings are bound.
                            // Intermediate bindings are collected unconditionally; the plan
                            // may reference variables that haven't been added yet.
                            (!is_last || self.eval_plan(&plan.plan, &child)).then_some(child)
                        })
                    })
                    .collect()
            } else {
                let mut next_envs = Vec::new();
                for env in &envs {
                    for &node_id in &candidates {
                        let mut child = env.child();
                        child.insert(binding.name.clone(), BindingValue::Node(node_id));
                        if !is_last || self.eval_plan(&plan.plan, &child) {
                            next_envs.push(child);
                        }
                    }
                }
                next_envs
            };
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
                let candidates = self.ctx.kind_index.nodes_of_kinds(kinds);
                candidates.into_iter().any(|node_id| {
                    let mut child = env.child();
                    child.insert(var.clone(), BindingValue::Node(node_id));
                    self.eval_plan(body, &child)
                })
            }

            QueryPlan::Forall { var, kinds, body } => {
                let candidates = self.ctx.kind_index.nodes_of_kinds(kinds);
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
                    self.ctx.current_file,
                    self.ctx.summaries,
                )
                .with_cfg_cache(self.ctx.cfg_cache)
                .with_sizes(self.ctx.sizes);
                if let Some(cf) = self.ctx.cross_file {
                    engine = engine.with_cross_file(cf);
                }
                !engine.run(spec).is_empty()
            }

            QueryPlan::MatchesPattern { expr, ty, fields } => {
                self.eval_matches_pattern(expr, ty, fields, env)
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
                            EvalValue::Null | EvalValue::MetaNode(..) | EvalValue::List(..) | EvalValue::Regex(..) => BindingValue::Null,
                        };
                        child.insert(param_name.to_owned(), binding);
                    }
                    // `pred_plan` borrows from `self.ctx.predicate_plans: &'a HashMap<...>`,
                    // an externally-owned reference with its own lifetime 'a — not a borrow
                    // of `self` itself — so it can be passed straight into the recursive
                    // `eval_plan` call without cloning the whole QueryPlan subtree on every
                    // predicate call (recursive predicates used to pay this on every level).
                    self.eval_plan(pred_plan, &child)
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
                let cpg = self.ctx.cpg;
                self.with_cfg_for_node(n, |cfg| cfg.node_loop_has_no_exit(n, cpg))
            }

            // ── Symbolic / path-sensitive CFG predicates ──────────────────────
            CfgPredicate::CfgReachesFeasible { a, b } => {
                let (Some(na), Some(nb)) = (env.get_node(a), env.get_node(b)) else {
                    return false;
                };
                let Some(ir) = self.ctx.cpg.ast.get(&na) else { return false };
                let Some(fn_id) = ir.function_id else { return false };
                let Some(cfg) = self.ctx.cfg_cache.get(&fn_id) else { return false };
                cfg.feasible_reaches(na, nb, self.ctx.cpg)
            }

            CfgPredicate::GuardEvalTrue { node } => {
                let Some(n) = env.get_node(node) else { return false };
                guard_const_eval(self.ctx.cpg, n) == Some(true)
            }

            CfgPredicate::GuardEvalFalse { node } => {
                let Some(n) = env.get_node(node) else { return false };
                guard_const_eval(self.ctx.cpg, n) == Some(false)
            }

            CfgPredicate::InDeadBranch { node } => {
                let Some(n) = env.get_node(node) else { return false };
                self.with_cfg_for_node(n, |cfg| cfg.node_in_dead_branch(n, self.ctx.cpg))
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
                if self.ctx.dfg.direct_flow(nf, nt) {
                    return true;
                }
                // Subtree extension: any descendant of `from` has a direct DFG edge
                // to any descendant of `to`. Handles LocalDef→LocalDef patterns where
                // the CPG's DFG edges go between identifier children, not declaration nodes.
                let from_sub = ast_subtree(self.ctx.cpg, nf);
                let to_sub = ast_subtree(self.ctx.cpg, nt);
                from_sub.iter().any(|&f| {
                    if let Some(succs) = self.ctx.dfg.forward.get(&f) {
                        succs.iter().any(|s| to_sub.contains(s) && *s != nf)
                    } else {
                        false
                    }
                })
            }
            DfgPredicate::ReachesFlow { from, to } => {
                let (Some(nf), Some(nt)) = (env.get_node(from), env.get_node(to)) else {
                    return false;
                };
                if self.ctx.dfg.reaches(nf, nt) {
                    return true;
                }
                // Subtree extension: check if any node reachable from any descendant
                // of `from` can reach any descendant of `to`.
                // This enables Call.dfg_reaches(Call) patterns where the DFG path goes
                // through intermediate identifier/argument nodes that are AST-children
                // of the target call.
                let to_sub = ast_subtree(self.ctx.cpg, nt);
                let from_sub = ast_subtree(self.ctx.cpg, nf);
                for &f in &from_sub {
                    let reachable = self.ctx.dfg.reachable_from(f);
                    if reachable.iter().any(|r| to_sub.contains(r) && *r != nf) {
                        return true;
                    }
                }
                false
            }
            DfgPredicate::ReachesWithBarrier { from, to, barrier_kinds } => {
                let (Some(nf), Some(nt)) = (env.get_node(from), env.get_node(to)) else {
                    return false;
                };
                self.ctx.dfg.reaches_with_barrier(nf, nt, barrier_kinds, self.ctx.cpg)
            }
            DfgPredicate::DfgDef { var_name, node } => {
                let Some(n) = env.get_node(node) else { return false };
                if self.ctx.dfg.defines_var(n, var_name) {
                    return true;
                }
                // Subtree extension: any descendant of `node` defines `var_name`
                ast_subtree(self.ctx.cpg, n).iter().any(|&d| {
                    d != n && self.ctx.dfg.defines_var(d, var_name)
                })
            }
            DfgPredicate::DfgUse { var_name, node } => {
                let Some(n) = env.get_node(node) else { return false };
                if self.ctx.dfg.uses_var(n, var_name) {
                    return true;
                }
                // Subtree extension: any descendant of `node` uses `var_name`
                ast_subtree(self.ctx.cpg, n).iter().any(|&d| {
                    d != n && self.ctx.dfg.uses_var(d, var_name)
                })
            }
        }
    }

    // ── Pattern matching ──────────────────────────────────────────────────────

    fn eval_matches_pattern(
        &self,
        expr: &PlanExpr,
        ty: &TypeExpr,
        fields: &[FieldConstraint],
        env: &BindingEnv,
    ) -> bool {
        let node_id = match self.eval_plan_expr(expr, env) {
            EvalValue::Node(id) => id,
            _ => return false,
        };
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
        // A MetaNode is the result of `node.cpp_meta` (etc.); the next step accesses
        // a field on the language-specific metadata side-table.
        if let EvalValue::MetaNode(meta_id, ref ns) = val {
            return self.eval_meta_field(meta_id, ns, &step.method);
        }

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
            // `kind` returns the IrNodeKind as a PascalCase string (e.g. "Call", "Identifier").
            // This lets rules write `n.arg(0).kind == "Identifier"` to check the IR type.
            "kind" => EvalValue::Str(format!("{:?}", node.kind)),
            "namespace" => node.namespace.as_deref().map(|s| EvalValue::Str(s.to_owned())).unwrap_or(EvalValue::Null),
            "class_context" => node.class_context.as_deref().map(|s| EvalValue::Str(s.to_owned())).unwrap_or(EvalValue::Null),
            "visibility" => node.visibility.as_deref().map(|s| EvalValue::Str(s.to_owned())).unwrap_or(EvalValue::Null),
            // The literal operator token for BinaryOp/UnaryOp nodes (e.g. "/", "%", "+"),
            // so rules can match on the actual operator instead of regexing the node's
            // full source text (which also matches unrelated substrings, e.g. a "/"
            // inside a string-literal operand).
            "operator" => node.operator.as_deref().map(|s| EvalValue::Str(s.to_owned())).unwrap_or(EvalValue::Null),
            "line" => EvalValue::Int(node.line as i64),
            "end_line" => EvalValue::Int(node.end_line as i64),
            "file" => self.ctx.cpg.source_file.as_deref().map(|s| EvalValue::Str(s.to_owned())).unwrap_or(EvalValue::Null),
            "is_some" => EvalValue::Bool(true), // node was valid if we got here
            "is_none" => EvalValue::Bool(false),

            // ── Tree navigation ───────────────────────────────────────────────
            // `id()` returns the node's own identity as a Node value, so it can be
            // passed into `has_ancestor(x.id())` / `has_descendant(x.id())` to check
            // a relationship against one *specific* node, or compared with `==`/`!=`.
            "id" => EvalValue::Node(node_id),

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
                // Two overloads: `has_ancestor("type_name")` filters by type, and
                // `has_ancestor(other.id())` checks whether `other` is specifically
                // among this node's ancestors — a targeted identity check, not
                // "does any ancestor exist". These must be distinguished by the
                // evaluated argument's runtime type, since a `Node` and a `Str` are
                // semantically different queries.
                let arg = step.args.first().map(|a| self.eval_plan_expr(a, env));
                match arg {
                    Some(EvalValue::Node(target)) => {
                        EvalValue::Bool(self.ancestor_id_match(node_id, target))
                    }
                    Some(EvalValue::Str(ty)) => {
                        EvalValue::Bool(!matches!(self.find_ancestor(node_id, Some(&ty)), EvalValue::Null))
                    }
                    _ => EvalValue::Bool(!matches!(self.find_ancestor(node_id, None), EvalValue::Null)),
                }
            }

            "descendant" => {
                // BFS over children, return first descendant matching type arg
                let ty_str = step.args.first()
                    .map(|a| self.eval_plan_expr(a, env))
                    .and_then(|v| if let EvalValue::Str(s) = v { Some(s) } else { None });
                self.find_descendant(node_id, ty_str.as_deref())
            }

            "has_descendant" => {
                let arg = step.args.first().map(|a| self.eval_plan_expr(a, env));
                match arg {
                    Some(EvalValue::Node(target)) => {
                        EvalValue::Bool(self.descendant_id_match(node_id, target))
                    }
                    Some(EvalValue::Str(ty)) => {
                        EvalValue::Bool(!matches!(self.find_descendant(node_id, Some(&ty)), EvalValue::Null))
                    }
                    _ => EvalValue::Bool(!matches!(self.find_descendant(node_id, None), EvalValue::Null)),
                }
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
                // Arguments live inside an argument_list/arguments child for most
                // languages (C/C++, Java, Go, JS/TS). Find that container first.
                let arg_id = node.children.iter().find_map(|&cid| {
                    let child = self.ctx.cpg.ast.get(&cid)?;
                    if matches!(child.node_type.as_str(), "argument_list" | "arguments") {
                        child.children.get(n).copied()
                    } else {
                        None
                    }
                });
                arg_id.or_else(|| node.children.get(n).copied())
                    .map(EvalValue::Node)
                    .unwrap_or(EvalValue::Null)
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
                self.ctx.kind_index.call_site_for_node(node_id)
                    .map(|cs| EvalValue::Str(cs.callee.clone()))
                    .unwrap_or_else(|| {
                        node.name.as_deref().map(|s| EvalValue::Str(s.to_owned())).unwrap_or(EvalValue::Null)
                    })
            }

            "qualified_callee" => {
                // Fully-qualified callee name (e.g. "std::string::append", "com.example.Foo.bar").
                // Falls back to simple callee name when no qualified form is available.
                self.ctx.kind_index.call_site_for_node(node_id)
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
                self.ctx.kind_index.call_site_for_node(node_id)
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
                // param(n) — nth parameter of a MethodDef.
                // In C/C++ params are nested: function_definition →
                // function_declarator → parameter_list → parameter_declaration.
                // In Java/Go/JS/TS params sit inside formal_parameters or
                // parameter_list which IS a direct child. We descend up to two
                // container levels to collect all ParamDef nodes.
                let n = step
                    .args
                    .first()
                    .and_then(|a| eval_as_index(self.eval_plan_expr(a, env)))
                    .unwrap_or(0);
                let params = collect_param_nodes(self.ctx.cpg, node);
                params.get(n).copied().map(EvalValue::Node).unwrap_or(EvalValue::Null)
            }

            "param_count" => {
                let count = collect_param_nodes(self.ctx.cpg, node).len();
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

            // ── Symbolic / path-sensitive node methods ───────────────────────
            // Walk up the parent chain to find the nearest Conditional or Switch
            // ancestor, then return its "condition" field child.  This lets rules
            // do things like `n.branch_condition().eval_bool()` to ask "is the
            // guard that dominates n statically known to be true/false?"
            "branch_condition" => {
                find_enclosing_condition(self.ctx.cpg, node_id,
                    &[IrNodeKind::Conditional, IrNodeKind::Switch])
            }

            // Same as branch_condition but walks up to the nearest Loop ancestor.
            "loop_condition" => {
                find_enclosing_condition(self.ctx.cpg, node_id, &[IrNodeKind::Loop])
            }

            // ── Identifier node methods ───────────────────────────────────────
            "refers_to" => {
                // For a Call, use the already-resolved callee_id from the call
                // graph. For any other node (typically an Identifier used as
                // a variable reference), fall back to name-based resolution
                // against LocalDef/ParamDef/FieldDef declarations.
                self.ctx.kind_index.call_site_for_node(node_id)
                    .and_then(|cs| cs.callee_id)
                    .or_else(|| resolve_var_declaration(self.ctx.cpg, node_id, node))
                    .map(EvalValue::Node)
                    .unwrap_or(EvalValue::Null)
            }

            // ── Alias / pointer analysis ─────────────────────────────────────
            "points_to" => {
                // Returns the first POINTS_TO target for this node, or Null.
                self.ctx.alias.points_to_set(node_id)
                    .and_then(|s| s.iter().next().copied())
                    .map(EvalValue::Node)
                    .unwrap_or(EvalValue::Null)
            }

            "alias_target" => {
                // Synonym for points_to — first POINTS_TO target.
                self.ctx.alias.points_to_set(node_id)
                    .and_then(|s| s.iter().next().copied())
                    .map(EvalValue::Node)
                    .unwrap_or(EvalValue::Null)
            }

            "is_pointer" => {
                // True if this node has any outgoing POINTS_TO edges.
                EvalValue::Bool(self.ctx.alias.is_pointer(node_id))
            }

            // ── Size tracking ─────────────────────────────────────────────────
            "alloc_size" => {
                // Returns Int(n) for concrete sizes, Str(expr) for symbolic, Null if unknown.
                match self.ctx.sizes.size_of(node_id) {
                    SizeValue::Concrete(n) => EvalValue::Int(n),
                    SizeValue::Symbolic(s) => EvalValue::Str(s),
                    SizeValue::Unknown => EvalValue::Null,
                }
            }

            "has_known_size" => {
                // True only when a concrete byte count is known.
                EvalValue::Bool(self.ctx.sizes.concrete_size(node_id).is_some())
            }

            // ── Nullability ───────────────────────────────────────────────────
            "may_be_null" => {
                EvalValue::Bool(self.ctx.nullability.may_be_null(node_id))
            }

            "null_source" => {
                // Returns the original null-producing seed node, or Null.
                self.ctx.nullability.null_origin_of(node_id)
                    .map(EvalValue::Node)
                    .unwrap_or(EvalValue::Null)
            }

            // ── Symbolic / constant-folding evaluation ────────────────────────
            "eval_int" => {
                let mut se = SymbolicEval::new(self.ctx.cpg);
                match se.eval_int(node_id) {
                    Some(n) => EvalValue::Int(n),
                    None => EvalValue::Null,
                }
            }

            "eval_bool" => {
                let mut se = SymbolicEval::new(self.ctx.cpg);
                match se.eval_bool(node_id) {
                    Some(b) => EvalValue::Bool(b),
                    None => EvalValue::Null,
                }
            }

            "is_const_expr" => {
                let mut se = SymbolicEval::new(self.ctx.cpg);
                EvalValue::Bool(se.is_const(node_id))
            }

            // ── Language metadata side-table accessors ────────────────────────
            // Return a MetaNode sentinel; the next chained step resolves the field.
            "cpp_meta"    => EvalValue::MetaNode(node_id, "cpp".to_owned()),
            "go_meta"     => EvalValue::MetaNode(node_id, "go".to_owned()),
            "python_meta" => EvalValue::MetaNode(node_id, "python".to_owned()),
            "java_meta"   => EvalValue::MetaNode(node_id, "java".to_owned()),
            "js_meta"     => EvalValue::MetaNode(node_id, "js".to_owned()),
            "ts_meta"     => EvalValue::MetaNode(node_id, "ts".to_owned()),
            "rust_meta"   => EvalValue::MetaNode(node_id, "rust".to_owned()),

            _ => EvalValue::Null,
        }
    }

    // ── Tree-walk helpers ─────────────────────────────────────────────────────

    /// True if `target` appears in `node_id`'s parent_id chain. O(depth), not
    /// O(subtree) — used for `has_ancestor(other.id())` identity checks.
    fn ancestor_id_match(&self, node_id: NodeId, target: NodeId) -> bool {
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
            if parent_id == target {
                return true;
            }
            cur_id = parent_id;
        }
        false
    }

    /// True if `target` is a descendant of `node_id` — equivalent to asking
    /// whether `node_id` is an ancestor of `target`, so it reuses the same
    /// O(depth) parent-chain walk from `target` upward instead of a BFS over
    /// `node_id`'s whole subtree.
    fn descendant_id_match(&self, node_id: NodeId, target: NodeId) -> bool {
        if target == node_id {
            return false; // a node is not its own descendant
        }
        self.ancestor_id_match(target, node_id)
    }

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

    /// Resolve a single field from the language-specific metadata side-table for
    /// `node_id`. Called when `eval_method_step` receives an `EvalValue::MetaNode`.
    fn eval_meta_field(&self, node_id: NodeId, ns: &str, field: &str) -> EvalValue {
        match ns {
            "cpp" => {
                let Some(m) = self.ctx.cpg.cpp_metadata.get(&node_id) else {
                    return EvalValue::Null;
                };
                match field {
                    "class_context"      => opt_str(&m.class_context),
                    "namespace"          => opt_str(&m.namespace),
                    "visibility"         => opt_str(&m.visibility),
                    "qualified_name"     => opt_str(&m.qualified_name),
                    "is_constructor"     => EvalValue::Bool(m.is_constructor.unwrap_or(false)),
                    "is_destructor"      => EvalValue::Bool(m.is_destructor.unwrap_or(false)),
                    "is_virtual"         => EvalValue::Bool(m.is_virtual.unwrap_or(false)),
                    "is_virtual_dispatch" => EvalValue::Bool(m.is_virtual_dispatch),
                    "template_params"    => first_str(&m.template_params),
                    "base_classes"       => first_str(&m.base_classes),
                    _                    => EvalValue::Null,
                }
            }
            "go" => {
                let Some(m) = self.ctx.cpg.go_metadata.get(&node_id) else {
                    return EvalValue::Null;
                };
                match field {
                    "package_name"       => opt_str(&m.package_name),
                    "receiver_type"      => opt_str(&m.receiver_type),
                    "receiver_name"      => opt_str(&m.receiver_name),
                    "qualified_name"     => opt_str(&m.qualified_name),
                    "is_exported"        => EvalValue::Bool(m.is_exported),
                    "is_variadic"        => EvalValue::Bool(m.is_variadic),
                    "is_interface"       => EvalValue::Bool(m.is_interface),
                    "is_goroutine"       => EvalValue::Bool(m.is_goroutine),
                    "is_deferred"        => EvalValue::Bool(m.is_deferred),
                    "is_closure"         => EvalValue::Bool(m.is_closure),
                    "is_init"            => EvalValue::Bool(m.is_init),
                    "is_alias"           => EvalValue::Bool(m.is_alias),
                    "is_const"           => EvalValue::Bool(m.is_const),
                    "embedded_interfaces" => first_str(&m.embedded_interfaces),
                    "generic_type_params" => first_str(&m.generic_type_params),
                    _                    => EvalValue::Null,
                }
            }
            "python" => {
                let Some(m) = self.ctx.cpg.python_metadata.get(&node_id) else {
                    return EvalValue::Null;
                };
                match field {
                    "is_async"            => EvalValue::Bool(m.is_async),
                    "is_generator"        => EvalValue::Bool(m.is_generator),
                    "is_staticmethod"     => EvalValue::Bool(m.is_staticmethod),
                    "is_classmethod"      => EvalValue::Bool(m.is_classmethod),
                    "is_property"         => EvalValue::Bool(m.is_property),
                    "is_abstract"         => EvalValue::Bool(m.is_abstract),
                    "is_augmented"        => EvalValue::Bool(m.is_augmented),
                    "is_constructor_call" => EvalValue::Bool(m.is_constructor_call),
                    "is_super_call"       => EvalValue::Bool(m.is_super_call),
                    "is_dunder_call"      => EvalValue::Bool(m.is_dunder_call),
                    "is_yield_from"       => EvalValue::Bool(m.is_yield_from),
                    "has_star_args"       => EvalValue::Bool(m.has_star_args),
                    "has_double_star_args" => EvalValue::Bool(m.has_double_star_args),
                    "is_star_param"       => EvalValue::Bool(m.is_star_param),
                    "is_double_star_param" => EvalValue::Bool(m.is_double_star_param),
                    "is_keyword_only"     => EvalValue::Bool(m.is_keyword_only),
                    "return_annotation"   => opt_str(&m.return_annotation),
                    "annotation"          => opt_str(&m.annotation),
                    "metaclass"           => opt_str(&m.metaclass),
                    "call_receiver_text"  => opt_str(&m.call_receiver_text),
                    "decorators"          => first_str_vec(&m.decorators),
                    "closure_vars"        => first_str_vec(&m.closure_vars),
                    _                     => EvalValue::Null,
                }
            }
            "java" => {
                let Some(m) = self.ctx.cpg.java_metadata.get(&node_id) else {
                    return EvalValue::Null;
                };
                match field {
                    "package_name"          => opt_str(&m.package_name),
                    "fully_qualified_class" => opt_str(&m.fully_qualified_class),
                    "enclosing_class"       => opt_str(&m.enclosing_class),
                    "extends_type"          => opt_str(&m.extends_type),
                    "label_target"          => opt_str(&m.label_target),
                    "is_interface"          => EvalValue::Bool(m.is_interface),
                    "is_enum"               => EvalValue::Bool(m.is_enum),
                    "is_record"             => EvalValue::Bool(m.is_record),
                    "is_abstract"           => EvalValue::Bool(m.is_abstract),
                    "is_final"              => EvalValue::Bool(m.is_final),
                    "is_sealed"             => EvalValue::Bool(m.is_sealed),
                    "is_anonymous"          => EvalValue::Bool(m.is_anonymous),
                    "is_static"             => EvalValue::Bool(m.is_static),
                    "is_synchronized"       => EvalValue::Bool(m.is_synchronized),
                    "is_native"             => EvalValue::Bool(m.is_native),
                    "is_varargs"            => EvalValue::Bool(m.is_varargs),
                    "is_virtual_dispatch"   => EvalValue::Bool(m.is_virtual_dispatch),
                    "is_this_call"          => EvalValue::Bool(m.is_this_call),
                    "is_super_call"         => EvalValue::Bool(m.is_super_call),
                    "is_static_import"      => EvalValue::Bool(m.is_static_import),
                    "has_finally"           => EvalValue::Bool(m.has_finally),
                    "access_modifiers"      => first_str_vec(&m.access_modifiers),
                    "annotations"           => first_str_vec(&m.annotations),
                    "throws_types"          => first_str_vec(&m.throws_types),
                    "generic_type_params"   => first_str_vec(&m.generic_type_params),
                    "implements_types"      => first_str_vec(&m.implements_types),
                    "catch_types"           => first_str_vec(&m.catch_types),
                    _                       => EvalValue::Null,
                }
            }
            "js" => {
                let Some(m) = self.ctx.cpg.js_metadata.get(&node_id) else {
                    return EvalValue::Null;
                };
                match field {
                    "is_async"       => EvalValue::Bool(m.is_async),
                    "is_generator"   => EvalValue::Bool(m.is_generator),
                    "is_arrow"       => EvalValue::Bool(m.is_arrow),
                    "is_constructor" => EvalValue::Bool(m.is_constructor),
                    "is_getter"      => EvalValue::Bool(m.is_getter),
                    "is_setter"      => EvalValue::Bool(m.is_setter),
                    "is_static"      => EvalValue::Bool(m.is_static),
                    "is_private"     => EvalValue::Bool(m.is_private),
                    "is_delegate"    => EvalValue::Bool(m.is_delegate),
                    "is_for_of"      => EvalValue::Bool(m.is_for_of),
                    "module_kind"    => opt_str(&m.module_kind),
                    "scope_kind"     => opt_str(&m.scope_kind),
                    "class_context"  => opt_str(&m.class_context),
                    "export_kind"    => opt_str(&m.export_kind),
                    "import_source"  => opt_str(&m.import_source),
                    "decorator_names" => first_str_vec(&m.decorator_names),
                    _                => EvalValue::Null,
                }
            }
            "ts" => {
                let Some(m) = self.ctx.cpg.ts_metadata.get(&node_id) else {
                    return EvalValue::Null;
                };
                match field {
                    "is_async"               => EvalValue::Bool(m.is_async),
                    "is_abstract"            => EvalValue::Bool(m.is_abstract),
                    "is_readonly"            => EvalValue::Bool(m.is_readonly),
                    "is_optional"            => EvalValue::Bool(m.is_optional),
                    "is_definite_assignment" => EvalValue::Bool(m.is_definite_assignment),
                    "is_ambient"             => EvalValue::Bool(m.is_ambient),
                    "is_declare"             => EvalValue::Bool(m.is_declare),
                    "is_override"            => EvalValue::Bool(m.is_override),
                    "is_using"               => EvalValue::Bool(m.is_using),
                    "enum_is_const"          => EvalValue::Bool(m.enum_is_const),
                    "module_is_namespace"    => EvalValue::Bool(m.module_is_namespace),
                    "access_modifier"        => opt_str(&m.access_modifier),
                    "type_annotation"        => opt_str(&m.type_annotation),
                    "extends_type"           => opt_str(&m.extends_type),
                    "satisfies_type"         => opt_str(&m.satisfies_type),
                    "decorator_names"        => first_str_vec(&m.decorator_names),
                    "implements_types"       => first_str_vec(&m.implements_types),
                    "type_arguments"         => first_str_vec(&m.type_arguments),
                    "generic_constraints"    => m.generic_constraints.first()
                        .map(|(n, _)| EvalValue::Str(n.clone()))
                        .unwrap_or(EvalValue::Null),
                    _                        => EvalValue::Null,
                }
            }
            "rust" => {
                let Some(m) = self.ctx.cpg.rust_metadata.get(&node_id) else {
                    return EvalValue::Null;
                };
                match field {
                    "visibility"        => opt_str(&m.visibility),
                    "abi"               => opt_str(&m.abi),
                    "self_type"         => opt_str(&m.self_type),
                    "trait_type"        => opt_str(&m.trait_type),
                    "is_async"          => EvalValue::Bool(m.is_async),
                    "is_unsafe"         => EvalValue::Bool(m.is_unsafe),
                    "is_const"          => EvalValue::Bool(m.is_const),
                    "is_extern"         => EvalValue::Bool(m.is_extern),
                    "is_mut"            => EvalValue::Bool(m.is_mut),
                    "is_move_closure"   => EvalValue::Bool(m.is_move_closure),
                    "use_after_move"    => EvalValue::Bool(m.use_after_move),
                    "is_unsafe_context" => EvalValue::Bool(m.is_unsafe_context),
                    "is_no_std"         => EvalValue::Bool(m.is_no_std),
                    "derive_macros"     => first_str_vec(&m.derive_macros),
                    "lifetimes"         => first_str_vec(&m.lifetimes),
                    "generic_params"    => first_str_vec(&m.generic_params),
                    "where_clauses"     => first_str_vec(&m.where_clauses),
                    "trait_bounds"      => first_str_vec(&m.trait_bounds),
                    _                   => EvalValue::Null,
                }
            }
            _ => EvalValue::Null,
        }
    }
}

// ── Evaluation values ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum EvalValue {
    Node(NodeId),
    /// Intermediate value for language-metadata chains: `node.cpp_meta.is_virtual`.
    /// Carries the node ID and the metadata namespace tag ("cpp", "go", "python",
    /// "java", "js", "ts", "rust"). The next `eval_method_step` call resolves the
    /// actual field from the matching side-table in the CPG.
    MetaNode(NodeId, String),
    Str(String),
    Int(i64),
    Bool(bool),
    Null,
    List(Vec<EvalValue>),
    /// A compiled `/pattern/flags` regex literal, for `expr in /pattern/`.
    Regex(regex::Regex),
}

/// Compile a WQL regex literal's raw source (`/pattern/flags`, as captured by
/// the lexer including the delimiting slashes) into a `regex::Regex`.
/// `\/` is unescaped to `/` (only needed to escape the WQL delimiter inside
/// the pattern); every other backslash escape is passed through unchanged so
/// normal regex syntax (`\*`, `\d`, `\.`, character classes, etc.) works.
fn compile_wql_regex(raw: &str) -> Option<regex::Regex> {
    let body = raw.strip_prefix('/')?;
    let slash_pos = body.rfind('/')?;
    let (pattern, rest) = body.split_at(slash_pos);
    let flags = &rest[1..];
    let pattern = pattern.replace("\\/", "/");
    let mut builder = regex::RegexBuilder::new(&pattern);
    if flags.contains('i') {
        builder.case_insensitive(true);
    }
    if flags.contains('s') {
        builder.dot_matches_new_line(true);
    }
    if flags.contains('m') {
        builder.multi_line(true);
    }
    builder.build().ok()
}

/// Return the set of all node IDs in the AST subtree rooted at `root` (inclusive).
/// Used by DFG predicate subtree extensions so that `LocalDef.dfg_reaches(Call)`
/// checks flow between descendant identifier/expression nodes, not just the
/// structural container nodes (which have no DFG edges themselves).
fn ast_subtree(cpg: &Cpg, root: NodeId) -> HashSet<NodeId> {
    use std::collections::VecDeque;
    let mut visited: HashSet<NodeId> = HashSet::new();
    let mut queue: VecDeque<NodeId> = VecDeque::new();
    queue.push_back(root);
    visited.insert(root);
    while let Some(nid) = queue.pop_front() {
        if let Some(node) = cpg.ast.get(&nid) {
            for &child in &node.children {
                if visited.insert(child) {
                    queue.push_back(child);
                }
            }
        }
    }
    visited
}

fn eval_value_of_literal(lit: &Literal) -> EvalValue {
    match lit {
        Literal::Int(n) => EvalValue::Int(*n),
        Literal::Bool(b) => EvalValue::Bool(*b),
        Literal::Str(s) => EvalValue::Str(s.clone()),
        Literal::Null => EvalValue::Null,
        Literal::List(items) => EvalValue::List(items.iter().map(eval_value_of_literal).collect()),
        Literal::Regex(raw) => compile_wql_regex(raw).map(EvalValue::Regex).unwrap_or(EvalValue::Null),
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
        CmpOp::In => match rhs {
            EvalValue::List(items) => items.iter().any(|item| values_equal(lhs, item)),
            // `expr in /pattern/` — regex search against the LHS string.
            EvalValue::Regex(re) => matches!(lhs, EvalValue::Str(s) if re.is_match(s)),
            // Fall back to substring containment when the RHS is a plain string
            // (e.g. `text() in /pattern/`-style checks against a scalar), so
            // `in` still behaves sensibly outside of list-literal membership.
            EvalValue::Str(s) => matches!(lhs, EvalValue::Str(needle) if s.contains(needle.as_str())),
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

fn opt_str(s: &Option<String>) -> EvalValue {
    s.as_deref().map(|v| EvalValue::Str(v.to_owned())).unwrap_or(EvalValue::Null)
}

fn first_str(v: &Option<Vec<String>>) -> EvalValue {
    v.as_ref().and_then(|list| list.first()).map(|s| EvalValue::Str(s.clone())).unwrap_or(EvalValue::Null)
}

fn first_str_vec(v: &[String]) -> EvalValue {
    v.first().map(|s| EvalValue::Str(s.clone())).unwrap_or(EvalValue::Null)
}

// ── Symbolic / path-sensitive helpers ────────────────────────────────────────

/// Walk up the AST parent chain from `start` and return the condition child of
/// the nearest ancestor whose `kind` is in `targets` (Conditional, Loop, Switch).
/// Prefers the child whose field name is "condition"; falls back to first child.
/// Used by `.branch_condition()` and `.loop_condition()` node methods.
fn find_enclosing_condition(cpg: &Cpg, start: NodeId, targets: &[IrNodeKind]) -> EvalValue {
    let mut cur = start;
    let mut depth = 0usize;
    loop {
        depth += 1;
        if depth > 200 {
            return EvalValue::Null;
        }
        let node = match cpg.ast.get(&cur) {
            Some(n) => n,
            None => return EvalValue::Null,
        };
        if targets.contains(&node.kind) {
            // Find "condition" field child
            let cond = node.children.iter().enumerate().find_map(|(i, &cid)| {
                if node.field_names.get(i).and_then(|f| f.as_deref()) == Some("condition") {
                    Some(cid)
                } else {
                    None
                }
            }).or_else(|| node.children.first().copied());
            return cond.map(EvalValue::Node).unwrap_or(EvalValue::Null);
        }
        match node.parent_id {
            Some(p) if p != cur => cur = p,
            _ => return EvalValue::Null,
        }
    }
}

/// Symbolically evaluate the guard condition of the nearest enclosing
/// Conditional/Loop/Switch ancestor of `node_id`.
/// Returns `Some(true)` / `Some(false)` when the condition is a constant;
/// `None` when it is not constant or when no enclosing branch exists.
fn guard_const_eval(cpg: &Cpg, node_id: NodeId) -> Option<bool> {
    let cond_val = find_enclosing_condition(
        cpg,
        node_id,
        &[IrNodeKind::Conditional, IrNodeKind::Loop, IrNodeKind::Switch],
    );
    let cond_id = match cond_val {
        EvalValue::Node(id) => id,
        _ => return None,
    };
    let mut se = SymbolicEval::new(cpg);
    match se.eval(cond_id) {
        crate::symbolic::SymbolicValue::Bool(b) => Some(b),
        crate::symbolic::SymbolicValue::Int(0) => Some(false),
        crate::symbolic::SymbolicValue::Int(_) => Some(true),
        _ => None,
    }
}

/// Resolve a variable reference (an `Identifier` used as a value, e.g. an
/// argument to a call) back to the `LocalDef`/`ParamDef`/`FieldDef` node that
/// declared it, by name. Prefers a declaration in the same function; falls
/// back to any matching declaration (e.g. a global) otherwise. Name-based
/// resolution is a simplification — it does not model block-level shadowing —
/// but is sufficient for the common case of one declaration per name.
pub(crate) fn resolve_var_declaration(cpg: &Cpg, node_id: NodeId, node: &IrNode) -> Option<NodeId> {
    if node.kind != IrNodeKind::Identifier {
        return None;
    }
    let name = node.text.as_deref()?;
    let scope_fn = node.function_id;
    let mut fallback: Option<NodeId> = None;
    for (&id, n) in &cpg.ast {
        if id == node_id {
            continue;
        }
        if !matches!(n.kind, IrNodeKind::LocalDef | IrNodeKind::ParamDef | IrNodeKind::FieldDef) {
            continue;
        }
        // `.name` isn't reliably populated for every LocalDef shape (e.g. a
        // pointer declaration with an initializer, `char *p = malloc(n)`,
        // leaves it `None`) — fall back to `.text`, which several LocalDef
        // shapes (`init_declarator` in particular) populate with just the
        // declared identifier rather than the full source span.
        let decl_name = n.name.as_deref().or(n.text.as_deref());
        if decl_name != Some(name) {
            continue;
        }
        if scope_fn.is_some() && n.function_id == scope_fn {
            return Some(id);
        }
        if fallback.is_none() {
            fallback = Some(id);
        }
    }
    fallback
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Collect all `ParamDef` nodes for a function/method node, descending into
/// transparent parameter containers (`parameter_list`, `formal_parameters`,
/// `function_declarator`) so this works for all supported languages.
fn collect_param_nodes(cpg: &Cpg, fn_node: &IrNode) -> Vec<NodeId> {
    let mut params: Vec<NodeId> = Vec::new();
    for &cid in &fn_node.children {
        let child = match cpg.ast.get(&cid) { Some(c) => c, None => continue };
        if child.kind == IrNodeKind::ParamDef {
            params.push(cid);
        } else if matches!(
            child.node_type.as_str(),
            "parameter_list" | "formal_parameters" | "parameters"
        ) {
            for &gcid in &child.children {
                if cpg.ast.get(&gcid).map_or(false, |g| g.kind == IrNodeKind::ParamDef) {
                    params.push(gcid);
                }
            }
        } else if child.node_type == "function_declarator" {
            // C/C++: function_definition → function_declarator → parameter_list → params
            for &gcid in &child.children {
                if let Some(gc) = cpg.ast.get(&gcid) {
                    if gc.node_type == "parameter_list" {
                        for &ggcid in &gc.children {
                            if cpg.ast.get(&ggcid).map_or(false, |g| g.kind == IrNodeKind::ParamDef) {
                                params.push(ggcid);
                            }
                        }
                    }
                }
            }
        }
    }
    // Filter out C-style `(void)` — a nameless parameter_declaration whose only
    // non-punctuation child is `primitive_type` "void". This represents an empty
    // parameter list in C, not an actual void-typed parameter.
    params.retain(|&pid| !is_c_void_param(cpg, pid));
    params
}

/// Returns true for a `parameter_declaration` node that is the C `(void)` sentinel,
/// meaning the function takes no arguments (as opposed to an unprototyped `()`).
fn is_c_void_param(cpg: &Cpg, param_id: NodeId) -> bool {
    let Some(node) = cpg.ast.get(&param_id) else { return false };
    if node.node_type != "parameter_declaration" { return false }
    if node.name.is_some() { return false }
    let type_children: Vec<_> = node.children.iter()
        .filter_map(|&cid| cpg.ast.get(&cid))
        .filter(|c| c.node_type != "," && !c.node_type.starts_with('*'))
        .collect();
    type_children.len() == 1
        && type_children[0].node_type == "primitive_type"
        && type_children[0].text.as_deref() == Some("void")
}

/// Return candidate node IDs for a root binding, respecting NodeType raw matching.
fn candidates_for_binding(kind_index: &KindIndex, binding: &RootBinding) -> Vec<NodeId> {
    if !binding.kinds.is_empty() {
        return kind_index.nodes_of_kinds(&binding.kinds);
    }
    // NodeType("raw_ts_kind") — filter by raw node_type string
    if let TypeExpr::NodeType(raw) = &binding.ty {
        return kind_index.nodes_of_raw_type(raw);
    }
    // Named / unresolved types — fall back to all nodes
    kind_index.nodes_of_kinds(&[])
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
