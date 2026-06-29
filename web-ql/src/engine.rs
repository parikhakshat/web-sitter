use std::collections::{HashMap, HashSet};
use rayon::prelude::*;
use web_sitter::{Cpg, IrNode, IrNodeKind, LiteralKind, NodeId};
use web_profiler as prof;
use crate::ast::{CmpOp, Literal, TypeExpr};
use crate::cfg::FunctionCfg;
use crate::dfg::DfgIndex;
use crate::ir::{
    AstConstraint, BindingEnv, BindingValue, CfgPredicate, CompiledClause, CompiledRule,
    DfgPredicate, FieldConstraint, MethodStep, PlanExpr, QueryPlan, RuleSet, SearchPlan,
};
use crate::finding::{Finding, FindingLocation};
use crate::taint::{EndpointRegistry, TaintEngine};

// ── Eval context ──────────────────────────────────────────────────────────────

pub struct EvalContext<'a> {
    pub cpg: &'a Cpg,
    pub dfg: &'a DfgIndex,
    pub cfg_cache: &'a HashMap<NodeId, FunctionCfg>,
    pub summaries: &'a HashMap<String, web_sitter::FunctionSummary>,
    pub registry: &'a EndpointRegistry,
    /// Compiled predicates for recursive calls
    pub predicate_plans: &'a HashMap<String, QueryPlan>,
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
                                rule_findings.push(finding_from_env(rule, &env, self.ctx.cpg));
                            }
                        }
                        CompiledClause::Taint(spec) => {
                            let _s = prof::span("query.taint_check");
                            prof::count("taint_checks", 1);
                            let engine = TaintEngine::new(
                                self.ctx.registry,
                                self.ctx.dfg,
                                self.ctx.cpg,
                                self.ctx.summaries,
                            );
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

    // ── Search clause evaluation ──────────────────────────────────────────────

    fn eval_search(&self, plan: &SearchPlan) -> Vec<BindingEnv> {
        let mut envs: Vec<BindingEnv> = vec![BindingEnv::new()];
        let last_idx = plan.root_bindings.len().saturating_sub(1);

        for (i, binding) in plan.root_bindings.iter().enumerate() {
            let is_last = i == last_idx;
            let mut next_envs = Vec::new();
            for env in &envs {
                let candidates = nodes_of_kinds(self.ctx.cpg, &binding.kinds);
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

            QueryPlan::AstConstraint(c) => self.eval_ast_constraint(c, env),

            QueryPlan::CfgPredicate(c) => self.eval_cfg_predicate(c, env),

            QueryPlan::DfgPredicate(d) => self.eval_dfg_predicate(d, env),

            QueryPlan::TaintCheck(spec) => {
                let engine = TaintEngine::new(
                    self.ctx.registry,
                    self.ctx.dfg,
                    self.ctx.cpg,
                    self.ctx.summaries,
                );
                !engine.run(spec).is_empty()
            }

            QueryPlan::MatchesPattern { var, ty, fields } => {
                self.eval_matches_pattern(var, ty, fields, env)
            }

            QueryPlan::PredicateCall { name, args } => {
                if let Some(pred_plan) = self.ctx.predicate_plans.get(name) {
                    // Bind args positionally — simplified; full impl would map by param name
                    let _ = args;
                    self.eval_plan(pred_plan, env)
                } else {
                    false
                }
            }

            QueryPlan::FixpointGroup { names, bodies } => {
                // Semi-naive evaluation: iterate until no new facts are derived.
                // For now, evaluate once (non-recursive fallback).
                let _ = names;
                bodies.iter().any(|b| self.eval_plan(b, env))
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
                let fn_id = self.ctx.cpg.ast.get(&na).and_then(|n| n.function_id);
                if let Some(fn_id) = fn_id {
                    if let Some(cfg) = self.ctx.cfg_cache.get(&fn_id) {
                        return cfg.node_dominates(na, nb);
                    }
                }
                false
            }
            CfgPredicate::PostDominates { a: _, b: _ } => {
                // Post-dominance would require a reverse-CFG dominator tree; stub
                false
            }
            CfgPredicate::SameBlock { a, b } => {
                let (Some(na), Some(nb)) = (env.get_node(a), env.get_node(b)) else {
                    return false;
                };
                let fn_id = self.ctx.cpg.ast.get(&na).and_then(|n| n.function_id);
                if let Some(fn_id) = fn_id {
                    if let Some(cfg) = self.ctx.cfg_cache.get(&fn_id) {
                        return cfg.same_block(na, nb);
                    }
                }
                false
            }
            CfgPredicate::CfgReaches { a, b } => {
                let (Some(na), Some(nb)) = (env.get_node(a), env.get_node(b)) else {
                    return false;
                };
                let fn_id = self.ctx.cpg.ast.get(&na).and_then(|n| n.function_id);
                if let Some(fn_id) = fn_id {
                    if let Some(cfg) = self.ctx.cfg_cache.get(&fn_id) {
                        return cfg.node_reaches(na, nb);
                    }
                }
                false
            }
        }
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

        // Check type matches
        if let Some(kinds) = crate::types::expand_type(ty) {
            if !kinds.contains(&node.kind) {
                return false;
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

    fn extract_field(&self, node: &IrNode, field: &str, _node_id: NodeId) -> EvalValue {
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
            _ => EvalValue::Null,
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
            "name" => node.name.as_deref().map(|s| EvalValue::Str(s.to_owned())).unwrap_or(EvalValue::Null),
            "text" => node.text.as_deref().map(|s| EvalValue::Str(s.to_owned())).unwrap_or(EvalValue::Null),
            "raw_kind" => EvalValue::Str(node.node_type.clone()),
            "namespace" => node.namespace.as_deref().map(|s| EvalValue::Str(s.to_owned())).unwrap_or(EvalValue::Null),
            "class_context" => node.class_context.as_deref().map(|s| EvalValue::Str(s.to_owned())).unwrap_or(EvalValue::Null),
            "visibility" => node.visibility.as_deref().map(|s| EvalValue::Str(s.to_owned())).unwrap_or(EvalValue::Null),
            "line" => EvalValue::Int(node.line as i64),
            "end_line" => EvalValue::Int(node.end_line as i64),
            "file" => self.ctx.cpg.source_file.as_deref().map(|s| EvalValue::Str(s.to_owned())).unwrap_or(EvalValue::Null),
            "lit_kind" => node
                .lit_kind
                .as_ref()
                .map(|k| EvalValue::Str(lit_kind_str(k).to_owned()))
                .unwrap_or(EvalValue::Null),
            "is_constructor" => EvalValue::Bool(node.is_constructor.unwrap_or(false)),
            "is_destructor" => EvalValue::Bool(node.is_destructor.unwrap_or(false)),
            "is_virtual" => EvalValue::Bool(node.is_virtual.unwrap_or(false)),
            "is_some" => EvalValue::Bool(true), // if we got here, val was a valid node
            "is_none" => EvalValue::Bool(false),
            "parent" => {
                node.parent_id.map(EvalValue::Node).unwrap_or(EvalValue::Null)
            }
            "function_id" => {
                node.function_id.map(EvalValue::Node).unwrap_or(EvalValue::Null)
            }
            "arg" => {
                // arg(N) — Nth child of a call node
                let n = step
                    .args
                    .first()
                    .and_then(|a| {
                        if let EvalValue::Int(i) = self.eval_plan_expr(a, env) {
                            Some(i as usize)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0);
                node.children.get(n).copied().map(EvalValue::Node).unwrap_or(EvalValue::Null)
            }
            "arg_count" => EvalValue::Int(node.argument_count.unwrap_or(0) as i64),
            "child" => {
                let n = step
                    .args
                    .first()
                    .and_then(|a| {
                        if let EvalValue::Int(i) = self.eval_plan_expr(a, env) {
                            Some(i as usize)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0);
                node.children.get(n).copied().map(EvalValue::Node).unwrap_or(EvalValue::Null)
            }
            "callee_name" | "qualified_callee" => {
                self.ctx
                    .cpg
                    .call_graph
                    .get(&node_id)
                    .map(|e| EvalValue::Str(e.name.clone()))
                    .unwrap_or_else(|| {
                        node.name.as_deref().map(|s| EvalValue::Str(s.to_owned())).unwrap_or(EvalValue::Null)
                    })
            }
            "return_type" => {
                node.signature.as_deref().map(|s| EvalValue::Str(s.to_owned())).unwrap_or(EvalValue::Null)
            }
            _ => EvalValue::Null,
        }
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

// ── Helpers ───────────────────────────────────────────────────────────────────

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
) -> Finding {
    let matched_nodes: Vec<NodeId> = env
        .bindings
        .values()
        .filter_map(|v| match v {
            BindingValue::Node(id) => Some(*id),
            _ => None,
        })
        .collect();

    // Use the first matched node for location
    let location = matched_nodes
        .first()
        .copied()
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
