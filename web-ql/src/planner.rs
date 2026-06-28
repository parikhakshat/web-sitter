use std::collections::HashMap;
use web_sitter::IrNodeKind;
use crate::ast::{
    Binding, CmpOp, Expr, ExprKind, FindExpr, Language, Literal, NamedRef, NodePattern,
    PredicateDef, PropagatorDef, RuleClause, RuleFile, SanitizerDef, SearchClause, SinkDef,
    SourceDef, TaintClause, TopLevelItem, TypeExpr,
};
use crate::ir::{
    AstConstraint, BindingValue, CompiledClause, CompiledRule, FieldConstraint, MethodStep,
    PlanExpr, QueryPlan, RootBinding, RuleSet, SearchPlan, SeedHint, StringMatcher,
    TaintEndpointRef, TaintSpec,
};
use crate::types::{check_method_on_type, expand_type};

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, thiserror::Error)]
pub enum PlanError {
    #[error("undefined predicate `{0}`")]
    UndefinedPredicate(String),
    #[error("undefined variable `{0}`")]
    UndefinedVariable(String),
    #[error("type error in `{context}`: {msg}")]
    TypeError { context: String, msg: String },
    #[error("arity mismatch calling `{name}`: expected {expected}, got {got}")]
    ArityMismatch { name: String, expected: usize, got: usize },
    #[error("unsupported feature: {0}")]
    Unsupported(String),
}

pub type PlanResult<T> = Result<T, PlanError>;

// ── Scope ─────────────────────────────────────────────────────────────────────

/// Type environment for a scope during planning.
#[derive(Debug, Clone, Default)]
struct Scope {
    vars: HashMap<String, TypeExpr>,
}

impl Scope {
    fn with_binding(mut self, name: &str, ty: TypeExpr) -> Self {
        self.vars.insert(name.to_owned(), ty);
        self
    }

    fn lookup(&self, name: &str) -> Option<&TypeExpr> {
        self.vars.get(name)
    }

    fn child_with(&self, name: &str, ty: TypeExpr) -> Self {
        let mut child = self.clone();
        child.vars.insert(name.to_owned(), ty);
        child
    }
}

// ── Named definition registry ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum DefKind {
    Predicate(PredicateDef),
    Source(SourceDef),
    Sink(SinkDef),
    Sanitizer(SanitizerDef),
    Propagator(PropagatorDef),
}

// ── Planner ───────────────────────────────────────────────────────────────────

/// Compiles a parsed `RuleFile` into a `RuleSet`.
pub struct Planner {
    defs: HashMap<String, DefKind>,
}

impl Planner {
    pub fn new() -> Self {
        Self { defs: HashMap::new() }
    }

    /// Compile a full rule file into a RuleSet.
    pub fn compile(&mut self, file: &RuleFile) -> PlanResult<RuleSet> {
        // First pass: register all named definitions
        for item in &file.items {
            match item {
                TopLevelItem::PredicateDef(p) => {
                    self.defs.insert(p.name.clone(), DefKind::Predicate(p.clone()));
                }
                TopLevelItem::SourceDef(s) => {
                    self.defs.insert(s.name.clone(), DefKind::Source(s.clone()));
                }
                TopLevelItem::SinkDef(s) => {
                    self.defs.insert(s.name.clone(), DefKind::Sink(s.clone()));
                }
                TopLevelItem::SanitizerDef(s) => {
                    self.defs.insert(s.name.clone(), DefKind::Sanitizer(s.clone()));
                }
                TopLevelItem::PropagatorDef(p) => {
                    self.defs.insert(p.name.clone(), DefKind::Propagator(p.clone()));
                }
                TopLevelItem::Rule(_) => {}
            }
        }

        // Second pass: compile rules
        let mut compiled = Vec::new();
        for item in &file.items {
            if let TopLevelItem::Rule(rule) = item {
                compiled.push(self.compile_rule(rule)?);
            }
        }

        Ok(RuleSet::new(compiled))
    }

    fn compile_rule(&self, rule: &crate::ast::Rule) -> PlanResult<CompiledRule> {
        let mut clauses = Vec::new();
        let mut seed_hints = Vec::new();

        for clause in &rule.clauses {
            match clause {
                RuleClause::Search(sc) => {
                    let (plan, hints) = self.compile_search_clause(sc)?;
                    seed_hints.extend(hints.clone());
                    clauses.push(CompiledClause::Search(plan));
                }
                RuleClause::Taint(tc) => {
                    let spec = self.compile_taint_clause(tc)?;
                    // For taint clauses, seed hints are derived from sources
                    seed_hints.push(SeedHint::AllNodes);
                    clauses.push(CompiledClause::Taint(spec));
                }
            }
        }

        Ok(CompiledRule {
            id: rule.id.clone(),
            severity: rule.severity,
            languages: rule.languages.clone(),
            tags: rule.tags.clone().unwrap_or_default(),
            message: rule.message.clone(),
            seed_hints,
            clauses,
        })
    }

    fn compile_search_clause(
        &self,
        sc: &SearchClause,
    ) -> PlanResult<(SearchPlan, Vec<SeedHint>)> {
        let mut scope = Scope::default();
        let mut root_bindings = Vec::new();

        for binding in &sc.bindings {
            let kinds = expand_type(&binding.ty).unwrap_or_default();
            let hints = hints_from_kinds(&kinds);
            scope.vars.insert(binding.name.clone(), binding.ty.clone());
            root_bindings.push(RootBinding {
                name: binding.name.clone(),
                ty: binding.ty.clone(),
                kinds,
                hints,
            });
        }

        let plan = self.compile_expr(&sc.condition, &scope)?;
        let report_vars = root_bindings.iter().map(|b| b.name.clone()).collect();
        let hints = root_bindings.iter().flat_map(|b| b.hints.clone()).collect();

        Ok((
            SearchPlan { root_bindings, plan, report_vars },
            hints,
        ))
    }

    fn compile_taint_clause(&self, tc: &TaintClause) -> PlanResult<TaintSpec> {
        let mut spec = TaintSpec::default();

        if let Some(v) = tc.require_interprocedural {
            spec.require_interprocedural = v;
        }
        if let Some(d) = tc.max_call_depth {
            spec.max_call_depth = d;
        }
        if let Some(v) = tc.require_same_function {
            spec.require_same_function = v;
        }

        let scope = Scope::default();
        for nr in &tc.sources {
            spec.sources.push(self.compile_named_ref(nr, &scope)?);
        }
        for nr in &tc.sinks {
            spec.sinks.push(self.compile_named_ref(nr, &scope)?);
        }
        for nr in &tc.sanitizers {
            spec.sanitizers.push(self.compile_named_ref(nr, &scope)?);
        }
        for nr in &tc.propagators {
            spec.propagators.push(self.compile_named_ref(nr, &scope)?);
        }

        Ok(spec)
    }

    fn compile_named_ref(&self, nr: &NamedRef, scope: &Scope) -> PlanResult<TaintEndpointRef> {
        let args = nr
            .args
            .iter()
            .map(|a| self.compile_plan_expr(a, scope))
            .collect::<PlanResult<Vec<_>>>()?;
        Ok(TaintEndpointRef { name: nr.name.clone(), args })
    }

    // ── Expression compilation ────────────────────────────────────────────────

    fn compile_expr(&self, expr: &Expr, scope: &Scope) -> PlanResult<QueryPlan> {
        match &expr.kind {
            ExprKind::Or(a, b) => Ok(QueryPlan::OrAny(vec![
                self.compile_expr(a, scope)?,
                self.compile_expr(b, scope)?,
            ])),

            ExprKind::And(a, b) => Ok(QueryPlan::AndAll(vec![
                self.compile_expr(a, scope)?,
                self.compile_expr(b, scope)?,
            ])),

            ExprKind::Not(inner) => {
                Ok(QueryPlan::Not(Box::new(self.compile_expr(inner, scope)?)))
            }

            ExprKind::Compare { lhs, op, rhs } => {
                let lhs_pe = self.compile_plan_expr(lhs, scope)?;
                let rhs_pe = self.compile_plan_expr(rhs, scope)?;
                // Type-check the method chain on the LHS
                self.typecheck_plan_expr(lhs, scope)?;
                Ok(QueryPlan::AstConstraint(AstConstraint {
                    lhs: lhs_pe,
                    op: *op,
                    rhs: rhs_pe,
                }))
            }

            ExprKind::Exists { var, ty, body } => {
                let kinds = expand_type(ty).unwrap_or_default();
                let child_scope = scope.child_with(var, ty.clone());
                let body_plan = self.compile_expr(body, &child_scope)?;
                Ok(QueryPlan::Exists {
                    var: var.clone(),
                    kinds,
                    body: Box::new(body_plan),
                })
            }

            ExprKind::Forall { var, ty, body } => {
                let kinds = expand_type(ty).unwrap_or_default();
                let child_scope = scope.child_with(var, ty.clone());
                let body_plan = self.compile_expr(body, &child_scope)?;
                Ok(QueryPlan::Forall {
                    var: var.clone(),
                    kinds,
                    body: Box::new(body_plan),
                })
            }

            ExprKind::Call { name, args } => {
                if let Some(_def) = self.defs.get(name) {
                    let arg_exprs = args
                        .iter()
                        .map(|a| self.compile_plan_expr(a, scope))
                        .collect::<PlanResult<Vec<_>>>()?;
                    Ok(QueryPlan::PredicateCall { name: name.clone(), args: arg_exprs })
                } else {
                    Err(PlanError::UndefinedPredicate(name.clone()))
                }
            }

            ExprKind::MatchesPattern { expr, pattern } => {
                self.compile_matches_pattern(expr, pattern, scope)
            }

            ExprKind::Ident(name) => {
                if scope.lookup(name).is_none() {
                    return Err(PlanError::UndefinedVariable(name.clone()));
                }
                // A bare identifier used as a boolean — treat as `name.is_some() == true`
                Ok(QueryPlan::AstConstraint(AstConstraint {
                    lhs: PlanExpr::MethodChain {
                        receiver: Box::new(PlanExpr::Var(name.clone())),
                        steps: vec![MethodStep { method: "is_some".into(), args: vec![] }],
                    },
                    op: CmpOp::Eq,
                    rhs: PlanExpr::Lit(Literal::Bool(true)),
                }))
            }

            ExprKind::Literal(lit) => Ok(QueryPlan::Literal(lit_is_truthy(lit))),

            ExprKind::Paren(inner) => self.compile_expr(inner, scope),

            ExprKind::MethodCall { .. } => {
                // A bare method call used as a boolean predicate
                let pe = self.compile_plan_expr(expr, scope)?;
                Ok(QueryPlan::AstConstraint(AstConstraint {
                    lhs: pe,
                    op: CmpOp::Eq,
                    rhs: PlanExpr::Lit(Literal::Bool(true)),
                }))
            }
        }
    }

    fn compile_matches_pattern(
        &self,
        expr: &Expr,
        pattern: &NodePattern,
        scope: &Scope,
    ) -> PlanResult<QueryPlan> {
        // The expr should be a variable reference
        let var = match &expr.kind {
            ExprKind::Ident(n) => n.clone(),
            ExprKind::MethodCall { receiver, method, args } => {
                // Allow method chains too — wrap as plan expr comparison
                let lhs = self.compile_plan_expr(expr, scope)?;
                let mut fields = Vec::new();
                for (field, constraint) in &pattern.fields {
                    fields.push(FieldConstraint {
                        field: field.clone(),
                        constraint: self.compile_plan_expr(constraint, scope)?,
                    });
                }
                // Synthesize a var name to hold the intermediate
                let _ = (receiver, method, args);
                return Ok(QueryPlan::MatchesPattern {
                    var: format!("__matches_{}", lhs_repr(&lhs)),
                    ty: pattern.ty.clone(),
                    fields,
                });
            }
            _ => return Err(PlanError::Unsupported(
                "`matches` LHS must be a variable or method chain".into(),
            )),
        };

        let mut fields = Vec::new();
        for (field, constraint) in &pattern.fields {
            fields.push(FieldConstraint {
                field: field.clone(),
                constraint: self.compile_plan_expr(constraint, scope)?,
            });
        }

        Ok(QueryPlan::MatchesPattern {
            var,
            ty: pattern.ty.clone(),
            fields,
        })
    }

    // ── Plan expression compilation ───────────────────────────────────────────

    fn compile_plan_expr(&self, expr: &Expr, scope: &Scope) -> PlanResult<PlanExpr> {
        match &expr.kind {
            ExprKind::Ident(name) => {
                if scope.lookup(name).is_none() {
                    return Err(PlanError::UndefinedVariable(name.clone()));
                }
                Ok(PlanExpr::Var(name.clone()))
            }

            ExprKind::Literal(lit) => Ok(PlanExpr::Lit(lit.clone())),

            ExprKind::MethodCall { receiver, method, args } => {
                let recv_pe = self.compile_plan_expr(receiver, scope)?;
                let arg_pes = args
                    .iter()
                    .map(|a| self.compile_plan_expr(a, scope))
                    .collect::<PlanResult<Vec<_>>>()?;

                // Flatten nested MethodChain into a single chain with appended step
                match recv_pe {
                    PlanExpr::MethodChain { receiver: inner, mut steps } => {
                        steps.push(MethodStep { method: method.clone(), args: arg_pes });
                        Ok(PlanExpr::MethodChain { receiver: inner, steps })
                    }
                    other => Ok(PlanExpr::MethodChain {
                        receiver: Box::new(other),
                        steps: vec![MethodStep { method: method.clone(), args: arg_pes }],
                    }),
                }
            }

            ExprKind::Compare { lhs, op, rhs } => Ok(PlanExpr::Compare {
                lhs: Box::new(self.compile_plan_expr(lhs, scope)?),
                op: *op,
                rhs: Box::new(self.compile_plan_expr(rhs, scope)?),
            }),

            ExprKind::Paren(inner) => self.compile_plan_expr(inner, scope),

            _ => Err(PlanError::Unsupported(
                "complex expression in value position".into(),
            )),
        }
    }

    // ── Type checking ─────────────────────────────────────────────────────────

    fn typecheck_plan_expr(&self, expr: &Expr, scope: &Scope) -> PlanResult<()> {
        match &expr.kind {
            ExprKind::MethodCall { receiver, method, .. } => {
                // Determine the receiver type from scope
                if let Some(ty) = self.infer_type(receiver, scope) {
                    check_method_on_type(method, &ty).map_err(|msg| PlanError::TypeError {
                        context: method.clone(),
                        msg,
                    })?;
                }
                self.typecheck_plan_expr(receiver, scope)
            }
            _ => Ok(()),
        }
    }

    fn infer_type<'a>(&self, expr: &'a Expr, scope: &'a Scope) -> Option<TypeExpr> {
        match &expr.kind {
            ExprKind::Ident(name) => scope.lookup(name).cloned(),
            ExprKind::MethodCall { receiver, method, .. } => {
                // Most methods return Node or String; simplified inference
                let recv_ty = self.infer_type(receiver, scope)?;
                Some(return_type_of_method(method, &recv_ty))
            }
            ExprKind::Paren(inner) => self.infer_type(inner, scope),
            _ => None,
        }
    }
}

impl Default for Planner {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn hints_from_kinds(kinds: &[IrNodeKind]) -> Vec<SeedHint> {
    if kinds.len() > 20 {
        vec![SeedHint::AllNodes]
    } else {
        kinds.iter().map(|k| SeedHint::Kind(*k)).collect()
    }
}

fn lit_is_truthy(lit: &Literal) -> bool {
    match lit {
        Literal::Bool(b) => *b,
        Literal::Null => false,
        Literal::Int(n) => *n != 0,
        _ => true,
    }
}

fn lhs_repr(pe: &PlanExpr) -> String {
    match pe {
        PlanExpr::Var(n) => n.clone(),
        PlanExpr::MethodChain { steps, .. } => {
            steps.last().map(|s| s.method.clone()).unwrap_or_default()
        }
        _ => "expr".into(),
    }
}

/// Very simplified return type inference for method chains.
fn return_type_of_method(method: &str, recv_ty: &TypeExpr) -> TypeExpr {
    match method {
        "parent" | "ancestor" | "child" | "descendant" | "receiver" | "return_value" => {
            TypeExpr::Node
        }
        "callee_name" | "qualified_callee" | "name" | "text" | "raw_kind"
        | "string_value" | "namespace" | "file" | "return_type" | "visibility" => {
            TypeExpr::Named("String".into())
        }
        "arg" | "param" => recv_ty.clone(),
        _ => TypeExpr::Node,
    }
}
