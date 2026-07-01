mod fixtures;
use fixtures::*;
use std::collections::HashMap;
use web_sitter::IrNodeKind;
use web_ql::{
    alias::AliasIndex,
    dfg::DfgIndex,
    engine::{EvalContext, RuleRunner},
    ir::{
        AstConstraint, CfgPredicate, CompiledClause, CompiledRule, DfgPredicate,
        MethodStep, PlanExpr, QueryPlan, RootBinding, RuleSet, SearchPlan,
    },
    ast::{CmpOp, Language, Literal, Severity, TypeExpr},
    cfg::FunctionCfg,
    kind_index::KindIndex,
    nullability::NullabilityIndex,
    size_tracking::AllocSizeIndex,
    taint::EndpointRegistry,
    finding::Finding,
    loader::compile_rules,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn empty_registry() -> EndpointRegistry {
    EndpointRegistry::new()
}

fn root_binding(name: &str, kinds: Vec<IrNodeKind>) -> RootBinding {
    RootBinding {
        name: name.to_owned(),
        ty: TypeExpr::Node,
        kinds,
        hints: vec![],
    }
}

fn search_rule(id: &str, kinds: Vec<IrNodeKind>, plan: QueryPlan) -> CompiledRule {
    CompiledRule {
        id: id.to_owned(),
        severity: Some(Severity::High),
        message: Some("Test finding".to_owned()),
        tags: vec![],
        languages: None,
        seed_hints: vec![],
        clauses: vec![CompiledClause::Search(SearchPlan {
            root_bindings: vec![root_binding("n", kinds)],
            plan,
            report_vars: vec!["n".to_owned()],
        })],
    }
}

fn run_rule(rule: CompiledRule, cpg: &web_sitter::Cpg) -> Vec<Finding> {
    let dfg = DfgIndex::build(cpg);
    let cfg_cache: HashMap<u32, FunctionCfg> = HashMap::new();
    let summaries: HashMap<String, web_sitter::FunctionSummary> = HashMap::new();
    let registry = empty_registry();
    let predicate_plans: HashMap<String, QueryPlan> = HashMap::new();
    let predicate_params: HashMap<String, Vec<String>> = HashMap::new();
    let alias = AliasIndex::build(cpg);
    let sizes = AllocSizeIndex::build(cpg);
    let kind_index = KindIndex::build(cpg);
    let nullability = NullabilityIndex::build(cpg, &kind_index);
    let ctx = EvalContext {
        cpg,
        current_file: std::path::Path::new("test.c"),
        dfg: &dfg,
        cfg_cache: &cfg_cache,
        kind_index: &kind_index,
        alias: &alias,
        sizes: &sizes,
        nullability: &nullability,
        summaries: &summaries,
        registry: &registry,
        predicate_plans: &predicate_plans,
        predicate_params: &predicate_params,
        cross_file: None,
    };
    let runner = RuleRunner::new(ctx);
    let rule_set = RuleSet::new(vec![rule]);
    runner.run(&rule_set)
}

/// Like `run_rule`, but lets the caller supply non-empty `predicate_plans` /
/// `predicate_params` to exercise `QueryPlan::PredicateCall` resolution.
fn run_rule_with_predicates(
    rule: CompiledRule,
    cpg: &web_sitter::Cpg,
    predicate_plans: HashMap<String, QueryPlan>,
    predicate_params: HashMap<String, Vec<String>>,
) -> Vec<Finding> {
    let dfg = DfgIndex::build(cpg);
    let cfg_cache: HashMap<u32, FunctionCfg> = HashMap::new();
    let summaries: HashMap<String, web_sitter::FunctionSummary> = HashMap::new();
    let registry = empty_registry();
    let alias = AliasIndex::build(cpg);
    let sizes = AllocSizeIndex::build(cpg);
    let kind_index = KindIndex::build(cpg);
    let nullability = NullabilityIndex::build(cpg, &kind_index);
    let ctx = EvalContext {
        cpg,
        current_file: std::path::Path::new("test.c"),
        dfg: &dfg,
        cfg_cache: &cfg_cache,
        kind_index: &kind_index,
        alias: &alias,
        sizes: &sizes,
        nullability: &nullability,
        summaries: &summaries,
        registry: &registry,
        predicate_plans: &predicate_plans,
        predicate_params: &predicate_params,
        cross_file: None,
    };
    let runner = RuleRunner::new(ctx);
    let rule_set = RuleSet::new(vec![rule]);
    runner.run(&rule_set)
}

// ── QueryPlan::PredicateCall ────────────────────────────────────────────────

#[test]
fn predicate_call_resolves_and_evaluates_body() {
    let (cpg, _) = simple_call_cpg();
    let mut predicate_plans = HashMap::new();
    predicate_plans.insert("always_true".to_owned(), QueryPlan::Literal(true));

    let plan = QueryPlan::PredicateCall { name: "always_true".to_owned(), args: vec![] };
    let rule = search_rule("call-pred", vec![], plan);
    let findings = run_rule_with_predicates(rule, &cpg, predicate_plans, HashMap::new());
    assert!(!findings.is_empty(), "PredicateCall to a true-body predicate should match");
}

#[test]
fn predicate_call_to_undefined_predicate_is_false() {
    let (cpg, _) = simple_call_cpg();
    let plan = QueryPlan::PredicateCall { name: "missing".to_owned(), args: vec![] };
    let rule = search_rule("call-missing-pred", vec![], plan);
    let findings = run_rule_with_predicates(rule, &cpg, HashMap::new(), HashMap::new());
    assert!(findings.is_empty(), "PredicateCall to an unresolved name should evaluate false");
}

#[test]
fn predicate_call_nested_two_levels_does_not_panic_or_misresolve() {
    // predicate `outer` calls predicate `inner`, which is Literal(true). This exercises
    // looking up `predicate_plans` while already inside a `PredicateCall` evaluation —
    // the scenario the (now-removed) per-call QueryPlan::clone() existed to "protect"
    // against. Both lookups borrow the same external `&'a HashMap`, so nested/concurrent
    // shared borrows are fine without cloning.
    let (cpg, _) = simple_call_cpg();
    let mut predicate_plans = HashMap::new();
    predicate_plans.insert("inner".to_owned(), QueryPlan::Literal(true));
    predicate_plans.insert(
        "outer".to_owned(),
        QueryPlan::PredicateCall { name: "inner".to_owned(), args: vec![] },
    );

    let plan = QueryPlan::PredicateCall { name: "outer".to_owned(), args: vec![] };
    let rule = search_rule("call-nested-pred", vec![], plan);
    let findings = run_rule_with_predicates(rule, &cpg, predicate_plans, HashMap::new());
    assert!(!findings.is_empty(), "two-level nested PredicateCall should resolve to true");
}

// ── QueryPlan::Literal ────────────────────────────────────────────────────────

#[test]
fn literal_true_always_matches() {
    let (cpg, _) = simple_call_cpg();
    let rule = search_rule("always", vec![], QueryPlan::Literal(true));
    // Literal(true) with empty kinds → iterates all nodes
    let findings = run_rule(rule, &cpg);
    assert!(!findings.is_empty(), "Literal(true) should produce findings for each node");
}

#[test]
fn literal_false_never_matches() {
    let (cpg, _) = simple_call_cpg();
    let rule = search_rule("never", vec![], QueryPlan::Literal(false));
    let findings = run_rule(rule, &cpg);
    assert!(findings.is_empty(), "Literal(false) should produce no findings");
}

// ── QueryPlan::AndAll / OrAny / Not ──────────────────────────────────────────

#[test]
fn and_all_both_true() {
    let (cpg, _) = simple_call_cpg();
    let plan = QueryPlan::AndAll(vec![QueryPlan::Literal(true), QueryPlan::Literal(true)]);
    let rule = search_rule("and-true", vec![], plan);
    let findings = run_rule(rule, &cpg);
    assert!(!findings.is_empty());
}

#[test]
fn and_all_one_false() {
    let (cpg, _) = simple_call_cpg();
    let plan = QueryPlan::AndAll(vec![QueryPlan::Literal(true), QueryPlan::Literal(false)]);
    let rule = search_rule("and-false", vec![], plan);
    let findings = run_rule(rule, &cpg);
    assert!(findings.is_empty());
}

#[test]
fn or_any_one_true() {
    let (cpg, _) = simple_call_cpg();
    let plan = QueryPlan::OrAny(vec![QueryPlan::Literal(false), QueryPlan::Literal(true)]);
    let rule = search_rule("or-true", vec![], plan);
    let findings = run_rule(rule, &cpg);
    assert!(!findings.is_empty());
}

#[test]
fn or_any_all_false() {
    let (cpg, _) = simple_call_cpg();
    let plan = QueryPlan::OrAny(vec![QueryPlan::Literal(false), QueryPlan::Literal(false)]);
    let rule = search_rule("or-false", vec![], plan);
    let findings = run_rule(rule, &cpg);
    assert!(findings.is_empty());
}

#[test]
fn not_true_becomes_false() {
    let (cpg, _) = simple_call_cpg();
    let plan = QueryPlan::Not(Box::new(QueryPlan::Literal(true)));
    let rule = search_rule("not-true", vec![], plan);
    let findings = run_rule(rule, &cpg);
    assert!(findings.is_empty());
}

#[test]
fn not_false_becomes_true() {
    let (cpg, _) = simple_call_cpg();
    let plan = QueryPlan::Not(Box::new(QueryPlan::Literal(false)));
    let rule = search_rule("not-false", vec![], plan);
    let findings = run_rule(rule, &cpg);
    assert!(!findings.is_empty());
}

// ── AstConstraint ─────────────────────────────────────────────────────────────

#[test]
fn ast_constraint_name_eq_match() {
    // Rule: find Call nodes where n.name == "func"
    let (cpg, _call_id) = simple_call_cpg();
    let plan = QueryPlan::AstConstraint(AstConstraint {
        lhs: PlanExpr::MethodChain {
            receiver: Box::new(PlanExpr::Var("n".to_owned())),
            steps: vec![web_ql::ir::MethodStep { method: "name".to_owned(), args: vec![] }],
        },
        op: CmpOp::Eq,
        rhs: PlanExpr::Lit(Literal::Str("func".to_owned())),
    });
    let rule = search_rule("name-match", vec![IrNodeKind::Call], plan);
    let findings = run_rule(rule, &cpg);
    assert_eq!(findings.len(), 1, "should match exactly one Call named 'func'");
}

#[test]
fn ast_constraint_name_eq_no_match() {
    let (cpg, _) = simple_call_cpg();
    let plan = QueryPlan::AstConstraint(AstConstraint {
        lhs: PlanExpr::MethodChain {
            receiver: Box::new(PlanExpr::Var("n".to_owned())),
            steps: vec![web_ql::ir::MethodStep { method: "name".to_owned(), args: vec![] }],
        },
        op: CmpOp::Eq,
        rhs: PlanExpr::Lit(Literal::Str("nonexistent".to_owned())),
    });
    let rule = search_rule("name-no-match", vec![IrNodeKind::Call], plan);
    let findings = run_rule(rule, &cpg);
    assert!(findings.is_empty(), "should not match wrong name");
}

#[test]
fn ast_constraint_name_ne() {
    let (cpg, _) = simple_call_cpg();
    // All Call nodes where name != "nonexistent" (should match all Calls)
    let plan = QueryPlan::AstConstraint(AstConstraint {
        lhs: PlanExpr::MethodChain {
            receiver: Box::new(PlanExpr::Var("n".to_owned())),
            steps: vec![web_ql::ir::MethodStep { method: "name".to_owned(), args: vec![] }],
        },
        op: CmpOp::Ne,
        rhs: PlanExpr::Lit(Literal::Str("nonexistent".to_owned())),
    });
    let rule = search_rule("name-ne", vec![IrNodeKind::Call], plan);
    let findings = run_rule(rule, &cpg);
    assert!(!findings.is_empty());
}

#[test]
fn ast_constraint_line_gt() {
    // All nodes where line > 0 (all nodes have line >= 1)
    let (cpg, _) = simple_call_cpg();
    let plan = QueryPlan::AstConstraint(AstConstraint {
        lhs: PlanExpr::MethodChain {
            receiver: Box::new(PlanExpr::Var("n".to_owned())),
            steps: vec![web_ql::ir::MethodStep { method: "line".to_owned(), args: vec![] }],
        },
        op: CmpOp::Gt,
        rhs: PlanExpr::Lit(Literal::Int(0)),
    });
    let rule = search_rule("line-gt", vec![], plan);
    let findings = run_rule(rule, &cpg);
    assert!(!findings.is_empty());
}

// ── Kind filtering ────────────────────────────────────────────────────────────

#[test]
fn kind_filter_call_only() {
    let (cpg, _) = simple_call_cpg();
    // Only Call nodes → should find exactly 1 Call node
    let rule = search_rule("calls", vec![IrNodeKind::Call], QueryPlan::Literal(true));
    let findings = run_rule(rule, &cpg);
    assert_eq!(findings.len(), 1);
}

#[test]
fn kind_filter_method_def_only() {
    let (cpg, _) = simple_call_cpg();
    let rule = search_rule("methods", vec![IrNodeKind::MethodDef], QueryPlan::Literal(true));
    let findings = run_rule(rule, &cpg);
    assert_eq!(findings.len(), 1);
}

#[test]
fn kind_filter_literal_none_in_cpg() {
    let (cpg, _) = simple_call_cpg();
    // No Literal nodes in simple_call_cpg
    let rule = search_rule("literals", vec![IrNodeKind::Literal], QueryPlan::Literal(true));
    let findings = run_rule(rule, &cpg);
    assert!(findings.is_empty());
}

// ── Exists / Forall ───────────────────────────────────────────────────────────

#[test]
fn exists_finds_matching_node() {
    let (cpg, _) = simple_call_cpg();
    // exists m: MethodDef where Literal(true) — there is a MethodDef
    let plan = QueryPlan::Exists {
        var: "m".to_owned(),
        kinds: vec![IrNodeKind::MethodDef],
        body: Box::new(QueryPlan::Literal(true)),
    };
    let rule = search_rule("exists-method", vec![], plan);
    let findings = run_rule(rule, &cpg);
    assert!(!findings.is_empty());
}

#[test]
fn exists_false_when_no_matching_node() {
    let (cpg, _) = simple_call_cpg();
    // exists lit: Literal — no literals → false
    let plan = QueryPlan::Exists {
        var: "lit".to_owned(),
        kinds: vec![IrNodeKind::Literal],
        body: Box::new(QueryPlan::Literal(true)),
    };
    let rule = search_rule("exists-literal", vec![], plan);
    let findings = run_rule(rule, &cpg);
    assert!(findings.is_empty());
}

#[test]
fn forall_true_when_no_nodes_of_kind() {
    let (cpg, _) = simple_call_cpg();
    // forall lit: Literal body=Literal(false) — vacuously true (no literals)
    let plan = QueryPlan::Forall {
        var: "lit".to_owned(),
        kinds: vec![IrNodeKind::Literal],
        body: Box::new(QueryPlan::Literal(false)),
    };
    let rule = search_rule("forall-vacuous", vec![], plan);
    let findings = run_rule(rule, &cpg);
    assert!(!findings.is_empty(), "vacuously true forall should produce findings");
}

// ── DFG predicate ─────────────────────────────────────────────────────────────

#[test]
fn dfg_predicate_reaches_flow_true() {
    // Two root bindings: n and m. The plan checks n reaches m transitively.
    // This tests that eval_search only evaluates the predicate after ALL
    // root bindings are bound (not after each individual binding).
    let (cpg, src, sink) = taint_flow_cpg(); // src=10 → mid=11 → sink=12
    let plan = QueryPlan::DfgPredicate(DfgPredicate::ReachesFlow {
        from: "n".to_owned(),
        to: "m".to_owned(),
    });
    let rule = CompiledRule {
        id: "dfg-reaches".to_owned(),
        severity: Some(Severity::High),
        message: Some("DFG reach".to_owned()),
        tags: vec![],
        languages: None,
        seed_hints: vec![],
        clauses: vec![CompiledClause::Search(SearchPlan {
            root_bindings: vec![root_binding("n", vec![]), root_binding("m", vec![])],
            plan,
            report_vars: vec!["n".to_owned(), "m".to_owned()],
        })],
    };
    let findings = run_rule(rule, &cpg);
    // src→mid, src→sink (transitive), mid→sink are reachable pairs → 3 findings
    assert!(!findings.is_empty(), "DFG reach with two root bindings should find reachable pairs");
    // Specifically, the source-to-sink pair must be found (both nodes in matched_nodes)
    let has_src_sink = findings.iter().any(|f| {
        f.matched_nodes.contains(&src) && f.matched_nodes.contains(&sink)
    });
    assert!(has_src_sink, "source (10) should reach sink (12) transitively");
}

#[test]
fn dfg_predicate_direct_flow() {
    // Two root bindings n and m; plan checks direct edge n→m.
    let (cpg, src, _sink) = taint_flow_cpg(); // src=10 → mid=11 → sink=12
    let plan = QueryPlan::DfgPredicate(DfgPredicate::DirectFlow {
        from: "n".to_owned(),
        to: "m".to_owned(),
    });
    let rule = CompiledRule {
        id: "dfg-direct".to_owned(),
        severity: Some(Severity::High),
        message: Some("Direct flow".to_owned()),
        tags: vec![],
        languages: None,
        seed_hints: vec![],
        clauses: vec![CompiledClause::Search(SearchPlan {
            root_bindings: vec![root_binding("n", vec![]), root_binding("m", vec![])],
            plan,
            report_vars: vec!["n".to_owned(), "m".to_owned()],
        })],
    };
    let findings = run_rule(rule, &cpg);
    // Direct edges: src(10)→mid(11) and mid(11)→sink(12) → exactly 2 direct pairs
    assert_eq!(findings.len(), 2, "exactly two direct DFG edges exist");
    // Verify src→mid is one of them (both nodes present in matched_nodes)
    let has_src_mid = findings.iter().any(|f| {
        f.matched_nodes.contains(&src) && f.matched_nodes.contains(&11)
    });
    assert!(has_src_mid, "direct edge from source (10) to mid (11) should be found");
}

// ── let binding ──────────────────────────────────────────────────────────────

#[test]
fn let_node_binds_derived_node_for_relational_predicate() {
    // CPG: call_outer (id=30) has arg call_arg (id=31); call_arg has DFG edge to sink (id=32).
    // Rule: find n: Call where let arg = n.arg(0) in arg.dfg_flows_to(sink_node)
    // with a second root binding sink_node: Call. Expect to find the pair.
    const OUTER: u32 = 30;
    const ARG: u32 = 31;
    const SINK: u32 = 32;

    let outer = make_call_node(OUTER, "free", vec![ARG]);
    let arg = make_call_node(ARG, "get_ptr", vec![]);
    let sink_node = make_call_node(SINK, "use_ptr", vec![]);

    let cpg = make_cpg_with_dfg(
        vec![(OUTER, outer), (ARG, arg), (SINK, sink_node)],
        vec![(ARG, SINK, "ptr")],
    );

    // Hand-build the plan: find n: Call, m: Call where let arg = n.arg(0) in arg.dfg_flows_to(m)
    let plan = QueryPlan::LetNode {
        var: "arg".to_owned(),
        expr: PlanExpr::MethodChain {
            receiver: Box::new(PlanExpr::Var("n".to_owned())),
            steps: vec![MethodStep {
                method: "arg".to_owned(),
                args: vec![PlanExpr::Lit(Literal::Int(0))],
            }],
        },
        body: Box::new(QueryPlan::DfgPredicate(DfgPredicate::DirectFlow {
            from: "arg".to_owned(),
            to: "m".to_owned(),
        })),
    };

    let rule = CompiledRule {
        id: "let-dfg".to_owned(),
        severity: Some(Severity::High),
        message: Some("let binding test".to_owned()),
        tags: vec![],
        languages: None,
        seed_hints: vec![],
        clauses: vec![CompiledClause::Search(SearchPlan {
            root_bindings: vec![
                root_binding("n", vec![IrNodeKind::Call]),
                root_binding("m", vec![IrNodeKind::Call]),
            ],
            plan,
            report_vars: vec!["n".to_owned(), "m".to_owned()],
        })],
    };

    let findings = run_rule(rule, &cpg);
    assert!(!findings.is_empty(), "let binding should enable arg-to-sink DFG check");
    let has_outer_sink = findings.iter().any(|f| {
        f.matched_nodes.contains(&OUTER) && f.matched_nodes.contains(&SINK)
    });
    assert!(has_outer_sink, "outer call (30) and sink (32) should be matched via let arg = n.arg(0)");
}

#[test]
fn let_node_false_when_binding_resolves_to_non_node() {
    // Binding resolves to a string (callee_name), not a node — should return false.
    let (cpg, call_id) = simple_call_cpg();
    let plan = QueryPlan::LetNode {
        var: "x".to_owned(),
        expr: PlanExpr::MethodChain {
            receiver: Box::new(PlanExpr::Var("n".to_owned())),
            steps: vec![MethodStep { method: "callee_name".to_owned(), args: vec![] }],
        },
        body: Box::new(QueryPlan::Literal(true)),
    };
    let rule = search_rule("let-non-node", vec![IrNodeKind::Call], plan);
    let findings = run_rule(rule, &cpg);
    assert!(findings.is_empty(), "let binding to a string (callee_name) should not match");
    let _ = call_id;
}

#[test]
fn let_node_compiles_from_wql() {
    // Verify the full parser → planner pipeline for let syntax.
    let src = r#"
rule "let-test" {
    severity: high
    find n: Call, m: Call where
        n.callee_name() == "free"
        and let arg = n.arg(0) in arg.dfg_reaches(m)
}
"#;
    let rs = compile_rules(src).expect("let syntax should compile");
    assert_eq!(rs.rules.len(), 1);
    assert!(!rs.rules[0].clauses.is_empty());
}

// ── Language filter ───────────────────────────────────────────────────────────

#[test]
fn language_filter_skips_wrong_language() {
    let (cpg, _) = simple_call_cpg(); // language = "python"
    let rule = CompiledRule {
        id: "rust-only".to_owned(),
        severity: None,
        message: None,
        tags: vec![],
        languages: Some(vec![Language::Rust]),
        seed_hints: vec![],
        clauses: vec![CompiledClause::Search(SearchPlan {
            root_bindings: vec![],
            plan: QueryPlan::Literal(true),
            report_vars: vec![],
        })],
    };
    let findings = run_rule(rule, &cpg);
    assert!(findings.is_empty(), "rust rule should not match python cpg");
}

#[test]
fn language_filter_matches_correct_language() {
    let (cpg, _) = simple_call_cpg(); // language = "python"
    let rule = CompiledRule {
        id: "py-rule".to_owned(),
        severity: None,
        message: None,
        tags: vec![],
        languages: Some(vec![Language::Python]),
        seed_hints: vec![],
        clauses: vec![CompiledClause::Search(SearchPlan {
            root_bindings: vec![],
            plan: QueryPlan::Literal(true),
            report_vars: vec![],
        })],
    };
    let findings = run_rule(rule, &cpg);
    // empty bindings → one empty env → one finding per node... actually
    // root_bindings empty means only 1 empty env → 1 finding from Literal(true)
    assert!(!findings.is_empty(), "python rule should match python cpg");
}

// ── Finding fields ────────────────────────────────────────────────────────────

#[test]
fn finding_has_correct_rule_id() {
    let (cpg, _) = simple_call_cpg();
    let rule = search_rule("my-rule-id", vec![IrNodeKind::Call], QueryPlan::Literal(true));
    let findings = run_rule(rule, &cpg);
    assert!(findings.iter().all(|f| f.rule_id == "my-rule-id"));
}

#[test]
fn finding_has_severity() {
    let (cpg, _) = simple_call_cpg();
    let rule = search_rule("sev-rule", vec![IrNodeKind::Call], QueryPlan::Literal(true));
    let findings = run_rule(rule, &cpg);
    assert!(!findings.is_empty());
    assert!(findings.iter().all(|f| f.severity == Some(Severity::High)));
}

#[test]
fn finding_has_message() {
    let (cpg, _) = simple_call_cpg();
    let rule = search_rule("msg-rule", vec![IrNodeKind::Call], QueryPlan::Literal(true));
    let findings = run_rule(rule, &cpg);
    assert!(!findings.is_empty());
    assert!(findings.iter().all(|f| f.message == "Test finding"));
}

#[test]
fn finding_location_has_line() {
    let (cpg, _) = simple_call_cpg();
    let rule = search_rule("loc-rule", vec![IrNodeKind::Call], QueryPlan::Literal(true));
    let findings = run_rule(rule, &cpg);
    assert!(!findings.is_empty());
    // line should be >= 1 (our make_node sets line=1)
    assert!(findings.iter().all(|f| f.location.line >= 1));
}

// ── Multiple rules in a rule set ──────────────────────────────────────────────

#[test]
fn run_multiple_rules_all_findings_collected() {
    let (cpg, _) = simple_call_cpg();
    let dfg = DfgIndex::build(&cpg);
    let cfg_cache = HashMap::new();
    let summaries = HashMap::new();
    let registry = empty_registry();
    let predicate_plans = HashMap::new();
    let predicate_params: HashMap<String, Vec<String>> = HashMap::new();
    let alias = AliasIndex::build(&cpg);
    let sizes = AllocSizeIndex::build(&cpg);
    let kind_index = KindIndex::build(&cpg);
    let nullability = NullabilityIndex::build(&cpg, &kind_index);
    let ctx = EvalContext {
        cpg: &cpg,
        current_file: std::path::Path::new("test.c"),
        dfg: &dfg,
        cfg_cache: &cfg_cache,
        kind_index: &kind_index,
        alias: &alias,
        sizes: &sizes,
        nullability: &nullability,
        summaries: &summaries,
        registry: &registry,
        predicate_plans: &predicate_plans,
        predicate_params: &predicate_params,
        cross_file: None,
    };
    let runner = RuleRunner::new(ctx);
    let rule_set = RuleSet::new(vec![
        search_rule("r1", vec![IrNodeKind::Call], QueryPlan::Literal(true)),
        search_rule("r2", vec![IrNodeKind::MethodDef], QueryPlan::Literal(true)),
    ]);
    let findings = runner.run(&rule_set);
    let r1_findings: Vec<_> = findings.iter().filter(|f| f.rule_id == "r1").collect();
    let r2_findings: Vec<_> = findings.iter().filter(|f| f.rule_id == "r2").collect();
    assert_eq!(r1_findings.len(), 1, "1 Call node");
    assert_eq!(r2_findings.len(), 1, "1 MethodDef node");
}

#[test]
fn empty_rule_set_returns_no_findings() {
    let (cpg, _) = simple_call_cpg();
    let dfg = DfgIndex::build(&cpg);
    let cfg_cache = HashMap::new();
    let summaries = HashMap::new();
    let registry = empty_registry();
    let predicate_plans = HashMap::new();
    let predicate_params: HashMap<String, Vec<String>> = HashMap::new();
    let alias = AliasIndex::build(&cpg);
    let sizes = AllocSizeIndex::build(&cpg);
    let kind_index = KindIndex::build(&cpg);
    let nullability = NullabilityIndex::build(&cpg, &kind_index);
    let ctx = EvalContext {
        cpg: &cpg,
        current_file: std::path::Path::new("test.c"),
        dfg: &dfg,
        cfg_cache: &cfg_cache,
        kind_index: &kind_index,
        alias: &alias,
        sizes: &sizes,
        nullability: &nullability,
        summaries: &summaries,
        registry: &registry,
        predicate_plans: &predicate_plans,
        predicate_params: &predicate_params,
        cross_file: None,
    };
    let runner = RuleRunner::new(ctx);
    let rule_set = RuleSet::new(vec![]);
    let findings = runner.run(&rule_set);
    assert!(findings.is_empty());
}

// ── Helper: build a runner with a real FunctionCfg cache ─────────────────────

fn run_rule_with_cfg(rule: CompiledRule, cpg: &web_sitter::Cpg, fn_id: u32) -> Vec<Finding> {
    let dfg = DfgIndex::build(cpg);
    let mut cfg_cache: HashMap<u32, FunctionCfg> = HashMap::new();
    cfg_cache.insert(fn_id, FunctionCfg::build_for_function(cpg, fn_id));
    let summaries: HashMap<String, web_sitter::FunctionSummary> = HashMap::new();
    let registry = EndpointRegistry::new();
    let predicate_plans: HashMap<String, QueryPlan> = HashMap::new();
    let predicate_params: HashMap<String, Vec<String>> = HashMap::new();
    let alias = AliasIndex::build(cpg);
    let sizes = AllocSizeIndex::build(cpg);
    let kind_index = KindIndex::build(cpg);
    let nullability = NullabilityIndex::build(cpg, &kind_index);
    let ctx = EvalContext {
        cpg,
        current_file: std::path::Path::new("test.c"),
        dfg: &dfg,
        cfg_cache: &cfg_cache,
        kind_index: &kind_index,
        alias: &alias,
        sizes: &sizes,
        nullability: &nullability,
        summaries: &summaries,
        registry: &registry,
        predicate_plans: &predicate_plans,
        predicate_params: &predicate_params,
        cross_file: None,
    };
    let runner = RuleRunner::new(ctx);
    let rule_set = RuleSet::new(vec![rule]);
    runner.run(&rule_set)
}

// ── CFG predicate: Dominates ──────────────────────────────────────────────────

#[test]
fn cfg_dominates_in_linear_cfg() {
    let (cpg, fn_id) = linear_cfg_cpg(); // FN_ID=20, N1=21 (bb0) → N2=22 (bb1) → N3=23 (bb2)
    // N1 dominates N2 (linear flow)
    let plan = QueryPlan::CfgPredicate(CfgPredicate::Dominates {
        a: "n".to_owned(),
        b: "m".to_owned(),
    });
    let rule = CompiledRule {
        id: "dominates".to_owned(),
        severity: None,
        message: None,
        tags: vec![],
        languages: None,
        seed_hints: vec![],
        clauses: vec![CompiledClause::Search(SearchPlan {
            root_bindings: vec![
                root_binding("n", vec![IrNodeKind::Assign]),
                root_binding("m", vec![IrNodeKind::Return]),
            ],
            plan,
            report_vars: vec!["n".to_owned(), "m".to_owned()],
        })],
    };
    let findings = run_rule_with_cfg(rule, &cpg, fn_id);
    assert!(!findings.is_empty(), "N1/N2 (Assign) should dominate N3 (Return)");
}

// ── CFG predicate: PostDominates ──────────────────────────────────────────────

#[test]
fn cfg_post_dominates_in_linear_cfg() {
    let (cpg, fn_id) = linear_cfg_cpg(); // N1=21, N2=22, N3=23 (exit)
    // N3 (Return in exit block) post-dominates N1 (all paths end at N3)
    let plan = QueryPlan::CfgPredicate(CfgPredicate::PostDominates {
        a: "n".to_owned(), // post-dominator
        b: "m".to_owned(), // dominated
    });
    let rule = CompiledRule {
        id: "post-dom".to_owned(),
        severity: None,
        message: None,
        tags: vec![],
        languages: None,
        seed_hints: vec![],
        clauses: vec![CompiledClause::Search(SearchPlan {
            root_bindings: vec![
                root_binding("n", vec![IrNodeKind::Return]),
                root_binding("m", vec![IrNodeKind::Assign]),
            ],
            plan,
            report_vars: vec!["n".to_owned(), "m".to_owned()],
        })],
    };
    let findings = run_rule_with_cfg(rule, &cpg, fn_id);
    assert!(!findings.is_empty(), "Return node should post-dominate Assign nodes");
}

// ── CFG predicate: SameFunction ───────────────────────────────────────────────

#[test]
fn cfg_same_function_nodes_in_same_fn() {
    let (cpg, _fn_id) = linear_cfg_cpg();
    // N1=21 and N2=22 are both in fn_id=20
    let plan = QueryPlan::CfgPredicate(CfgPredicate::SameFunction {
        a: "n".to_owned(),
        b: "m".to_owned(),
    });
    let rule = CompiledRule {
        id: "same-fn".to_owned(),
        severity: None,
        message: None,
        tags: vec![],
        languages: None,
        seed_hints: vec![],
        clauses: vec![CompiledClause::Search(SearchPlan {
            root_bindings: vec![
                root_binding("n", vec![IrNodeKind::Assign]),
                root_binding("m", vec![IrNodeKind::Return]),
            ],
            plan,
            report_vars: vec!["n".to_owned(), "m".to_owned()],
        })],
    };
    let findings = run_rule(rule, &cpg);
    assert!(!findings.is_empty(), "Assign and Return nodes share the same function_id");
}

#[test]
fn cfg_same_function_false_for_different_fns() {
    // Two separate CPGs merged: the nodes have different function_ids
    let cpg1 = make_cpg_with_ids(vec![
        (1, {
            let mut n = make_node(1, IrNodeKind::MethodDef, Some("fn1"));
            n
        }),
        (2, {
            let mut n = make_node(2, IrNodeKind::Assign, Some("x"));
            n.function_id = Some(1);
            n
        }),
        (3, {
            let mut n = make_node(3, IrNodeKind::MethodDef, Some("fn2"));
            n
        }),
        (4, {
            let mut n = make_node(4, IrNodeKind::Assign, Some("y"));
            n.function_id = Some(3);
            n
        }),
    ]);
    // Nodes 2 and 4 have different function_ids
    let plan = QueryPlan::CfgPredicate(CfgPredicate::SameFunction {
        a: "n".to_owned(),
        b: "m".to_owned(),
    });
    let rule = CompiledRule {
        id: "diff-fn".to_owned(),
        severity: None,
        message: None,
        tags: vec![],
        languages: None,
        seed_hints: vec![],
        clauses: vec![CompiledClause::Search(SearchPlan {
            root_bindings: vec![
                RootBinding { name: "n".to_owned(), ty: TypeExpr::Node, kinds: vec![IrNodeKind::Assign], hints: vec![] },
                RootBinding { name: "m".to_owned(), ty: TypeExpr::Node, kinds: vec![IrNodeKind::Assign], hints: vec![] },
            ],
            plan,
            report_vars: vec!["n".to_owned(), "m".to_owned()],
        })],
    };
    let findings = run_rule(rule, &cpg1);
    // Only same-fn pairs should match: (2,2) and (4,4) — but NOT (2,4) or (4,2)
    for f in &findings {
        let nodes = &f.matched_nodes;
        if nodes.contains(&2) && nodes.contains(&4) {
            panic!("Cross-function pair should not match SameFunction");
        }
    }
}

// ── CFG predicate: InLoop ─────────────────────────────────────────────────────

#[test]
fn cfg_in_loop_false_for_non_loop_nodes() {
    let (cpg, fn_id) = linear_cfg_cpg();
    // Linear CFG has no loops
    let plan = QueryPlan::CfgPredicate(CfgPredicate::InLoop {
        node: "n".to_owned(),
    });
    let rule = search_rule("in-loop", vec![], plan);
    let findings = run_rule_with_cfg(rule, &cpg, fn_id);
    assert!(findings.is_empty(), "No loops in linear CFG");
}

// ── CFG predicate: CfgReachableWithout ───────────────────────────────────────

#[test]
fn cfg_reachable_without_barrier_unblocked() {
    // branching_cfg: bb0(COND) → bb1(THEN), bb2(ELSE) → bb3(MERGE)
    // COND can reach MERGE even when THEN is the barrier (alternative path via ELSE).
    let (cpg, fn_id) = branching_cfg_cpg(); // COND=31, THEN=32, ELSE=33, MERGE=34
    // Find: Conditional(n) reaches Return(m) without going through THEN(b:Assign named "x")
    let plan = QueryPlan::CfgPredicate(CfgPredicate::CfgReachableWithout {
        from: "n".to_owned(),
        to: "m".to_owned(),
        barrier: "b".to_owned(),
    });
    let rule = CompiledRule {
        id: "reach-without-unblocked".to_owned(),
        severity: None,
        message: None,
        tags: vec![],
        languages: None,
        seed_hints: vec![],
        clauses: vec![CompiledClause::Search(SearchPlan {
            root_bindings: vec![
                root_binding("n", vec![IrNodeKind::Conditional]),
                root_binding("m", vec![IrNodeKind::Return]),
                root_binding("b", vec![IrNodeKind::Assign]),
            ],
            plan,
            report_vars: vec!["n".to_owned(), "m".to_owned(), "b".to_owned()],
        })],
    };
    let findings = run_rule_with_cfg(rule, &cpg, fn_id);
    // COND(31) can reach MERGE(34) via the ELSE(33) branch even when THEN(32) is blocked.
    // There should be a finding with n=COND(31), m=MERGE(34), b=THEN(32) since alternative exists.
    let can_reach_via_else = findings.iter().any(|f| {
        f.matched_nodes.contains(&31) && f.matched_nodes.contains(&34) && f.matched_nodes.contains(&32)
    });
    assert!(can_reach_via_else, "COND→MERGE should still be reachable without THEN (via ELSE branch)");
}

#[test]
fn cfg_reachable_without_blocked_single_path() {
    // In the linear CFG: bb0(N1=21) → bb1(N2=22) → bb2(N3=23)
    // Build a targeted CPG with Call→Assign→Return to test blocking.
    // Use call node as "from", assign as barrier, return as "to".
    let fn_id: u32 = 1;
    let from_id: u32 = 2;
    let barrier_id: u32 = 3;
    let to_id: u32 = 4;

    let cpg = make_cpg_with_blocks(
        vec![
            (fn_id, make_node(fn_id, IrNodeKind::MethodDef, Some("test_fn"))),
            (from_id, make_node_in_fn(from_id, IrNodeKind::Call, Some("src"), fn_id)),
            (barrier_id, make_node_in_fn(barrier_id, IrNodeKind::Assign, Some("mid"), fn_id)),
            (to_id, make_node_in_fn(to_id, IrNodeKind::Return, None, fn_id)),
        ],
        fn_id,
        vec![
            ("bb0", vec![from_id], vec!["bb1"]),   // Call → Assign
            ("bb1", vec![barrier_id], vec!["bb2"]), // Assign → Return
            ("bb2", vec![to_id], vec![]),
        ],
    );

    let dfg = DfgIndex::build(&cpg);
    let mut cfg_cache: HashMap<u32, FunctionCfg> = HashMap::new();
    cfg_cache.insert(fn_id, FunctionCfg::build_for_function(&cpg, fn_id));
    let summaries: HashMap<String, web_sitter::FunctionSummary> = HashMap::new();
    let registry = EndpointRegistry::new();
    let predicate_plans: HashMap<String, QueryPlan> = HashMap::new();
    let predicate_params: HashMap<String, Vec<String>> = HashMap::new();
    let alias = AliasIndex::build(&cpg);
    let sizes = AllocSizeIndex::build(&cpg);
    let kind_index = KindIndex::build(&cpg);
    let nullability = NullabilityIndex::build(&cpg, &kind_index);
    let ctx = EvalContext {
        cpg: &cpg,
        current_file: std::path::Path::new("test.c"),
        dfg: &dfg,
        cfg_cache: &cfg_cache,
        kind_index: &kind_index,
        alias: &alias,
        sizes: &sizes,
        nullability: &nullability,
        summaries: &summaries,
        registry: &registry,
        predicate_plans: &predicate_plans,
        predicate_params: &predicate_params,
        cross_file: None,
    };

    // When we block the Assign (barrier) node, Call cannot reach Return.
    let runner = RuleRunner::new(ctx);
    let plan = QueryPlan::CfgPredicate(CfgPredicate::CfgReachableWithout {
        from: "n".to_owned(),
        to: "m".to_owned(),
        barrier: "b".to_owned(),
    });
    let rule = CompiledRule {
        id: "blocked".to_owned(),
        severity: None,
        message: None,
        tags: vec![],
        languages: None,
        seed_hints: vec![],
        clauses: vec![CompiledClause::Search(SearchPlan {
            root_bindings: vec![
                root_binding("n", vec![IrNodeKind::Call]),
                root_binding("m", vec![IrNodeKind::Return]),
                root_binding("b", vec![IrNodeKind::Assign]),
            ],
            plan,
            report_vars: vec!["n".to_owned(), "m".to_owned(), "b".to_owned()],
        })],
    };
    let rule_set = RuleSet::new(vec![rule]);
    let findings = runner.run(&rule_set);
    // The only possible combination is n=Call(2), m=Return(4), b=Assign(3).
    // With Assign(3) as barrier, the only path Call→Assign→Return is blocked.
    assert!(findings.is_empty(), "single-path linear CFG should be blocked by the mid barrier");
}

// ── DFG predicate: DfgDef / DfgUse ──────────────────────────────────────────

#[test]
fn dfg_def_matches_source_of_variable_edge() {
    // CPG with a DFG edge: node 1 → node 2 for variable "x"
    let cpg = make_cpg_with_dfg(
        vec![
            (1, make_node(1, IrNodeKind::Assign, Some("lhs"))),
            (2, make_node(2, IrNodeKind::Identifier, Some("rhs"))),
        ],
        vec![(1, 2, "x")],
    );
    let plan = QueryPlan::DfgPredicate(DfgPredicate::DfgDef {
        var_name: "x".to_owned(),
        node: "n".to_owned(),
    });
    let rule = search_rule("dfg-def", vec![], plan);
    let findings = run_rule(rule, &cpg);
    // Only node 1 defines "x"
    assert_eq!(findings.len(), 1, "only the source node should define variable x");
    assert!(findings[0].matched_nodes.contains(&1), "node 1 should be the definition site");
}

#[test]
fn dfg_use_matches_destination_of_variable_edge() {
    let cpg = make_cpg_with_dfg(
        vec![
            (1, make_node(1, IrNodeKind::Assign, Some("lhs"))),
            (2, make_node(2, IrNodeKind::Identifier, Some("rhs"))),
        ],
        vec![(1, 2, "x")],
    );
    let plan = QueryPlan::DfgPredicate(DfgPredicate::DfgUse {
        var_name: "x".to_owned(),
        node: "n".to_owned(),
    });
    let rule = search_rule("dfg-use", vec![], plan);
    let findings = run_rule(rule, &cpg);
    // Only node 2 uses "x"
    assert_eq!(findings.len(), 1, "only the destination node should use variable x");
    assert!(findings[0].matched_nodes.contains(&2), "node 2 should be the use site");
}

#[test]
fn dfg_def_no_match_for_wrong_variable() {
    let cpg = make_cpg_with_dfg(
        vec![(1, make_node(1, IrNodeKind::Assign, Some("a")))],
        vec![(1, 2, "x")],
    );
    let plan = QueryPlan::DfgPredicate(DfgPredicate::DfgDef {
        var_name: "y".to_owned(), // wrong variable
        node: "n".to_owned(),
    });
    let rule = search_rule("dfg-def-no-match", vec![], plan);
    let findings = run_rule(rule, &cpg);
    assert!(findings.is_empty(), "variable 'y' has no definition edges");
}

// ── NodeType raw matching ─────────────────────────────────────────────────────

#[test]
fn node_type_raw_matches_node_type_field() {
    // NodeType("call") should match a Call node (node_type = "call")
    let (cpg, _) = simple_call_cpg();
    let rule = CompiledRule {
        id: "raw-call".to_owned(),
        severity: None,
        message: None,
        tags: vec![],
        languages: None,
        seed_hints: vec![],
        clauses: vec![CompiledClause::Search(SearchPlan {
            root_bindings: vec![RootBinding {
                name: "n".to_owned(),
                ty: TypeExpr::NodeType("call".to_owned()),
                kinds: vec![], // empty kinds → will filter by node_type
                hints: vec![],
            }],
            plan: QueryPlan::Literal(true),
            report_vars: vec!["n".to_owned()],
        })],
    };
    let findings = run_rule(rule, &cpg);
    assert_eq!(findings.len(), 1, "NodeType('call') should match exactly one Call node");
}

#[test]
fn node_type_raw_matches_pattern_check() {
    // MatchesPattern with NodeType("methoddef") should type-check correctly
    let (cpg, fn_id) = simple_call_cpg();
    let plan = QueryPlan::MatchesPattern {
        var: "n".to_owned(),
        ty: TypeExpr::NodeType("methoddef".to_owned()),
        fields: vec![],
    };
    let rule = search_rule("nodetype-pattern", vec![], plan);
    let findings = run_rule(rule, &cpg);
    assert!(!findings.is_empty(), "NodeType('methoddef') should match MethodDef nodes");
    // Only MethodDef nodes should match
    let _ = fn_id;
}

// ── Method steps: has_ancestor / ancestor ─────────────────────────────────────

#[test]
fn method_ancestor_walks_parent_chain() {
    // Build a CPG where node 2 has parent_id = 1 (MethodDef)
    let cpg = make_cpg_with_ids(vec![
        (1, make_node(1, IrNodeKind::MethodDef, Some("outer"))),
        (2, {
            let mut n = make_node(2, IrNodeKind::Call, Some("inner"));
            n.parent_id = Some(1);
            n.function_id = Some(1);
            n
        }),
    ]);
    // has_ancestor("methoddef") on node 2 should return true
    let plan = QueryPlan::AstConstraint(AstConstraint {
        lhs: PlanExpr::MethodChain {
            receiver: Box::new(PlanExpr::Var("n".to_owned())),
            steps: vec![MethodStep {
                method: "has_ancestor".to_owned(),
                args: vec![PlanExpr::Lit(Literal::Str("methoddef".to_owned()))],
            }],
        },
        op: CmpOp::Eq,
        rhs: PlanExpr::Lit(Literal::Bool(true)),
    });
    let rule = search_rule("has-ancestor", vec![IrNodeKind::Call], plan);
    let findings = run_rule(rule, &cpg);
    assert_eq!(findings.len(), 1, "Call node should have a MethodDef ancestor");
}

#[test]
fn method_has_ancestor_false_when_no_parent() {
    // Node with no parent_id
    let cpg = make_cpg_with_ids(vec![
        (1, make_node(1, IrNodeKind::Call, Some("alone"))),
    ]);
    let plan = QueryPlan::AstConstraint(AstConstraint {
        lhs: PlanExpr::MethodChain {
            receiver: Box::new(PlanExpr::Var("n".to_owned())),
            steps: vec![MethodStep {
                method: "has_ancestor".to_owned(),
                args: vec![PlanExpr::Lit(Literal::Str("methoddef".to_owned()))],
            }],
        },
        op: CmpOp::Eq,
        rhs: PlanExpr::Lit(Literal::Bool(false)),
    });
    let rule = search_rule("no-ancestor", vec![IrNodeKind::Call], plan);
    let findings = run_rule(rule, &cpg);
    assert_eq!(findings.len(), 1, "Node with no parent should have no MethodDef ancestor");
}

// ── Method steps: has_descendant / descendant ─────────────────────────────────

#[test]
fn method_has_descendant_finds_child() {
    // Node 1 has child node 2 (Literal)
    let cpg = make_cpg_with_ids(vec![
        (1, {
            let mut n = make_node(1, IrNodeKind::Call, Some("f"));
            n.children = vec![2];
            n
        }),
        (2, make_node(2, IrNodeKind::Literal, None)),
    ]);
    let plan = QueryPlan::AstConstraint(AstConstraint {
        lhs: PlanExpr::MethodChain {
            receiver: Box::new(PlanExpr::Var("n".to_owned())),
            steps: vec![MethodStep {
                method: "has_descendant".to_owned(),
                args: vec![PlanExpr::Lit(Literal::Str("literal".to_owned()))],
            }],
        },
        op: CmpOp::Eq,
        rhs: PlanExpr::Lit(Literal::Bool(true)),
    });
    let rule = search_rule("has-desc", vec![IrNodeKind::Call], plan);
    let findings = run_rule(rule, &cpg);
    assert_eq!(findings.len(), 1, "Call with Literal child should have_descendant('literal')");
}

// ── Method steps: param / param_count ────────────────────────────────────────

#[test]
fn method_param_count_correct() {
    // MethodDef with two ParamDef children
    let cpg = make_cpg_with_ids(vec![
        (1, {
            let mut n = make_node(1, IrNodeKind::MethodDef, Some("foo"));
            n.children = vec![2, 3];
            n
        }),
        (2, make_node(2, IrNodeKind::ParamDef, Some("a"))),
        (3, make_node(3, IrNodeKind::ParamDef, Some("b"))),
    ]);
    let plan = QueryPlan::AstConstraint(AstConstraint {
        lhs: PlanExpr::MethodChain {
            receiver: Box::new(PlanExpr::Var("n".to_owned())),
            steps: vec![MethodStep {
                method: "param_count".to_owned(),
                args: vec![],
            }],
        },
        op: CmpOp::Eq,
        rhs: PlanExpr::Lit(Literal::Int(2)),
    });
    let rule = search_rule("param-count", vec![IrNodeKind::MethodDef], plan);
    let findings = run_rule(rule, &cpg);
    assert_eq!(findings.len(), 1, "param_count() should return 2 for method with 2 params");
}

// ── Method steps: string_value / int_value ────────────────────────────────────

#[test]
fn method_string_value_returns_text() {
    let cpg = make_cpg_with_ids(vec![
        (1, make_literal_node(1, web_sitter::LiteralKind::String, "hello")),
    ]);
    let plan = QueryPlan::AstConstraint(AstConstraint {
        lhs: PlanExpr::MethodChain {
            receiver: Box::new(PlanExpr::Var("n".to_owned())),
            steps: vec![MethodStep {
                method: "string_value".to_owned(),
                args: vec![],
            }],
        },
        op: CmpOp::Eq,
        rhs: PlanExpr::Lit(Literal::Str("hello".to_owned())),
    });
    let rule = search_rule("str-val", vec![IrNodeKind::Literal], plan);
    let findings = run_rule(rule, &cpg);
    assert_eq!(findings.len(), 1, "string_value() should return the literal text");
}

#[test]
fn method_int_value_parses_number() {
    let cpg = make_cpg_with_ids(vec![
        (1, make_literal_node(1, web_sitter::LiteralKind::Integer, "42")),
    ]);
    let plan = QueryPlan::AstConstraint(AstConstraint {
        lhs: PlanExpr::MethodChain {
            receiver: Box::new(PlanExpr::Var("n".to_owned())),
            steps: vec![MethodStep {
                method: "int_value".to_owned(),
                args: vec![],
            }],
        },
        op: CmpOp::Eq,
        rhs: PlanExpr::Lit(Literal::Int(42)),
    });
    let rule = search_rule("int-val", vec![IrNodeKind::Literal], plan);
    let findings = run_rule(rule, &cpg);
    assert_eq!(findings.len(), 1, "int_value() should parse '42' as 42");
}

// ── Method steps: has_arg ────────────────────────────────────────────────────

#[test]
fn method_has_arg_true_for_child() {
    // Call node with child 2; query: does Call have arg that is node 2?
    let cpg = make_cpg_with_ids(vec![
        (1, make_call_node(1, "f", vec![2])),
        (2, make_node(2, IrNodeKind::Identifier, Some("x"))),
    ]);
    // Find Call nodes where has_arg(arg[0]) == true
    let plan = QueryPlan::AstConstraint(AstConstraint {
        lhs: PlanExpr::MethodChain {
            receiver: Box::new(PlanExpr::Var("n".to_owned())),
            steps: vec![MethodStep {
                method: "has_arg".to_owned(),
                args: vec![PlanExpr::MethodChain {
                    receiver: Box::new(PlanExpr::Var("n".to_owned())),
                    steps: vec![MethodStep {
                        method: "arg".to_owned(),
                        args: vec![PlanExpr::Lit(Literal::Int(0))],
                    }],
                }],
            }],
        },
        op: CmpOp::Eq,
        rhs: PlanExpr::Lit(Literal::Bool(true)),
    });
    let rule = search_rule("has-arg", vec![IrNodeKind::Call], plan);
    let findings = run_rule(rule, &cpg);
    assert_eq!(findings.len(), 1, "has_arg(arg(0)) should be true for call with one arg");
}

// ── Method steps: basic_block ─────────────────────────────────────────────────

#[test]
fn method_basic_block_returns_block_id() {
    let (cpg, fn_id) = linear_cfg_cpg(); // N1=21, N2=22, N3=23
    // Nodes in bb0=0, bb1=1, bb2=2 after sorting
    let plan = QueryPlan::AstConstraint(AstConstraint {
        lhs: PlanExpr::MethodChain {
            receiver: Box::new(PlanExpr::Var("n".to_owned())),
            steps: vec![MethodStep {
                method: "basic_block".to_owned(),
                args: vec![],
            }],
        },
        op: CmpOp::Ge,
        rhs: PlanExpr::Lit(Literal::Int(0)),
    });
    let rule = search_rule("bb", vec![IrNodeKind::Assign], plan);
    let findings = run_rule_with_cfg(rule, &cpg, fn_id);
    assert!(!findings.is_empty(), "Assign nodes in CFG should have a block ID >= 0");
}

// ── FixpointGroup recursion guard ─────────────────────────────────────────────

#[test]
fn fixpoint_group_terminates_without_infinite_loop() {
    let (cpg, _) = simple_call_cpg();
    // A FixpointGroup that contains a self-referencing PredicateCall.
    // The depth guard should prevent infinite recursion.
    let plan = QueryPlan::FixpointGroup {
        names: vec!["rec".to_owned()],
        bodies: vec![QueryPlan::PredicateCall {
            name: "rec".to_owned(),
            args: vec![],
        }],
    };
    let rule = search_rule("fixpoint-rec", vec![], plan);
    // Should terminate (return false due to depth cap) without hanging
    let findings = run_rule(rule, &cpg);
    assert!(findings.is_empty(), "Recursive fixpoint with undefined pred should terminate false");
}

#[test]
fn fixpoint_group_non_recursive_works() {
    let (cpg, _) = simple_call_cpg();
    // Non-recursive FixpointGroup is just a disjunction of bodies
    let plan = QueryPlan::FixpointGroup {
        names: vec!["base".to_owned()],
        bodies: vec![QueryPlan::Literal(true)],
    };
    let rule = search_rule("fixpoint-base", vec![], plan);
    let findings = run_rule(rule, &cpg);
    assert!(!findings.is_empty(), "Non-recursive FixpointGroup(true) should produce findings");
}
