mod fixtures;
use fixtures::*;
use std::collections::HashMap;
use web_sitter::IrNodeKind;
use web_ql::{
    dfg::DfgIndex,
    engine::{EvalContext, RuleRunner},
    ir::{
        AstConstraint, CompiledClause, CompiledRule, DfgPredicate,
        PlanExpr, QueryPlan, RootBinding, RuleSet, SearchPlan,
    },
    ast::{CmpOp, Language, Literal, Severity, TypeExpr},
    cfg::FunctionCfg,
    taint::EndpointRegistry,
    finding::Finding,
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
    let ctx = EvalContext {
        cpg,
        dfg: &dfg,
        cfg_cache: &cfg_cache,
        summaries: &summaries,
        registry: &registry,
        predicate_plans: &predicate_plans,
    };
    let runner = RuleRunner::new(ctx);
    let rule_set = RuleSet::new(vec![rule]);
    runner.run(&rule_set)
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
    let ctx = EvalContext {
        cpg: &cpg,
        dfg: &dfg,
        cfg_cache: &cfg_cache,
        summaries: &summaries,
        registry: &registry,
        predicate_plans: &predicate_plans,
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
    let ctx = EvalContext {
        cpg: &cpg,
        dfg: &dfg,
        cfg_cache: &cfg_cache,
        summaries: &summaries,
        registry: &registry,
        predicate_plans: &predicate_plans,
    };
    let runner = RuleRunner::new(ctx);
    let rule_set = RuleSet::new(vec![]);
    let findings = runner.run(&rule_set);
    assert!(findings.is_empty());
}
