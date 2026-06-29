use web_ql::loader::compile_rules;
use web_ql::parser::parse_rule_file;
use web_ql::ast::{Severity, Language, TopLevelItem};
use web_ql::ir::{CfgPredicate, CompiledClause, DfgPredicate, QueryPlan, SearchPlan};

// ── Minimal rule ──────────────────────────────────────────────────────────────

#[test]
fn parse_minimal_rule() {
    let src = r#"rule "empty" { }"#;
    let rf = parse_rule_file(src).expect("parse failed");
    assert_eq!(rf.items.len(), 1);
    let TopLevelItem::Rule(rule) = &rf.items[0] else { panic!("not a rule") };
    assert_eq!(rule.id, "empty");
    assert!(rule.clauses.is_empty());
}

#[test]
fn parse_rule_with_severity() {
    let src = r#"rule "check" { severity: high }"#;
    let rf = parse_rule_file(src).unwrap();
    let TopLevelItem::Rule(rule) = &rf.items[0] else { panic!() };
    assert_eq!(rule.severity, Some(Severity::High));
}

#[test]
fn parse_rule_all_severities() {
    for (kw, expected) in &[
        ("critical", Severity::Critical),
        ("high", Severity::High),
        ("medium", Severity::Medium),
        ("low", Severity::Low),
        ("info", Severity::Info),
    ] {
        let src = format!(r#"rule "r" {{ severity: {kw} }}"#);
        let rf = parse_rule_file(&src).unwrap();
        let TopLevelItem::Rule(rule) = &rf.items[0] else { panic!() };
        assert_eq!(rule.severity, Some(*expected), "severity {kw}");
    }
}

#[test]
fn parse_rule_with_message() {
    let src = r#"rule "msg" { message: "Found dangerous call" }"#;
    let rf = parse_rule_file(src).unwrap();
    let TopLevelItem::Rule(rule) = &rf.items[0] else { panic!() };
    assert_eq!(rule.message.as_deref(), Some("Found dangerous call"));
}

#[test]
fn parse_rule_with_languages() {
    let src = r#"rule "lang" { languages: [python, javascript] }"#;
    let rf = parse_rule_file(src).unwrap();
    let TopLevelItem::Rule(rule) = &rf.items[0] else { panic!() };
    let langs = rule.languages.as_ref().unwrap();
    assert!(langs.contains(&Language::Python));
    assert!(langs.contains(&Language::JavaScript));
}

#[test]
fn parse_rule_with_tags() {
    let src = r#"rule "tagged" { tags: ["injection", "security"] }"#;
    let rf = parse_rule_file(src).unwrap();
    let TopLevelItem::Rule(rule) = &rf.items[0] else { panic!() };
    let tags = rule.tags.as_ref().unwrap();
    assert!(tags.contains(&"injection".to_owned()));
    assert!(tags.contains(&"security".to_owned()));
}

#[test]
fn parse_rule_all_metadata() {
    let src = r#"
rule "full" {
    severity: critical
    message: "Taint found"
    languages: [python, go]
    tags: ["cwe-89", "injection"]
}
"#;
    let rf = parse_rule_file(src).unwrap();
    let TopLevelItem::Rule(rule) = &rf.items[0] else { panic!() };
    assert_eq!(rule.severity, Some(Severity::Critical));
    assert!(rule.message.is_some());
    assert!(rule.languages.is_some());
    assert!(rule.tags.is_some());
}

// ── Find (search) clause ──────────────────────────────────────────────────────

#[test]
fn parse_find_clause_simple() {
    let src = r#"rule "r" { find n: Call where n.name == "eval" }"#;
    let rf = parse_rule_file(src).unwrap();
    let TopLevelItem::Rule(rule) = &rf.items[0] else { panic!() };
    assert_eq!(rule.clauses.len(), 1);
}

#[test]
fn parse_find_clause_eq_operator() {
    let src = r#"rule "r" { find n: Call where n.name == "exec" }"#;
    parse_rule_file(src).expect("should parse");
}

#[test]
fn parse_find_clause_ne_operator() {
    let src = r#"rule "r" { find n: MethodDef where n.name != "safe" }"#;
    parse_rule_file(src).expect("should parse");
}

#[test]
fn parse_find_clause_integer_comparison() {
    let src = r#"rule "r" { find n: Call where n.line > 10 }"#;
    parse_rule_file(src).expect("should parse");
}

#[test]
fn parse_find_clause_and_condition() {
    let src = r#"rule "r" { find n: Call where n.name == "exec" and n.line > 5 }"#;
    parse_rule_file(src).expect("should parse");
}

#[test]
fn parse_find_clause_or_condition() {
    let src = r#"rule "r" { find n: Call where n.name == "eval" or n.name == "exec" }"#;
    parse_rule_file(src).expect("should parse");
}

#[test]
fn parse_find_clause_not_condition() {
    let src = r#"rule "r" { find n: Call where not n.name == "safe" }"#;
    parse_rule_file(src).expect("should parse");
}

#[test]
fn parse_find_clause_multiple_bindings() {
    let src = r#"rule "r" { find n: Call, m: MethodDef where n.name == "exec" }"#;
    parse_rule_file(src).expect("should parse");
}

// ── Taint clause ──────────────────────────────────────────────────────────────

#[test]
fn parse_taint_clause_basic() {
    let src = r#"
rule "sqli" {
    taint {
        sources: ["user_input"]
        sinks: ["execute_sql"]
    }
}
"#;
    parse_rule_file(src).expect("should parse taint clause");
}

#[test]
fn parse_taint_clause_with_sanitizers() {
    let src = r#"
rule "sqli" {
    taint {
        sources: ["get_param"]
        sinks: ["db_query"]
        sanitizers: ["escape_sql", "parameterize"]
    }
}
"#;
    parse_rule_file(src).expect("should parse taint with sanitizers");
}

#[test]
fn parse_taint_clause_with_options() {
    let src = r#"
rule "xss" {
    taint {
        sources: ["request.GET"]
        sinks: ["render_html"]
        require_interprocedural: true
        max_call_depth: 5
    }
}
"#;
    parse_rule_file(src).expect("should parse taint with options");
}

// ── Predicate definitions ─────────────────────────────────────────────────────

#[test]
fn parse_predicate_def() {
    let src = r#"
pred is_dangerous(n: Call) {
    n.name == "exec" or n.name == "eval"
}
"#;
    let rf = parse_rule_file(src).expect("should parse predicate");
    assert_eq!(rf.items.len(), 1);
    matches!(&rf.items[0], TopLevelItem::PredicateDef(_));
}

#[test]
fn parse_rule_calling_predicate() {
    let src = r#"
pred is_dangerous(n: Call) {
    n.name == "exec"
}
rule "use-pred" {
    find n: Call where is_dangerous(n)
}
"#;
    let rf = parse_rule_file(src).expect("should parse rule with predicate call");
    assert_eq!(rf.items.len(), 2);
}

// ── Source/sink definitions ───────────────────────────────────────────────────

#[test]
fn parse_source_def() {
    let src = r#"source user_input { kind: Call, name: "input" }"#;
    let rf = parse_rule_file(src).expect("should parse source def");
    assert_eq!(rf.items.len(), 1);
    matches!(&rf.items[0], TopLevelItem::SourceDef(_));
}

#[test]
fn parse_sink_def() {
    let src = r#"sink sql_exec { kind: Call, name: "execute" }"#;
    let rf = parse_rule_file(src).expect("should parse sink def");
    matches!(&rf.items[0], TopLevelItem::SinkDef(_));
}

// ── Multiple rules ────────────────────────────────────────────────────────────

#[test]
fn parse_multiple_rules() {
    let src = r#"
rule "rule-1" { severity: high }
rule "rule-2" { severity: low }
rule "rule-3" { }
"#;
    let rf = parse_rule_file(src).unwrap();
    assert_eq!(rf.items.len(), 3);
}

// ── Compile_rules end-to-end ──────────────────────────────────────────────────

#[test]
fn compile_empty_rule_set() {
    let rs = compile_rules(r#"rule "r" { }"#).expect("compile failed");
    assert_eq!(rs.rules.len(), 1);
    assert_eq!(rs.rules[0].id, "r");
}

#[test]
fn compile_rule_with_find() {
    let src = r#"rule "calls" { severity: high find n: Call where n.name == "exec" }"#;
    let rs = compile_rules(src).expect("compile failed");
    assert_eq!(rs.rules.len(), 1);
    assert!(!rs.rules[0].clauses.is_empty());
}

#[test]
fn compile_rule_with_taint() {
    let src = r#"
rule "taint-test" {
    severity: critical
    taint {
        sources: ["user_input"]
        sinks: ["exec"]
    }
}
"#;
    let rs = compile_rules(src).expect("compile failed");
    assert_eq!(rs.rules.len(), 1);
    assert!(!rs.rules[0].clauses.is_empty());
}

#[test]
fn compile_multiple_rules() {
    let src = r#"
rule "r1" { severity: high }
rule "r2" { severity: low }
"#;
    let rs = compile_rules(src).expect("compile failed");
    assert_eq!(rs.rules.len(), 2);
    let ids: Vec<&str> = rs.rules.iter().map(|r| r.id.as_str()).collect();
    assert!(ids.contains(&"r1"));
    assert!(ids.contains(&"r2"));
}

// ── Parse errors ──────────────────────────────────────────────────────────────

#[test]
fn missing_closing_brace_is_error() {
    let src = r#"rule "bad" {"#;
    assert!(parse_rule_file(src).is_err());
}

#[test]
fn missing_rule_id_is_error() {
    let src = r#"rule { }"#;
    assert!(parse_rule_file(src).is_err());
}

#[test]
fn unknown_top_level_token_is_error() {
    let src = r#"foobar "x" { }"#;
    assert!(parse_rule_file(src).is_err());
}

#[test]
fn lex_error_propagates() {
    // '@' is not a valid token
    let src = r#"rule "test" { @bad }"#;
    assert!(parse_rule_file(src).is_err());
}

#[test]
fn empty_source_ok() {
    let rf = parse_rule_file("").expect("empty source should parse");
    assert!(rf.items.is_empty());
}

#[test]
fn comment_only_source_ok() {
    let rf = parse_rule_file("// just a comment\n/* block */").expect("comments should parse");
    assert!(rf.items.is_empty());
}

// ── DSL feature coverage ──────────────────────────────────────────────────────

#[test]
fn compile_language_filter_applied() {
    let src = r#"rule "py-only" { languages: [python] severity: high }"#;
    let rs = compile_rules(src).expect("compile");
    let rule = &rs.rules[0];
    let langs = rule.languages.as_ref().unwrap();
    assert!(langs.iter().any(|l| l.to_string() == "python"));
}

#[test]
fn compile_preserves_tags() {
    let src = r#"rule "tagged" { tags: ["cwe-79"] severity: low }"#;
    let rs = compile_rules(src).expect("compile");
    assert!(rs.rules[0].tags.contains(&"cwe-79".to_owned()));
}

// ── Relational predicate compilation ─────────────────────────────────────────

fn extract_search_plan(rs: &web_ql::ir::RuleSet) -> &SearchPlan {
    let CompiledClause::Search(plan) = &rs.rules[0].clauses[0] else {
        panic!("expected Search clause");
    };
    plan
}

#[test]
fn compile_cfg_reaches_emits_cfg_predicate() {
    let src = r#"
rule "test" {
    find a: Call, b: Call where
        a.cfg_reaches(b)
}
"#;
    let rs = compile_rules(src).expect("compile");
    let plan = extract_search_plan(&rs);
    assert_eq!(plan.root_bindings.len(), 2);
    assert!(
        matches!(&plan.plan, QueryPlan::CfgPredicate(CfgPredicate::CfgReaches { a, b })
            if a == "a" && b == "b"),
        "cfg_reaches should compile to CfgPredicate::CfgReaches, got {:?}", plan.plan
    );
}

#[test]
fn compile_dominates_emits_cfg_predicate() {
    let src = r#"
rule "test" {
    find a: Conditional, b: Call where
        a.dominates(b)
}
"#;
    let rs = compile_rules(src).expect("compile");
    let plan = extract_search_plan(&rs);
    assert!(
        matches!(&plan.plan, QueryPlan::CfgPredicate(CfgPredicate::Dominates { a, b })
            if a == "a" && b == "b"),
        "dominates should compile to CfgPredicate::Dominates, got {:?}", plan.plan
    );
}

#[test]
fn compile_dfg_reaches_emits_dfg_predicate() {
    let src = r#"
rule "test" {
    find a: Call, b: Call where
        a.dfg_reaches(b)
}
"#;
    let rs = compile_rules(src).expect("compile");
    let plan = extract_search_plan(&rs);
    assert!(
        matches!(&plan.plan, QueryPlan::DfgPredicate(DfgPredicate::ReachesFlow { from, to })
            if from == "a" && to == "b"),
        "dfg_reaches should compile to DfgPredicate::ReachesFlow, got {:?}", plan.plan
    );
}

#[test]
fn compile_dfg_flows_to_emits_dfg_predicate() {
    let src = r#"
rule "test" {
    find a: Call, b: Call where
        a.dfg_flows_to(b)
}
"#;
    let rs = compile_rules(src).expect("compile");
    let plan = extract_search_plan(&rs);
    assert!(
        matches!(&plan.plan, QueryPlan::DfgPredicate(DfgPredicate::DirectFlow { from, to })
            if from == "a" && to == "b"),
        "dfg_flows_to should compile to DfgPredicate::DirectFlow, got {:?}", plan.plan
    );
}

#[test]
fn compile_cfg_reaches_without_emits_cfg_predicate() {
    let src = r#"
rule "test" {
    find a: Call, b: Call, barrier: Call where
        a.cfg_reaches_without(b, barrier)
}
"#;
    let rs = compile_rules(src).expect("compile");
    let plan = extract_search_plan(&rs);
    assert_eq!(plan.root_bindings.len(), 3);
    assert!(
        matches!(&plan.plan, QueryPlan::CfgPredicate(CfgPredicate::CfgReachableWithout {
            from, to, barrier
        }) if from == "a" && to == "b" && barrier == "barrier"),
        "cfg_reaches_without should compile to CfgReachableWithout, got {:?}", plan.plan
    );
}

#[test]
fn compile_in_loop_emits_cfg_predicate() {
    let src = r#"
rule "test" {
    find n: Loop where n.in_loop()
}
"#;
    let rs = compile_rules(src).expect("compile");
    let plan = extract_search_plan(&rs);
    assert!(
        matches!(&plan.plan, QueryPlan::CfgPredicate(CfgPredicate::InLoop { node })
            if node == "n"),
        "in_loop() should compile to CfgPredicate::InLoop, got {:?}", plan.plan
    );
}

#[test]
fn compile_same_function_emits_cfg_predicate() {
    let src = r#"
rule "test" {
    find a: Call, b: Call where a.same_function(b)
}
"#;
    let rs = compile_rules(src).expect("compile");
    let plan = extract_search_plan(&rs);
    assert!(
        matches!(&plan.plan, QueryPlan::CfgPredicate(CfgPredicate::SameFunction { a, b })
            if a == "a" && b == "b"),
        "same_function should compile to CfgPredicate::SameFunction, got {:?}", plan.plan
    );
}

#[test]
fn non_relational_method_still_compiles_as_ast_constraint() {
    // callee_name() is not a relational predicate — should still compile fine as boolean
    let src = r#"
rule "test" {
    find n: Call where n.callee_name() == "exec"
}
"#;
    let rs = compile_rules(src).expect("compile");
    let plan = extract_search_plan(&rs);
    assert!(
        matches!(&plan.plan, QueryPlan::AstConstraint(_)),
        "callee_name() comparison should stay as AstConstraint, got {:?}", plan.plan
    );
}

// ── Validate web-ql-queries directory ────────────────────────────────────────

#[test]
fn wql_query_files_parse() {
    let dir = std::path::Path::new("../web-ql-queries");
    if !dir.exists() {
        return; // skip if not present
    }
    fn collect_wql(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_wql(&path, out);
            } else if path.extension().map_or(false, |x| x == "wql") {
                out.push(path);
            }
        }
    }
    let mut wql_files = Vec::new();
    collect_wql(dir, &mut wql_files);
    let mut failures = Vec::new();
    for path in &wql_files {
        let src = std::fs::read_to_string(path).expect("read wql file");
        if let Err(e) = compile_rules(&src) {
            failures.push(format!("{}: {}", path.display(), e));
        }
    }
    if !failures.is_empty() {
        panic!("WQL parse failures:\n{}", failures.join("\n"));
    }
}
