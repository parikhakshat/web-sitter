mod fixtures;
use fixtures::*;
use std::path::PathBuf;
use web_sitter::IrNodeKind;
use web_ql::{
    ir::{CompiledClause, CompiledRule, QueryPlan, RootBinding, RuleSet, SearchPlan},
    ast::{Severity, TypeExpr},
    loader::compile_rules,
    taint::EndpointRegistry,
    workspace::Workspace,
};

fn empty_registry() -> EndpointRegistry {
    EndpointRegistry::new()
}

fn empty_rule_set() -> RuleSet {
    RuleSet { rules: vec![], global_seed_hints: vec![] }
}

fn always_true_rule_set() -> RuleSet {
    RuleSet::new(vec![CompiledRule {
        id: "always".to_owned(),
        severity: Some(Severity::High),
        message: Some("found".to_owned()),
        tags: vec![],
        languages: None,
        seed_hints: vec![],
        clauses: vec![CompiledClause::Search(SearchPlan {
            root_bindings: vec![RootBinding {
                name: "n".to_owned(),
                ty: TypeExpr::Node,
                kinds: vec![IrNodeKind::Call],
                hints: vec![],
            }],
            plan: QueryPlan::Literal(true),
            report_vars: vec!["n".to_owned()],
        })],
    }])
}

fn path(s: &str) -> PathBuf {
    PathBuf::from(s)
}

// ── Construction ──────────────────────────────────────────────────────────────

#[test]
fn new_workspace_is_empty() {
    let ws = Workspace::new(empty_registry());
    assert_eq!(ws.files.len(), 0);
    assert_eq!(ws.total_nodes(), 0);
    assert_eq!(ws.total_size_bytes(), 0);
}

// ── upsert_file ───────────────────────────────────────────────────────────────

#[test]
fn upsert_file_new_returns_true() {
    let mut ws = Workspace::new(empty_registry());
    let (cpg, _) = simple_call_cpg();
    let inserted = ws.upsert_file(path("a.py"), cpg, 1);
    assert!(inserted, "new file should return true");
    assert_eq!(ws.files.len(), 1);
}

#[test]
fn upsert_file_same_hash_returns_false() {
    let mut ws = Workspace::new(empty_registry());
    let (cpg1, _) = simple_call_cpg();
    let (cpg2, _) = simple_call_cpg();
    ws.upsert_file(path("a.py"), cpg1, 42);
    let reinserted = ws.upsert_file(path("a.py"), cpg2, 42); // same hash
    assert!(!reinserted, "same hash should return false (no change)");
    assert_eq!(ws.files.len(), 1); // still just one file
}

#[test]
fn upsert_file_changed_hash_returns_true() {
    let mut ws = Workspace::new(empty_registry());
    let (cpg1, _) = simple_call_cpg();
    let (cpg2, _) = simple_call_cpg();
    ws.upsert_file(path("a.py"), cpg1, 1);
    let updated = ws.upsert_file(path("a.py"), cpg2, 2); // different hash
    assert!(updated, "changed hash should return true");
    assert_eq!(ws.files.len(), 1); // still one file, updated in place
}

#[test]
fn upsert_multiple_files() {
    let mut ws = Workspace::new(empty_registry());
    for i in 0..5u64 {
        let (cpg, _) = simple_call_cpg();
        ws.upsert_file(PathBuf::from(format!("file{i}.py")), cpg, i);
    }
    assert_eq!(ws.files.len(), 5);
}

// ── remove_file ───────────────────────────────────────────────────────────────

#[test]
fn remove_file_decrements_count() {
    let mut ws = Workspace::new(empty_registry());
    let (cpg, _) = simple_call_cpg();
    ws.upsert_file(path("a.py"), cpg, 1);
    ws.remove_file(&path("a.py"));
    assert_eq!(ws.files.len(), 0);
}

#[test]
fn remove_nonexistent_file_is_noop() {
    let mut ws = Workspace::new(empty_registry());
    ws.remove_file(&path("nonexistent.py")); // should not panic
    assert_eq!(ws.files.len(), 0);
}

#[test]
fn remove_one_of_two_files() {
    let mut ws = Workspace::new(empty_registry());
    let (cpg1, _) = simple_call_cpg();
    let (cpg2, _) = simple_call_cpg();
    ws.upsert_file(path("a.py"), cpg1, 1);
    ws.upsert_file(path("b.py"), cpg2, 2);
    ws.remove_file(&path("a.py"));
    assert_eq!(ws.files.len(), 1);
    assert!(ws.files.contains_key(&path("b.py")));
}

// ── total_nodes / total_size_bytes ────────────────────────────────────────────

#[test]
fn total_nodes_sums_across_files() {
    let mut ws = Workspace::new(empty_registry());
    let (cpg1, _) = simple_call_cpg(); // 2 nodes (MethodDef + Call)
    let (cpg2, _) = simple_call_cpg(); // 2 more
    ws.upsert_file(path("a.py"), cpg1, 1);
    ws.upsert_file(path("b.py"), cpg2, 2);
    assert_eq!(ws.total_nodes(), 4);
}

#[test]
fn total_size_bytes_nonzero_after_upsert() {
    let mut ws = Workspace::new(empty_registry());
    let (cpg, _) = simple_call_cpg();
    ws.upsert_file(path("a.py"), cpg, 1);
    assert!(ws.total_size_bytes() > 0);
}

#[test]
fn total_nodes_zero_after_all_removed() {
    let mut ws = Workspace::new(empty_registry());
    let (cpg, _) = simple_call_cpg();
    ws.upsert_file(path("a.py"), cpg, 1);
    ws.remove_file(&path("a.py"));
    assert_eq!(ws.total_nodes(), 0);
    assert_eq!(ws.total_size_bytes(), 0);
}

// ── scan ─────────────────────────────────────────────────────────────────────

#[test]
fn scan_empty_workspace_returns_no_findings() {
    let ws = Workspace::new(empty_registry());
    let findings = ws.scan(&always_true_rule_set());
    assert!(findings.is_empty());
}

#[test]
fn scan_empty_rule_set_returns_no_findings() {
    let mut ws = Workspace::new(empty_registry());
    let (cpg, _) = simple_call_cpg();
    ws.upsert_file(path("a.py"), cpg, 1);
    let findings = ws.scan(&empty_rule_set());
    assert!(findings.is_empty());
}

#[test]
fn scan_finds_calls_in_single_file() {
    let mut ws = Workspace::new(empty_registry());
    let (cpg, _) = simple_call_cpg(); // has 1 Call node
    ws.upsert_file(path("a.py"), cpg, 1);
    let findings = ws.scan(&always_true_rule_set());
    assert_eq!(findings.len(), 1, "should find 1 Call node");
    assert_eq!(findings[0].rule_id, "always");
}

#[test]
fn scan_finds_calls_across_multiple_files() {
    let mut ws = Workspace::new(empty_registry());
    for i in 0..3u64 {
        let (cpg, _) = simple_call_cpg(); // each has 1 Call
        ws.upsert_file(PathBuf::from(format!("file{i}.py")), cpg, i);
    }
    let findings = ws.scan(&always_true_rule_set());
    assert_eq!(findings.len(), 3, "3 files × 1 Call each = 3 findings");
}

#[test]
fn scan_with_language_filter() {
    let mut ws = Workspace::new(empty_registry());

    // python file
    let py_cpg = make_cpg_with_lang(
        vec![(1u32, make_node(1, IrNodeKind::Call, Some("func")))],
        "python",
    );
    ws.upsert_file(path("a.py"), py_cpg, 1);

    // rust file
    let rs_cpg = make_cpg_with_lang(
        vec![(2u32, make_node(2, IrNodeKind::Call, Some("func")))],
        "rust",
    );
    ws.upsert_file(path("b.rs"), rs_cpg, 2);

    // Rule that only matches python
    let rs = compile_rules(r#"rule "py" { languages: [python] find n: Call where n.name == "func" }"#)
        .expect("compile");
    let findings = ws.scan(&rs);
    // Should only find the python Call, not the rust one
    assert_eq!(findings.len(), 1);
}

#[test]
fn scan_updated_file_uses_new_version() {
    let mut ws = Workspace::new(empty_registry());

    // First insert: 1 Call
    let (cpg1, _) = simple_call_cpg();
    ws.upsert_file(path("a.py"), cpg1, 1);
    let findings1 = ws.scan(&always_true_rule_set());
    assert_eq!(findings1.len(), 1);

    // Update: CPG with 0 Call nodes
    use web_sitter::Cpg;
    let cpg2 = Cpg { language: "python".to_owned(), ..Cpg::default() };
    ws.upsert_file(path("a.py"), cpg2, 2); // hash changed
    let findings2 = ws.scan(&always_true_rule_set());
    assert_eq!(findings2.len(), 0, "updated file with no calls should have 0 findings");
}

// ── scan_with_pool ────────────────────────────────────────────────────────────

#[test]
fn scan_with_pool_same_results_as_scan() {
    let mut ws = Workspace::new(empty_registry());
    for i in 0..4u64 {
        let (cpg, _) = simple_call_cpg();
        ws.upsert_file(PathBuf::from(format!("file{i}.py")), cpg, i);
    }
    let rule_set = always_true_rule_set();

    let profiler = web_profiler::Profiler::new();
    let pool = web_profiler::ProfiledPool::build("test-pool", 2, &profiler)
        .expect("pool build");

    let findings_direct = ws.scan(&rule_set);
    let findings_pool = ws.scan_with_pool(&rule_set, &pool);

    assert_eq!(
        findings_direct.len(),
        findings_pool.len(),
        "scan and scan_with_pool should return same number of findings"
    );
}

// ── function summaries merge ──────────────────────────────────────────────────

#[test]
fn upsert_file_merges_function_summaries() {
    use std::collections::BTreeMap;
    use web_sitter::{Cpg, FunctionSummary};

    let mut ws = Workspace::new(empty_registry());

    let mut cpg = Cpg { language: "python".to_owned(), ..Cpg::default() };
    cpg.function_summaries.insert(
        1,
        FunctionSummary {
            name: "my_func".to_owned(),
            ..FunctionSummary::default()
        },
    );

    ws.upsert_file(path("a.py"), cpg, 1);
    assert!(ws.summaries.contains_key("my_func"), "summaries should be merged");
}

// ── Profiler integration ──────────────────────────────────────────────────────

#[test]
fn scan_integrates_with_profiler() {
    web_profiler::init();
    let mut ws = Workspace::new(empty_registry());
    let (cpg, _) = simple_call_cpg();
    ws.upsert_file(path("a.py"), cpg, 1);
    let _ = ws.scan(&always_true_rule_set());
    // After scan, profiler should have recorded some stages
    let report = web_profiler::report();
    // scan_total span should be present
    assert!(
        report.stages.iter().any(|s| s.name.contains("scan")),
        "profiler should record scan stages"
    );
}
