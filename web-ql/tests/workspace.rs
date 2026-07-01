mod fixtures;
use fixtures::*;
use std::path::PathBuf;
use std::sync::Arc;
use web_sitter::{CrossFileCallEdge, FunctionSummary, IrNodeKind, ParamEffect};
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
    RuleSet::new(vec![])
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

// ── taint registry resolution (named source/sink plans + base registry) ───────

#[test]
fn scan_taint_rule_with_named_source_and_sink_plans_finds_flow() {
    // Exercises build_taint_registry resolving BOTH named source/sink plan
    // definitions (evaluated per-CPG) AND falling back to the base registry for an
    // unnamed-but-registered endpoint, all in one rule — these resolve concurrently
    // internally, so this locks in that the merge back into one registry is correct.
    let mut ws = Workspace::new(empty_registry());
    let (cpg, _src, _sink) = taint_flow_cpg();
    ws.upsert_file(path("a.py"), cpg, 1);

    let rule_src = r#"
        source named_source = find n: Call where n.name == "user_input"
        sink named_sink = find n: Call where n.name == "execute_sql"
        rule "sqli" {
            taint {
                sources: ["named_source"]
                sinks: ["named_sink"]
            }
        }
    "#;
    let rule_set = compile_rules(rule_src).expect("rule should compile");
    let findings = ws.scan(&rule_set);

    assert_eq!(findings.len(), 1, "should find exactly one taint flow: {findings:?}");
    assert_eq!(findings[0].rule_id, "sqli");
}

#[test]
fn scan_taint_rule_falls_back_to_base_registry_for_unnamed_endpoints() {
    // No `source`/`sink` definitions in the rule file at all — both endpoint names
    // must resolve purely via the base EndpointRegistry passed into Workspace::new.
    let mut registry = empty_registry();
    registry.register("base_source", |cpg: &web_sitter::Cpg| {
        cpg.ast
            .iter()
            .filter(|(_, n)| n.name.as_deref() == Some("user_input"))
            .map(|(id, _)| *id)
            .collect()
    });
    registry.register("base_sink", |cpg: &web_sitter::Cpg| {
        cpg.ast
            .iter()
            .filter(|(_, n)| n.name.as_deref() == Some("execute_sql"))
            .map(|(id, _)| *id)
            .collect()
    });

    let mut ws = Workspace::new(registry);
    let (cpg, _src, _sink) = taint_flow_cpg();
    ws.upsert_file(path("a.py"), cpg, 1);

    let rule_src = r#"
        rule "sqli-base" {
            taint {
                sources: ["base_source"]
                sinks: ["base_sink"]
            }
        }
    "#;
    let rule_set = compile_rules(rule_src).expect("rule should compile");
    let findings = ws.scan(&rule_set);

    assert_eq!(findings.len(), 1, "should find the flow via base-registry fallback: {findings:?}");
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
    cpg.workspace.function_summaries.insert(
        1,
        FunctionSummary {
            name: "my_func".to_owned(),
            ..FunctionSummary::default()
        },
    );

    ws.upsert_file(path("a.py"), cpg, 1);
    assert!(ws.summaries.contains_key("my_func"), "summaries should be merged");
}

// ── build_cross_file_edges ──────────────────────────────────────────────────

#[test]
fn build_cross_file_edges_shares_callee_cpg_via_arc_not_clone() {
    // The whole point of Arc-wrapping FileIndex.cpg/.dfg is that
    // Workspace::cross_file_dfgs shares the *same* allocation as the callee file's
    // own FileIndex entry, instead of deep-cloning the CPG on every
    // build_cross_file_edges() call. Verify that with Arc::ptr_eq, not just that
    // the contents happen to be equal (which would also pass with a clone).
    let mut ws = Workspace::new(empty_registry());

    let callee_node = make_node(1, IrNodeKind::MethodDef, Some("helper"));
    let callee_cpg = make_cpg_with_ids(vec![(1, callee_node)]);
    ws.upsert_file(path("callee.py"), callee_cpg, 1);

    let caller_fn = make_node(10, IrNodeKind::MethodDef, Some("main"));
    let mut call_node = make_node(11, IrNodeKind::Call, Some("helper"));
    call_node.function_id = Some(10);
    let mut caller_cpg = make_cpg_with_ids(vec![(10, caller_fn), (11, call_node)]);
    caller_cpg.workspace.cross_file_calls = vec![CrossFileCallEdge {
        call_node: 11,
        caller_fn: 10,
        callee_name: "helper".to_owned(),
        qualified_callee: None,
        arg_positions: vec![],
    }];
    ws.upsert_file(path("caller.py"), caller_cpg, 1);

    ws.build_cross_file_edges();

    assert_eq!(
        ws.cross_file_callee_params.get(&11).map(|v| v.len()),
        Some(1),
        "the cross-file call should resolve to exactly one callee"
    );

    let callee_path = path("callee.py");
    let shared_cpg = &ws.cross_file_dfgs.get(&callee_path)
        .expect("callee should be registered in cross_file_dfgs")
        .1;
    let owned_cpg = &ws.files.get(&callee_path).expect("callee FileIndex should exist").cpg;
    assert!(
        Arc::ptr_eq(shared_cpg, owned_cpg),
        "cross_file_dfgs should share the same Arc<Cpg> allocation as FileIndex, not a deep clone"
    );

    let shared_dfg = &ws.cross_file_dfgs.get(&callee_path).unwrap().0;
    let owned_dfg = &ws.files.get(&callee_path).unwrap().dfg;
    assert!(
        Arc::ptr_eq(shared_dfg, owned_dfg),
        "cross_file_dfgs should share the same Arc<DfgIndex> allocation as FileIndex, not a deep clone"
    );
}

#[test]
fn build_cross_file_edges_resolves_unqualified_callee_name() {
    let mut ws = Workspace::new(empty_registry());

    let callee_node = make_node(1, IrNodeKind::MethodDef, Some("helper"));
    let callee_cpg = make_cpg_with_ids(vec![(1, callee_node)]);
    ws.upsert_file(path("callee.py"), callee_cpg, 1);

    let caller_fn = make_node(10, IrNodeKind::MethodDef, Some("main"));
    let mut call_node = make_node(11, IrNodeKind::Call, Some("helper"));
    call_node.function_id = Some(10);
    let mut caller_cpg = make_cpg_with_ids(vec![(10, caller_fn), (11, call_node)]);
    caller_cpg.workspace.cross_file_calls = vec![CrossFileCallEdge {
        call_node: 11,
        caller_fn: 10,
        callee_name: "helper".to_owned(),
        qualified_callee: None,
        arg_positions: vec![],
    }];
    ws.upsert_file(path("caller.py"), caller_cpg, 1);

    ws.build_cross_file_edges();

    let resolved = ws.cross_file_callee_params.get(&11).expect("call should resolve");
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].0, path("callee.py"));
}

// ── scan_incremental ─────────────────────────────────────────────────────────

#[test]
fn scan_incremental_matches_full_scan_results() {
    let mut ws = Workspace::new(empty_registry());
    for i in 0..3u64 {
        let (cpg, _) = simple_call_cpg();
        ws.upsert_file(PathBuf::from(format!("file{i}.py")), cpg, i);
    }
    let rule_set = always_true_rule_set();

    let incremental = ws.scan_incremental(&rule_set);
    assert_eq!(incremental.len(), 3, "3 files x 1 Call each = 3 findings");
}

#[test]
fn scan_incremental_clears_dirty_set_after_scan() {
    let mut ws = Workspace::new(empty_registry());
    let (cpg, _) = simple_call_cpg();
    ws.upsert_file(path("a.py"), cpg, 1);
    assert!(!ws.dirty_files().is_empty(), "newly inserted file should start dirty");

    ws.scan_incremental(&always_true_rule_set());
    assert!(
        ws.dirty_files().is_empty(),
        "dirty set should be empty after a successful incremental scan"
    );
}

#[test]
fn scan_incremental_repeated_scan_with_no_changes_is_stable() {
    // Re-running scan_incremental with nothing changed (no files dirty) must reuse the
    // cache and still produce the exact same findings as the first run.
    let mut ws = Workspace::new(empty_registry());
    for i in 0..3u64 {
        let (cpg, _) = simple_call_cpg();
        ws.upsert_file(PathBuf::from(format!("file{i}.py")), cpg, i);
    }
    let rule_set = always_true_rule_set();

    let first = ws.scan_incremental(&rule_set);
    assert!(ws.dirty_files().is_empty(), "no files should be dirty after the first scan");

    let second = ws.scan_incremental(&rule_set);
    assert_eq!(
        first.len(),
        second.len(),
        "scanning again with nothing dirty must return the same findings from cache"
    );
    assert_eq!(second.len(), 3);
}

#[test]
fn scan_incremental_upsert_marks_only_that_file_dirty() {
    // Precise per-file dirty tracking is what makes the incremental cache safe to use —
    // updating one file must not force every other file to be marked dirty too.
    let mut ws = Workspace::new(empty_registry());
    let (cpg_a, _) = simple_call_cpg();
    let (cpg_b, _) = simple_call_cpg();
    ws.upsert_file(path("a.py"), cpg_a, 1);
    ws.upsert_file(path("b.py"), cpg_b, 2);
    ws.scan_incremental(&always_true_rule_set());
    assert!(ws.dirty_files().is_empty());

    let (cpg_a2, _) = simple_call_cpg();
    ws.upsert_file(path("a.py"), cpg_a2, 99); // only a.py changes
    assert_eq!(ws.dirty_files().len(), 1, "only the updated file should be dirty");
    assert!(ws.dirty_files().contains(&path("a.py")));
    assert!(!ws.dirty_files().contains(&path("b.py")));
}

#[test]
fn scan_incremental_reflects_updated_file_content() {
    let mut ws = Workspace::new(empty_registry());
    let (cpg_a, _) = simple_call_cpg(); // 1 Call
    let (cpg_b, _) = simple_call_cpg(); // 1 Call
    ws.upsert_file(path("a.py"), cpg_a, 1);
    ws.upsert_file(path("b.py"), cpg_b, 2);

    let rule_set = always_true_rule_set();
    let first = ws.scan_incremental(&rule_set);
    assert_eq!(first.len(), 2);

    // Replace a.py with a CPG that has no Call nodes; b.py is untouched.
    use web_sitter::Cpg;
    let empty_cpg = Cpg { language: "python".to_owned(), ..Cpg::default() };
    ws.upsert_file(path("a.py"), empty_cpg, 100);

    let second = ws.scan_incremental(&rule_set);
    assert_eq!(
        second.len(),
        1,
        "a.py's findings should disappear after its update, b.py's should remain cached"
    );
}

#[test]
fn scan_incremental_invalidates_cache_when_rule_set_changes() {
    // A rule set swap (e.g. hot-reloaded rules) must not serve findings computed under
    // the previous rule set for files that weren't otherwise marked dirty.
    let mut ws = Workspace::new(empty_registry());
    let (cpg, _) = simple_call_cpg();
    ws.upsert_file(path("a.py"), cpg, 1);

    let first = ws.scan_incremental(&always_true_rule_set());
    assert_eq!(first.len(), 1);

    // No file changes — only the rule set differs (empty rule set now).
    let second = ws.scan_incremental(&empty_rule_set());
    assert_eq!(
        second.len(),
        0,
        "switching to an empty rule set must not keep serving the old rule set's cached findings"
    );

    // Switching back to the original rule set (still no file changes) must recompute too.
    let third = ws.scan_incremental(&always_true_rule_set());
    assert_eq!(third.len(), 1, "switching rule sets back must recompute, not serve stale cache");
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

#[test]
fn scan_with_interprocedural_taint_records_dfg_reachability_and_bfs_profiling() {
    // Same shape as `scan_taint_rule_finds_interprocedural_flow_through_function_summary`
    // — the point here isn't the finding itself (already covered there) but that
    // running an interprocedural taint scan actually shows up under the profiler:
    // the `DfgIndex::reachable_from` cache and the various named BFS spans
    // (`dfg.propagate_taint_bfs`, `taint.expand_interprocedural`,
    // `taint.reaches_with_propagators_bfs`) used internally to compute it.
    web_profiler::init();

    const SOURCE: u32 = 1;
    const WRAP: u32 = 2;
    const SINK: u32 = 3;

    let source_call = make_call_node(SOURCE, "get_input", vec![]);
    let wrap_call = make_call_node(WRAP, "wrap1", vec![SOURCE]);
    let sink_call = make_call_node(SINK, "execute_sql", vec![]);

    let mut cpg = make_cpg_with_dfg(
        vec![(SOURCE, source_call), (WRAP, wrap_call), (SINK, sink_call)],
        vec![(WRAP, SINK, "result")],
    );
    let mut param_effects = std::collections::BTreeSet::new();
    param_effects.insert(ParamEffect::TaintReturn(0));
    cpg.workspace.function_summaries.insert(
        100,
        FunctionSummary {
            name: "wrap1".to_owned(),
            param_effects,
            ..FunctionSummary::default()
        },
    );

    let mut ws = Workspace::new(empty_registry());
    ws.upsert_file(path("a.py"), cpg, 1);

    let rule_src = r#"
        source src = find n: Call where n.name == "get_input"
        sink snk = find n: Call where n.name == "execute_sql"
        rule "interprocedural-profiled" {
            taint {
                sources: ["src"]
                sinks: ["snk"]
            }
        }
        rule "direct-dfg-reaches-profiled" {
            find a: Call, b: Call where
                a.name == "wrap1" and b.name == "execute_sql" and a.dfg_reaches(b)
        }
    "#;
    let rule_set = compile_rules(rule_src).expect("rule should compile");
    let findings = ws.scan(&rule_set);
    assert_eq!(
        findings.len(),
        2,
        "sanity: both the taint flow and the direct dfg_reaches match should be found: {findings:?}"
    );

    let report = web_profiler::report();
    let stage_names: Vec<&str> = report.stages.iter().map(|s| s.name.as_str()).collect();
    for expected in [
        "dfg.propagate_taint_bfs",
        "taint.expand_interprocedural",
        "taint.reaches_with_propagators_bfs",
    ] {
        assert!(
            stage_names.iter().any(|n| *n == expected),
            "expected profiler stage `{expected}` to be recorded, got: {stage_names:?}"
        );
    }

    let cache_names: Vec<&str> = report.caches.iter().map(|c| c.name.as_str()).collect();
    assert!(
        cache_names.iter().any(|n| *n == "dfg.reach_cache"),
        "expected `dfg.reach_cache` to be tracked as a profiler cache, got: {cache_names:?}"
    );
}

// ── Default STDLIB propagator application ──────────────────────────────────────

#[test]
fn scan_applies_stdlib_propagator_by_default_without_rule_declaring_it() {
    // getParameter() [1] -> append(1) [2, args=[1]] -> (DFG edge) -> execute_sql() [3]
    // There is NO direct DFG edge from 1 to 2 — the only link is the Java
    // stdlib propagator entry for `append` (dst: -1 i.e. return value, src: [0]).
    // Before wiring per-language STDLIB propagators into the default taint
    // scan, this taint flow was invisible unless the rule explicitly listed
    // `propagators: [...]`. The rule below deliberately does not.
    let src_call = make_call_node(1, "getParameter", vec![]);
    let append_call = make_call_node(2, "append", vec![1]);
    let sink_call = make_call_node(3, "execute_sql", vec![]);

    let cpg = make_cpg_with_dfg(
        vec![(1, src_call), (2, append_call), (3, sink_call)],
        vec![(2, 3, "result")],
    );
    let mut cpg = cpg;
    cpg.language = "java".to_owned();

    let mut ws = Workspace::new(web_ql::security_patterns::builtin_endpoint_registry());
    ws.upsert_file(path("A.java"), cpg, 1);

    let rule_src = r#"
        source java_src = find n: Call where n.name == "getParameter"
        sink java_sink = find n: Call where n.name == "execute_sql"
        rule "propagator-default-test" {
            taint {
                sources: ["java_src"]
                sinks: ["java_sink"]
            }
        }
    "#;
    let rule_set = compile_rules(rule_src).expect("rule should compile");
    let findings = ws.scan(&rule_set);

    assert_eq!(
        findings.len(),
        1,
        "taint should flow through the stdlib `append` propagator by default: {findings:?}"
    );
}

// ── Interprocedural / cross-file BFS-from-seeds integration ───────────────────
//
// The taint.rs unit tests exercise `TaintEngine::expand_interprocedural` and
// `expand_cross_file` directly, bypassing the actual `.wql` rule pipeline. These
// tests instead go through `compile_rules` + `Workspace::scan`, the same path a
// real rule file takes, to lock in that BFS-from-seeds actually crosses function
// and file boundaries end to end — not just at the unit level.

#[test]
fn scan_taint_rule_finds_interprocedural_flow_through_function_summary() {
    // get_input() [1] -> wrap1(1) [2] -> (DFG) -> execute_sql() [3]
    // There is no direct DFG edge from 1 to 2 — `wrap1`'s return value only
    // becomes tainted via its `FunctionSummary` (TaintReturn(0): "tainted arg 0
    // taints the return value"), which `expand_interprocedural`'s call-argument
    // worklist must discover purely from `wrap1(source)` being a call whose
    // argument is tainted. From there, the ordinary DFG edge wrap1 -> sink
    // carries the (now-tainted) call node the rest of the way.
    const SOURCE: u32 = 1;
    const WRAP: u32 = 2;
    const SINK: u32 = 3;

    let source_call = make_call_node(SOURCE, "get_input", vec![]);
    let wrap_call = make_call_node(WRAP, "wrap1", vec![SOURCE]);
    let sink_call = make_call_node(SINK, "execute_sql", vec![]);

    let mut cpg = make_cpg_with_dfg(
        vec![(SOURCE, source_call), (WRAP, wrap_call), (SINK, sink_call)],
        vec![(WRAP, SINK, "result")],
    );
    let mut param_effects = std::collections::BTreeSet::new();
    param_effects.insert(ParamEffect::TaintReturn(0));
    cpg.workspace.function_summaries.insert(
        100,
        FunctionSummary {
            name: "wrap1".to_owned(),
            param_effects,
            ..FunctionSummary::default()
        },
    );

    let mut ws = Workspace::new(empty_registry());
    ws.upsert_file(path("a.py"), cpg, 1);

    let rule_src = r#"
        source src = find n: Call where n.name == "get_input"
        sink snk = find n: Call where n.name == "execute_sql"
        rule "interprocedural" {
            taint {
                sources: ["src"]
                sinks: ["snk"]
            }
        }
    "#;
    let rule_set = compile_rules(rule_src).expect("rule should compile");
    let findings = ws.scan(&rule_set);

    assert_eq!(
        findings.len(),
        1,
        "taint should flow interprocedurally through wrap1's function summary: {findings:?}"
    );
}

#[test]
fn scan_taint_rule_finds_cross_file_flow_through_callee_return() {
    // caller.py: get_input() [1] -> helper(1) [2] -> (DFG) -> execute_sql() [3]
    // callee.py: fn helper(param) { return param; }  (param [101] -DFG-> return [102])
    // `helper` is defined in a different file, so the only way the call node [2]
    // becomes tainted is via `expand_cross_file`: it must resolve the cross-file
    // call edge, propagate taint into callee.py's own DFG from the matched param
    // node, see the callee's Return node become tainted, and mark the call site
    // itself tainted — purely from `Workspace::build_cross_file_edges` metadata,
    // with no same-file DFG edge bridging [1] to [2] at all.
    const HELPER_FN: u32 = 100;
    const PARAM: u32 = 101;
    const RETURN: u32 = 102;

    let mut helper_fn = make_node(HELPER_FN, IrNodeKind::MethodDef, Some("helper"));
    let param_node = make_node_in_fn(PARAM, IrNodeKind::ParamDef, Some("param"), HELPER_FN);
    let return_node = make_node_in_fn(RETURN, IrNodeKind::Return, None, HELPER_FN);
    helper_fn.children = vec![PARAM];

    let callee_cpg = make_cpg_with_dfg(
        vec![(HELPER_FN, helper_fn), (PARAM, param_node), (RETURN, return_node)],
        vec![(PARAM, RETURN, "param")],
    );

    const CALLER_FN: u32 = 10;
    const SOURCE: u32 = 1;
    const CALL: u32 = 2;
    const SINK: u32 = 3;

    let caller_fn = make_node(CALLER_FN, IrNodeKind::MethodDef, Some("main"));
    let source_call = make_node_in_fn(SOURCE, IrNodeKind::Call, Some("get_input"), CALLER_FN);
    let call_node = {
        let mut n = make_call_node(CALL, "helper", vec![SOURCE]);
        n.function_id = Some(CALLER_FN);
        n
    };
    let sink_call = make_node_in_fn(SINK, IrNodeKind::Call, Some("execute_sql"), CALLER_FN);

    let mut caller_cpg = make_cpg_with_dfg(
        vec![
            (CALLER_FN, caller_fn),
            (SOURCE, source_call),
            (CALL, call_node),
            (SINK, sink_call),
        ],
        vec![(CALL, SINK, "result")],
    );
    caller_cpg.workspace.cross_file_calls = vec![CrossFileCallEdge {
        call_node: CALL,
        caller_fn: CALLER_FN,
        callee_name: "helper".to_owned(),
        qualified_callee: None,
        arg_positions: vec![],
    }];

    let mut ws = Workspace::new(empty_registry());
    ws.upsert_file(path("callee.py"), callee_cpg, 1);
    ws.upsert_file(path("caller.py"), caller_cpg, 1);
    ws.build_cross_file_edges();

    let rule_src = r#"
        source src = find n: Call where n.name == "get_input"
        sink snk = find n: Call where n.name == "execute_sql"
        rule "cross-file" {
            taint {
                sources: ["src"]
                sinks: ["snk"]
            }
        }
    "#;
    let rule_set = compile_rules(rule_src).expect("rule should compile");
    let findings = ws.scan(&rule_set);

    assert_eq!(
        findings.len(),
        1,
        "taint should flow cross-file through helper's callee-side return: {findings:?}"
    );
}

#[test]
fn scan_taint_rule_no_cross_file_flow_when_callee_param_unused() {
    // Same shape as the passing cross-file test above, but callee.py's `helper`
    // never routes its param to a Return node (dead parameter) — so the callee
    // DFG can't taint any Return node, and expand_cross_file must NOT mark the
    // call site tainted. Without this negative case, a version of
    // `expand_cross_file` that ignores the callee's actual dataflow (e.g. one
    // that treats "call resolves cross-file" as sufficient) would pass the
    // positive test above for the wrong reason.
    const HELPER_FN: u32 = 100;
    const PARAM: u32 = 101;
    const RETURN: u32 = 102;

    let mut helper_fn = make_node(HELPER_FN, IrNodeKind::MethodDef, Some("helper"));
    let param_node = make_node_in_fn(PARAM, IrNodeKind::ParamDef, Some("param"), HELPER_FN);
    let return_node = make_node_in_fn(RETURN, IrNodeKind::Return, None, HELPER_FN);
    helper_fn.children = vec![PARAM];

    // No DFG edge from PARAM to RETURN this time.
    let callee_cpg = make_cpg_with_dfg(
        vec![(HELPER_FN, helper_fn), (PARAM, param_node), (RETURN, return_node)],
        vec![],
    );

    const CALLER_FN: u32 = 10;
    const SOURCE: u32 = 1;
    const CALL: u32 = 2;
    const SINK: u32 = 3;

    let caller_fn = make_node(CALLER_FN, IrNodeKind::MethodDef, Some("main"));
    let source_call = make_node_in_fn(SOURCE, IrNodeKind::Call, Some("get_input"), CALLER_FN);
    let call_node = {
        let mut n = make_call_node(CALL, "helper", vec![SOURCE]);
        n.function_id = Some(CALLER_FN);
        n
    };
    let sink_call = make_node_in_fn(SINK, IrNodeKind::Call, Some("execute_sql"), CALLER_FN);

    let mut caller_cpg = make_cpg_with_dfg(
        vec![
            (CALLER_FN, caller_fn),
            (SOURCE, source_call),
            (CALL, call_node),
            (SINK, sink_call),
        ],
        vec![(CALL, SINK, "result")],
    );
    caller_cpg.workspace.cross_file_calls = vec![CrossFileCallEdge {
        call_node: CALL,
        caller_fn: CALLER_FN,
        callee_name: "helper".to_owned(),
        qualified_callee: None,
        arg_positions: vec![],
    }];

    let mut ws = Workspace::new(empty_registry());
    ws.upsert_file(path("callee.py"), callee_cpg, 1);
    ws.upsert_file(path("caller.py"), caller_cpg, 1);
    ws.build_cross_file_edges();

    let rule_src = r#"
        source src = find n: Call where n.name == "get_input"
        sink snk = find n: Call where n.name == "execute_sql"
        rule "cross-file-negative" {
            taint {
                sources: ["src"]
                sinks: ["snk"]
            }
        }
    "#;
    let rule_set = compile_rules(rule_src).expect("rule should compile");
    let findings = ws.scan(&rule_set);

    assert!(
        findings.is_empty(),
        "no cross-file flow should be reported when the callee never returns the tainted param: {findings:?}"
    );
}
