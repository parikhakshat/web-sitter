//! Parity port of `tests/test_cpg_infrastructure.py`.

use web_sitter::Cpg;
use web_sitter::{GraphBuildOptions, IncrementalCpgGenerator, compute_edit, generate_cpg_from_code};
use std::collections::{BTreeMap, BTreeSet};

fn parse_main_and_incremental(source: &[u8]) -> (Cpg, Cpg) {
    let main = generate_cpg_from_code(&String::from_utf8_lossy(source)).expect("main parse failed");
    let mut inc =
        IncrementalCpgGenerator::new(GraphBuildOptions::default()).expect("inc init failed");
    let inc_cpg = inc
        .parse_full(source)
        .expect("inc parse_full failed")
        .clone();
    (main, inc_cpg)
}

fn parse_incremental_updated(old_source: &[u8], new_source: &[u8]) -> (Cpg, Cpg) {
    let mut incremental_gen =
        IncrementalCpgGenerator::new(GraphBuildOptions::default()).expect("inc init failed");
    let _ = incremental_gen
        .parse_initial(old_source)
        .expect("inc initial parse failed");
    let edit = compute_edit(old_source, new_source).expect("expected non-empty edit");
    let updated = incremental_gen
        .apply_edit(&edit, new_source)
        .expect("inc apply_edit failed")
        .clone();

    let mut fresh_gen =
        IncrementalCpgGenerator::new(GraphBuildOptions::default()).expect("fresh init failed");
    let fresh = fresh_gen
        .parse_full(new_source)
        .expect("fresh parse_full failed")
        .clone();
    (updated, fresh)
}

fn ast_signature(cpg: &Cpg) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::<String, usize>::new();
    for node in cpg.ast.values() {
        let key = format!(
            "{:?}|{:?}|{}|{}|{}|{}|{}|{:?}",
            node.node_type,
            node.text,
            node.line,
            node.column,
            node.end_line,
            node.end_column,
            node.children.len(),
            node.field_names
        );
        *out.entry(key).or_insert(0) += 1;
    }
    out
}

fn dfg_signature(cpg: &Cpg) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::<String, usize>::new();
    for edge in &cpg.dataflow.edges {
        let src = cpg.ast.get(&edge.source);
        let dst = cpg.ast.get(&edge.destination);
        let key = format!(
            "{}|{}|{:?}|{:?}|{:?}|{:?}",
            edge.edge_type,
            edge.variable,
            src.map(|n| n.node_type.clone()),
            src.map(|n| n.line),
            dst.map(|n| n.node_type.clone()),
            dst.map(|n| n.line),
        );
        *out.entry(key).or_insert(0) += 1;
    }
    out
}

fn call_signature(cpg: &Cpg) -> BTreeSet<(String, String)> {
    let mut edges = BTreeSet::<(String, String)>::new();
    for entry in cpg.call_graph.values() {
        for call in &entry.calls {
            if !call.callee.is_empty() {
                edges.insert((entry.name.clone(), call.callee.clone()));
            }
        }
    }
    edges
}

fn edge_signature(
    cpg: &Cpg,
) -> BTreeSet<(
    String,
    String,
    Option<String>,
    Option<String>,
    Option<u32>,
    Option<String>,
    Option<String>,
    Option<u32>,
)> {
    cpg.dataflow
        .edges
        .iter()
        .map(|edge| {
            let src = cpg.ast.get(&edge.source);
            let dst = cpg.ast.get(&edge.destination);
            (
                edge.edge_type.clone(),
                edge.variable.clone(),
                src.map(|n| n.node_type.clone()),
                src.and_then(|n| n.text.clone()),
                src.map(|n| n.line),
                dst.map(|n| n.node_type.clone()),
                dst.and_then(|n| n.text.clone()),
                dst.map(|n| n.line),
            )
        })
        .collect()
}

fn has_edge(
    cpg: &Cpg,
    edge_type: &str,
    variable: &str,
    src_text: Option<&str>,
    dst_text: Option<&str>,
) -> bool {
    cpg.dataflow.edges.iter().any(|edge| {
        if edge.edge_type != edge_type || edge.variable != variable {
            return false;
        }
        let src = cpg.ast.get(&edge.source);
        let dst = cpg.ast.get(&edge.destination);
        if let Some(expected) = src_text {
            if src.and_then(|n| n.text.as_deref()) != Some(expected) {
                return false;
            }
        }
        if let Some(expected) = dst_text {
            if dst.and_then(|n| n.text.as_deref()) != Some(expected) {
                return false;
            }
        }
        true
    })
}

fn function_id_by_name(cpg: &Cpg, name: &str) -> Option<u32> {
    cpg.call_graph
        .iter()
        .find_map(|(fid, entry)| (entry.name == name).then_some(*fid))
}

fn has_arg_to_param_edge(cpg: &Cpg, caller_name: &str, callee_name: &str, variable: &str) -> bool {
    let caller_id = function_id_by_name(cpg, caller_name);
    let callee_id = function_id_by_name(cpg, callee_name);
    let (Some(caller_id), Some(callee_id)) = (caller_id, callee_id) else {
        return false;
    };

    cpg.dataflow.edges.iter().any(|edge| {
        if edge.edge_type != "INTERPROCEDURAL_FLOW" || edge.variable != variable {
            return false;
        }

        let src_fn = cpg.ast.get(&edge.source).and_then(|n| n.function_id);
        let dst_fn = cpg.ast.get(&edge.destination).and_then(|n| n.function_id);

        src_fn == Some(caller_id) && dst_fn == Some(callee_id)
    })
}

fn find_sources_for_dest_text(
    cpg: &Cpg,
    dest_text: &str,
    parent_type: &str,
) -> BTreeSet<(Option<String>, Option<u32>)> {
    let dest_ids = cpg
        .ast
        .iter()
        .filter_map(|(node_id, node)| {
            let parent_type_matches = node
                .parent_id
                .and_then(|pid| cpg.ast.get(&pid))
                .map(|p| p.node_type.as_str() == parent_type)
                .unwrap_or(false);
            (node.text.as_deref() == Some(dest_text) && parent_type_matches).then_some(*node_id)
        })
        .collect::<BTreeSet<_>>();

    cpg.dataflow
        .edges
        .iter()
        .filter(|edge| edge.edge_type == "REACHING_DEF" && dest_ids.contains(&edge.destination))
        .map(|edge| {
            let src = cpg.ast.get(&edge.source);
            (src.and_then(|n| n.text.clone()), src.map(|n| n.column))
        })
        .collect()
}

#[test]
fn test_incremental_update_matches_fresh_full_rebuild() {
    let pairs = [
        (
            b"int add(int a,int b){return a+b;} int main(){return add(1,2);} ".to_vec(),
            b"int add(int a,int b){return a+b;} int main(){return add(9,2);} ".to_vec(),
        ),
        (
            b"int f(int x){if(x){x++;}return x;} int main(){return f(1);} ".to_vec(),
            b"int f(int x){if(x){x+=2;}return x;} int main(){return f(1);} ".to_vec(),
        ),
    ];

    for (old_source, new_source) in pairs {
        let (updated, fresh) = parse_incremental_updated(&old_source, &new_source);
        assert_eq!(ast_signature(&updated), ast_signature(&fresh));
        assert_eq!(dfg_signature(&updated), dfg_signature(&fresh));
        assert_eq!(call_signature(&updated), call_signature(&fresh));
    }
}

#[test]
fn test_incremental_edit_reuses_majority_of_node_ids_for_small_change() {
    let old_source = b"int add(int a,int b){return a+b;} int main(){return add(1,2);} ";
    let new_source = b"int add(int a,int b){return a+b;} int main(){return add(9,2);} ";

    let mut incremental_gen =
        IncrementalCpgGenerator::new(GraphBuildOptions::default()).expect("inc init failed");
    let before = incremental_gen
        .parse_initial(old_source)
        .expect("parse initial failed")
        .clone();
    let edit = compute_edit(old_source, new_source).expect("expected non-empty edit");
    let after = incremental_gen
        .apply_edit(&edit, new_source)
        .expect("apply_edit failed")
        .clone();

    let old_ids = before.ast.keys().copied().collect::<BTreeSet<_>>();
    let new_ids = after.ast.keys().copied().collect::<BTreeSet<_>>();
    let overlap = old_ids.intersection(&new_ids).count();
    let ratio = if old_ids.is_empty() {
        1.0
    } else {
        overlap as f64 / old_ids.len() as f64
    };

    assert!(
        ratio >= 0.50,
        "Incremental update touched too much graph for one-token edit: overlap_ratio={ratio:.3}"
    );
}

#[test]
fn test_main_and_incremental_emit_arg_to_param_interprocedural_edges() {
    let source =
        b"int pred(int x) { return x > 3; } int cic(int x) { if (pred(x)) return 1; return 0; }";
    let (main, inc) = parse_main_and_incremental(source);

    assert!(
        has_arg_to_param_edge(&main, "cic", "pred", "x"),
        "Main generator should emit arg->param INTERPROCEDURAL_FLOW"
    );
    assert!(
        has_arg_to_param_edge(&inc, "cic", "pred", "x"),
        "Incremental generator should emit same arg->param INTERPROCEDURAL_FLOW"
    );
}

#[test]
fn test_cfg_reaching_defs_preserve_conditional_definition_paths() {
    let source = b"int f(int x) { int y = 0; if (x) y = 1; return y; }";
    let (main, inc) = parse_main_and_incremental(source);

    let main_sources = find_sources_for_dest_text(&main, "y", "return_statement");
    let inc_sources = find_sources_for_dest_text(&inc, "y", "return_statement");

    assert!(
        main_sources.len() >= 2,
        "Main generator should keep both conditional reaching defs"
    );
    assert_eq!(inc_sources, main_sources);
}

#[test]
fn test_cfg_reaching_defs_preserve_loop_carried_and_initial_paths() {
    let source = b"int f(int n) { int y = 0; while (n-- > 0) { y = 1; } return y; }";
    let (main, inc) = parse_main_and_incremental(source);

    let main_sources = find_sources_for_dest_text(&main, "y", "return_statement");
    let inc_sources = find_sources_for_dest_text(&inc, "y", "return_statement");

    assert!(main_sources.len() >= 2);
    assert_eq!(inc_sources, main_sources);
}

#[test]
fn test_cfg_reaching_defs_preserve_switch_fallthrough_paths() {
    let source = b"int f(int x) { int y = 0; switch (x) { case 0: y = 1; case 1: return y; default: return 2; } }";
    let (main, inc) = parse_main_and_incremental(source);

    let main_sources = find_sources_for_dest_text(&main, "y", "return_statement");
    let inc_sources = find_sources_for_dest_text(&inc, "y", "return_statement");

    assert!(main_sources.len() >= 2);
    assert_eq!(inc_sources, main_sources);
}

#[test]
fn test_cfg_reaching_defs_preserve_nested_short_circuit_merge_paths() {
    let source = b"int f(int a, int b, int c) { int y = 0; if ((a && b) || c) y = 1; return y; }";
    let (main, inc) = parse_main_and_incremental(source);

    let main_sources = find_sources_for_dest_text(&main, "y", "return_statement");
    let inc_sources = find_sources_for_dest_text(&inc, "y", "return_statement");

    assert!(main_sources.len() >= 2);
    assert_eq!(inc_sources, main_sources);
}

#[test]
fn test_cfg_reaching_defs_reject_goto_past_definition() {
    let source = b"int f(void) { goto use; int y = 1; use: return y; }";
    let (main, inc) = parse_main_and_incremental(source);

    let main_sources = find_sources_for_dest_text(&main, "y", "return_statement");
    let inc_sources = find_sources_for_dest_text(&inc, "y", "return_statement");

    assert!(
        main_sources.is_empty(),
        "CFG-primary reaching defs should not fall back to source order through goto"
    );
    assert_eq!(inc_sources, main_sources);
}

#[test]
fn test_function_definition_bb_assignment_does_not_own_descendants() {
    let cpg = generate_cpg_from_code("int f(int x) { if (x) { return 1; } return x; }")
        .expect("parse failed");

    let function_bb = cpg
        .ast
        .values()
        .find(|node| node.node_type == "function_definition")
        .and_then(|node| node.basic_block.clone())
        .expect("function_definition should have a BB");

    let final_return_x_bb = cpg
        .ast
        .values()
        .find(|node| {
            node.node_type == "identifier"
                && node.text.as_deref() == Some("x")
                && node
                    .parent_id
                    .and_then(|pid| cpg.ast.get(&pid))
                    .map(|parent| parent.node_type.as_str() == "return_statement")
                    .unwrap_or(false)
        })
        .and_then(|node| node.basic_block.clone())
        .expect("return x identifier should have a BB");

    assert_ne!(
        final_return_x_bb, function_bb,
        "function_definition BB tagging must not recursively overwrite body descendants"
    );
}

#[test]
fn test_points_to_edges_exist_and_match_for_address_of_flows() {
    let source = b"int f(void) { int *arr[1]; int x = 9; arr[0] = &x; return *arr[0]; }";
    let (main, inc) = parse_main_and_incremental(source);

    assert!(
        has_edge(&main, "POINTS_TO", "arr", Some("arr"), Some("x")),
        "Main generator should emit POINTS_TO"
    );
    assert!(
        has_edge(&inc, "POINTS_TO", "arr", Some("arr"), Some("x")),
        "Incremental generator should emit same POINTS_TO edge"
    );
}

#[test]
fn test_pointer_deref_write_records_pointer_def_and_rhs_flow() {
    let source = b"int f(int *ptr, int x) { *ptr = x; return *ptr; }";
    let (main, inc) = parse_main_and_incremental(source);

    assert!(
        has_edge(&main, "REACHING_DEF", "ptr", Some("ptr"), Some("ptr")),
        "Main generator should treat *ptr assignment as a ptr reaching definition"
    );
    assert!(
        has_edge(&main, "REACHING_DEF", "ptr", Some("x"), Some("ptr")),
        "Main generator should propagate RHS taint into ptr for deref writes"
    );
    assert!(
        has_edge(&inc, "REACHING_DEF", "ptr", Some("ptr"), Some("ptr")),
        "Incremental generator should treat *ptr assignment as a ptr reaching definition"
    );
    assert!(
        has_edge(&inc, "REACHING_DEF", "ptr", Some("x"), Some("ptr")),
        "Incremental generator should propagate RHS taint into ptr for deref writes"
    );
}

#[test]
fn test_interprocedural_return_flows_reach_call_result_and_match() {
    let source = b"int id(int a) { return a; } int f(int x) { int y = id(x); return y; }";
    let (main, inc) = parse_main_and_incremental(source);

    assert!(
        has_edge(&main, "INTERPROCEDURAL_FLOW", "y", Some("a"), Some("y")),
        "Main generator should emit return-to-call-result interprocedural flow"
    );
    assert!(
        has_edge(&inc, "INTERPROCEDURAL_FLOW", "y", Some("a"), Some("y")),
        "Incremental generator should emit return-to-call-result flow"
    );
}

#[test]
fn test_field_access_object_flow_matches_between_main_and_incremental() {
    let source = b"struct N { int v; }; int f(struct N *n) { n->v = 7; return n->v; }";
    let (main, inc) = parse_main_and_incremental(source);

    assert!(
        has_edge(&main, "REACHING_DEF", "n", Some("n"), Some("n->v")),
        "Main generator should emit object-to-field flow"
    );
    assert!(
        has_edge(&inc, "REACHING_DEF", "n", Some("n"), Some("n->v")),
        "Incremental generator should match object-to-field flow"
    );
}

#[test]
fn test_taint_source_tracking_matches_between_main_and_incremental() {
    let source =
        b"char *f(char *out) { char *u = getenv(\"USER\"); sprintf(out, \"%s\", u); return out; }";
    let (main, inc) = parse_main_and_incremental(source);

    let main_sig = edge_signature(&main);
    let inc_sig = edge_signature(&inc);

    assert_eq!(
        inc_sig, main_sig,
        "Main and incremental dataflow edges diverged"
    );
    assert!(
        has_edge(&main, "REACHING_DEF", "u", Some("u"), Some("u")),
        "Main generator should track dataflow for getenv-derived variable u"
    );
}

#[test]
fn test_multi_call_interprocedural_chain_matches_between_main_and_incremental() {
    let source = b"int src(int a) { return a; } int mid(int b) { return src(b); } int top(int c) { int d = mid(c); return d; }";
    let (main, inc) = parse_main_and_incremental(source);

    assert!(has_arg_to_param_edge(&main, "mid", "src", "a"));
    assert!(has_arg_to_param_edge(&main, "top", "mid", "b"));
    assert!(has_arg_to_param_edge(&inc, "mid", "src", "a"));
    assert!(has_arg_to_param_edge(&inc, "top", "mid", "b"));
}

#[test]
fn test_incremental_update_preserves_cfg_rd_semantics() {
    let cases = [
        (
            b"int f(int x) { int y = 0; if (x) return y; return 2; }".to_vec(),
            b"int f(int x) { int y = 0; if (x) y = 1; return y; }".to_vec(),
            "y",
            "return_statement",
            2_usize,
        ),
        (
            b"int f(int n) { int y = 0; return y; }".to_vec(),
            b"int f(int n) { int y = 0; while (n-- > 0) { y = 1; } return y; }".to_vec(),
            "y",
            "return_statement",
            2_usize,
        ),
        (
            b"int f(int x) { int y = 0; switch (x) { case 1: return y; default: return 2; } }".to_vec(),
            b"int f(int x) { int y = 0; switch (x) { case 0: y = 1; case 1: return y; default: return 2; } }".to_vec(),
            "y",
            "return_statement",
            2_usize,
        ),
    ];

    for (old_source, new_source, dest_text, parent_type, min_sources) in cases {
        let (updated, fresh) = parse_incremental_updated(&old_source, &new_source);
        let updated_sources = find_sources_for_dest_text(&updated, dest_text, parent_type);
        let fresh_sources = find_sources_for_dest_text(&fresh, dest_text, parent_type);

        assert_eq!(updated_sources, fresh_sources);
        assert!(
            updated_sources.len() >= min_sources,
            "Focused incremental CFG-RD regression lost expected reaching definitions"
        );
    }
}

#[test]
fn test_incremental_update_preserves_nested_short_circuit_cfg_rd_semantics() {
    let old_source = b"int f(int a, int b, int c) { int y = 0; if (a) y = 1; return y; }";
    let new_source =
        b"int f(int a, int b, int c) { int y = 0; if ((a && b) || c) y = 1; return y; }";

    let (updated, fresh) = parse_incremental_updated(old_source, new_source);
    let updated_sources = find_sources_for_dest_text(&updated, "y", "return_statement");
    let fresh_sources = find_sources_for_dest_text(&fresh, "y", "return_statement");

    assert_eq!(updated_sources, fresh_sources);
    assert!(updated_sources.len() >= 2);
}

#[test]
fn test_incremental_update_preserves_arg_to_param_interprocedural_flow() {
    let old_source = b"int pred(int x) { return x > 3; } int cic(int x) { return 0; }";
    let new_source =
        b"int pred(int x) { return x > 3; } int cic(int x) { if (pred(x)) return 1; return 0; }";

    let (updated, fresh) = parse_incremental_updated(old_source, new_source);

    assert!(has_arg_to_param_edge(&updated, "cic", "pred", "x"));
    assert!(has_arg_to_param_edge(&fresh, "cic", "pred", "x"));
}

#[test]
fn test_incremental_update_preserves_multi_call_interprocedural_chain() {
    let old_source = b"int src(int a) { return a; } int mid(int b) { return b; } int top(int c) { int d = mid(c); return d; }";
    let new_source = b"int src(int a) { return a; } int mid(int b) { return src(b); } int top(int c) { int d = mid(c); return d; }";

    let (updated, fresh) = parse_incremental_updated(old_source, new_source);

    assert!(has_arg_to_param_edge(&updated, "mid", "src", "a"));
    assert!(has_arg_to_param_edge(&updated, "top", "mid", "b"));
    assert!(has_arg_to_param_edge(&fresh, "mid", "src", "a"));
    assert!(has_arg_to_param_edge(&fresh, "top", "mid", "b"));
}

#[test]
fn test_incremental_update_preserves_points_to_edges() {
    let old_source = b"int f(void) { int *arr[1]; int x = 9; return x; }";
    let new_source = b"int f(void) { int *arr[1]; int x = 9; arr[0] = &x; return *arr[0]; }";

    let (updated, fresh) = parse_incremental_updated(old_source, new_source);

    assert!(has_edge(
        &updated,
        "POINTS_TO",
        "arr",
        Some("arr"),
        Some("x")
    ));
    assert!(has_edge(&fresh, "POINTS_TO", "arr", Some("arr"), Some("x")));
}

#[test]
fn test_incremental_update_preserves_taint_sources() {
    let old_source = b"char *f(char *out) { sprintf(out, \"%s\", \"safe\"); return out; }";
    let new_source =
        b"char *f(char *out) { char *u = getenv(\"USER\"); sprintf(out, \"%s\", u); return out; }";

    let (updated, fresh) = parse_incremental_updated(old_source, new_source);

    assert_eq!(edge_signature(&updated), edge_signature(&fresh));
    assert!(has_edge(
        &updated,
        "REACHING_DEF",
        "u",
        Some("u"),
        Some("u")
    ));
}

fn assert_update_parity(old_source: &[u8], new_source: &[u8]) {
    let (updated, fresh) = parse_incremental_updated(old_source, new_source);
    assert_eq!(
        ast_signature(&updated),
        ast_signature(&fresh),
        "AST signature mismatch after incremental update"
    );
    assert_eq!(
        dfg_signature(&updated),
        dfg_signature(&fresh),
        "DFG signature mismatch after incremental update"
    );
    assert_eq!(
        call_signature(&updated),
        call_signature(&fresh),
        "call graph mismatch after incremental update"
    );
}

#[test]
fn test_incremental_irrelevant_edit_in_other_function_preserves_signatures() {
    let old_source = b"int helper(int x) { return x; } int target(int y) { return y + 1; }";
    let new_source =
        b"int helper(int x) { return x; } int target(int y) { return y + 1; } /* noop */";
    assert_update_parity(old_source, new_source);
}

#[test]
fn test_incremental_whitespace_only_edit_preserves_signatures() {
    let old_source = b"int f(int a,int b){return a+b;}";
    let new_source = b"int f(int a, int b) { return a + b; }";
    assert_update_parity(old_source, new_source);
}

#[test]
fn test_incremental_function_deletion_matches_fresh() {
    let old_source = b"int keep(int x) { return x; } int remove(int y) { return y * 2; }";
    let new_source = b"int keep(int x) { return x; }";
    assert_update_parity(old_source, new_source);
}

#[test]
fn test_incremental_function_insertion_matches_fresh() {
    let old_source = b"int first(int x) { return x; }";
    let new_source =
        b"int first(int x) { return x; } int second(int y) { return y + 1; } int third(int z) { return z - 1; }";
    assert_update_parity(old_source, new_source);
}

#[test]
fn test_incremental_operator_change_matches_fresh() {
    let old_source =
        b"int calc(int a, int b) { return a + b; } int main(void) { return calc(1, 2); }";
    let new_source =
        b"int calc(int a, int b) { return a * b; } int main(void) { return calc(1, 2); }";
    assert_update_parity(old_source, new_source);
}

#[test]
fn test_incremental_array_size_change_matches_fresh() {
    let old_source = b"int f(void) { char buf[64]; buf[0] = 'a'; return buf[0]; }";
    let new_source = b"int f(void) { char buf[256]; buf[0] = 'a'; return buf[0]; }";
    assert_update_parity(old_source, new_source);
}

#[test]
fn test_incremental_malloc_size_change_matches_fresh() {
    let old_source =
        b"int f(void) { int *p = (int *)malloc(16); if (!p) return 0; free(p); return 0; }";
    let new_source =
        b"int f(void) { int *p = (int *)malloc(128); if (!p) return 0; free(p); return 0; }";
    assert_update_parity(old_source, new_source);
}

#[test]
fn test_incremental_new_interprocedural_return_flow_matches_fresh() {
    let old_source = b"int leaf(int v) { return v; } int caller(int x) { return x; }";
    let new_source = b"int leaf(int v) { return v; } int caller(int x) { return leaf(x); }";
    let (updated, fresh) = parse_incremental_updated(old_source, new_source);
    assert_eq!(ast_signature(&updated), ast_signature(&fresh));
    assert_eq!(dfg_signature(&updated), dfg_signature(&fresh));
    assert_eq!(call_signature(&updated), call_signature(&fresh));
    assert!(has_arg_to_param_edge(&updated, "caller", "leaf", "v"));
    assert!(has_arg_to_param_edge(&fresh, "caller", "leaf", "v"));
}

#[test]
fn test_incremental_edit_one_function_preserves_unrelated_function_dfg() {
    let old_source = b"int stable(int x) { return x + 1; } int changing(int y) { return y + 1; }";
    let new_source = b"int stable(int x) { return x + 1; } int changing(int y) { return y + 9; }";

    let (updated, fresh) = parse_incremental_updated(old_source, new_source);

    let stable_dfg = |cpg: &Cpg| {
        cpg.dataflow
            .edges
            .iter()
            .filter(|edge| {
                cpg.ast
                    .get(&edge.source)
                    .and_then(|n| n.function_id)
                    .and_then(|fid| cpg.call_graph.get(&fid))
                    .map(|entry| entry.name == "stable")
                    .unwrap_or(false)
            })
            .map(|edge| {
                format!(
                    "{}|{}|{}|{}",
                    edge.edge_type, edge.variable, edge.source, edge.destination
                )
            })
            .collect::<BTreeSet<_>>()
    };

    assert_eq!(stable_dfg(&updated), stable_dfg(&fresh));
}

#[test]
fn binary_expression_operator_field_is_set() {
    use web_sitter::generate_cpg_from_code;
    let src = "void f(int a, int b) { if (b == 0) return; int r = a / b; }";
    let cpg = generate_cpg_from_code(src).unwrap();
    use web_sitter::IrNodeKind;
    let bin_exprs: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| matches!(n.kind, IrNodeKind::BinaryOp | IrNodeKind::Conditional))
        .collect();
    assert!(!bin_exprs.is_empty(), "expected binary expression nodes in the AST");
    let has_div = cpg
        .ast
        .values()
        .any(|n| n.kind == IrNodeKind::BinaryOp && n.operator.as_deref() == Some("/"));
    assert!(has_div, "BinaryOp for 'a / b' should have operator '/'");
    let has_eq = cpg
        .ast
        .values()
        .any(|n| n.kind == IrNodeKind::BinaryOp && n.operator.as_deref() == Some("=="));
    assert!(has_eq, "BinaryOp for 'b == 0' should have operator '=='");
}
