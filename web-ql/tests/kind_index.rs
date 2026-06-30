mod fixtures;
use fixtures::*;
use std::collections::BTreeMap;
use web_sitter::{CallGraphEntry, CallSite, FunctionKind, IrNodeKind};
use web_ql::kind_index::KindIndex;

#[test]
fn nodes_of_kinds_returns_matching_nodes_only() {
    let (cpg, call_id) = simple_call_cpg();
    let idx = KindIndex::build(&cpg);

    let calls = idx.nodes_of_kinds(&[IrNodeKind::Call]);
    assert_eq!(calls, vec![call_id]);

    let methods = idx.nodes_of_kinds(&[IrNodeKind::MethodDef]);
    assert_eq!(methods.len(), 1);

    let none = idx.nodes_of_kinds(&[IrNodeKind::ClassDef]);
    assert!(none.is_empty());
}

#[test]
fn nodes_of_kinds_empty_filter_returns_all_nodes() {
    let (cpg, _) = simple_call_cpg();
    let idx = KindIndex::build(&cpg);
    let all = idx.nodes_of_kinds(&[]);
    assert_eq!(all.len(), cpg.ast.len());
}

#[test]
fn nodes_of_kinds_multiple_kinds_union() {
    let (cpg, _) = simple_call_cpg();
    let idx = KindIndex::build(&cpg);
    let both = idx.nodes_of_kinds(&[IrNodeKind::Call, IrNodeKind::MethodDef]);
    assert_eq!(both.len(), 2, "should return nodes of both kinds");
}

#[test]
fn nodes_of_raw_type_matches_node_type_string() {
    let (cpg, call_id) = simple_call_cpg();
    let idx = KindIndex::build(&cpg);
    // node_type is set to the lowercased Debug form of the kind by `make_node`.
    let matches = idx.nodes_of_raw_type("call");
    assert_eq!(matches, vec![call_id]);
}

#[test]
fn nodes_of_raw_type_is_case_insensitive() {
    let (cpg, call_id) = simple_call_cpg();
    let idx = KindIndex::build(&cpg);
    let matches = idx.nodes_of_raw_type("CALL");
    assert_eq!(matches, vec![call_id]);
}

#[test]
fn call_site_for_node_finds_registered_call() {
    let (mut cpg, call_id) = simple_call_cpg();
    let fn_id = 1;
    let mut call_graph = BTreeMap::new();
    call_graph.insert(
        fn_id,
        CallGraphEntry {
            name: "outer".to_owned(),
            calls: vec![CallSite {
                callee: "func".to_owned(),
                callee_id: None,
                call_site: Some(call_id),
                qualified_callee: None,
                callee_kind: FunctionKind::Internal,
            }],
            called_by: vec![],
        },
    );
    cpg.call_graph = call_graph;

    let idx = KindIndex::build(&cpg);
    let cs = idx.call_site_for_node(call_id);
    assert!(cs.is_some(), "should find the call site for the registered call node");
    assert_eq!(cs.unwrap().callee, "func");
}

#[test]
fn call_site_for_node_returns_none_when_unregistered() {
    let (cpg, call_id) = simple_call_cpg(); // no call_graph entries
    let idx = KindIndex::build(&cpg);
    assert!(idx.call_site_for_node(call_id).is_none());
}
