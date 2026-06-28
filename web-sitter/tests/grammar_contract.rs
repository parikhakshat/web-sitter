//! Port of `tests/test_c_grammar_json_contract.py` style checks.

use web_sitter::extract_schema;

#[test]
fn c_grammar_schema_has_expected_shape() {
    let schema = extract_schema();
    assert!(schema.contains_key("node_types"));
    assert!(schema.contains_key("edge_types"));
}

#[test]
fn c_grammar_schema_core_entry_rules_exist() {
    let schema = extract_schema();
    let node_types = schema.get("node_types").expect("node_types");
    for required in [
        "function_definition",
        "identifier",
        "call_expression",
        "assignment_expression",
        "declaration",
    ] {
        assert!(
            node_types.iter().any(|n| n == required),
            "missing node type {required}"
        );
    }
}

#[test]
fn named_kind_is_in_grammar_artifacts() {
    let schema = extract_schema();
    let node_types = schema.get("node_types").expect("node_types");
    for named_kind in [
        "if_statement",
        "while_statement",
        "for_statement",
        "switch_statement",
    ] {
        assert!(
            node_types.iter().any(|n| n == named_kind),
            "expected named kind '{named_kind}' in extracted schema"
        );
    }
}
