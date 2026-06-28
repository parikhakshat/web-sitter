//! Exact parity port of `/home/akshat/deep/vuln/tests/test_c_grammar_json_contract.py`.

use sonic_rs::Value;
use sonic_rs::{JsonContainerTrait, JsonValueTrait};
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

fn vuln_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("vuln")
}

fn load_c_grammar_json() -> Value {
    let path = vuln_root().join("c-grammar.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    sonic_rs::from_str(&raw).unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()))
}

fn grammar_rule_names(grammar: &Value) -> BTreeSet<String> {
    let rules = grammar
        .get("rules")
        .and_then(|v| v.as_object())
        .expect("c-grammar.json: missing 'rules' object");
    rules.iter().map(|(k, _)| k.to_string()).collect()
}

fn walk_collect_symbols(value: &Value, names: &mut BTreeSet<String>) {
    if let Some(map) = value.as_object() {
        if map.get(&"type").and_then(|v| v.as_str()) == Some("SYMBOL") {
            if let Some(name) = map.get(&"name").and_then(|v| v.as_str()) {
                names.insert(name.to_string());
            }
        }
        if map.get(&"type").and_then(|v| v.as_str()) == Some("ALIAS") {
            if let Some(name) = map.get(&"value").and_then(|v| v.as_str()) {
                names.insert(name.to_string());
            }
        }
        for (_, child) in map.iter() {
            walk_collect_symbols(child, names);
        }
    } else if let Some(items) = value.as_array() {
        for item in items.iter() {
            walk_collect_symbols(item, names);
        }
    }
}

fn grammar_all_construct_names(grammar: &Value) -> BTreeSet<String> {
    let mut names = grammar_rule_names(grammar);
    let default_val = Value::default();
    let rules_val = grammar.get("rules").unwrap_or(&default_val);
    walk_collect_symbols(rules_val, &mut names);
    names
}

fn tree_sitter_named_kinds() -> BTreeSet<String> {
    let mut out = BTreeSet::<String>::new();
    let language: tree_sitter::Language = tree_sitter_c::LANGUAGE.into();
    let count = language.node_kind_count();
    for i in 0..count {
        let id = i as u16;
        if language.node_kind_is_named(id) {
            if let Some(kind) = language.node_kind_for_id(id) {
                out.insert(kind.to_string());
            }
        }
    }
    out
}

#[test]
fn test_c_grammar_json_has_expected_shape() {
    let grammar = load_c_grammar_json();
    assert_eq!(grammar.get("name").and_then(|v| v.as_str()), Some("c"));
    let rules = grammar.get("rules").and_then(|v| v.as_object());
    assert!(
        rules.is_some_and(|rules| rules.len() > 100),
        "expected a non-trivial rules object in c-grammar.json"
    );
}

#[test]
fn test_c_grammar_json_core_entry_rules_exist() {
    let names = grammar_rule_names(&load_c_grammar_json());
    for required in [
        "translation_unit",
        "function_definition",
        "declaration",
        "if_statement",
        "while_statement",
        "for_statement",
        "switch_statement",
        "call_expression",
        "preproc_include",
    ] {
        assert!(
            names.contains(required),
            "Expected rule {required:?} in c-grammar.json"
        );
    }
}

#[test]
fn test_named_kind_is_in_grammar_artifacts() {
    let constructs = grammar_all_construct_names(&load_c_grammar_json());
    for kind in tree_sitter_named_kinds() {
        assert!(
            constructs.contains(&kind),
            "missing grammar reference for {kind:?}"
        );
    }
}
