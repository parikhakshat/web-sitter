//! Symbol anonymizer tests — verify variable renaming while preserving stdlib/field names.

use web_sitter::{SymbolAnonymizer, generate_cpg_from_code};

fn anonymize(src: &str) -> (web_sitter::Cpg, std::collections::HashMap<String, String>) {
    let cpg = generate_cpg_from_code(src).expect("CPG generation failed");
    let mut anon = SymbolAnonymizer::new();
    let result = anon.anonymize(&cpg);
    (result.cpg, result.symbol_table)
}

#[test]
fn anonymizer_renames_variables() {
    let (anon_cpg, symbol_table) = anonymize("void f() { int buf = 42; }");
    // 'buf' should be renamed to something like var0.
    let has_buf = anon_cpg
        .ast
        .values()
        .any(|n| n.text.as_deref() == Some("buf"));
    assert!(
        !has_buf,
        "original name 'buf' should not appear after anonymization"
    );
    // The symbol_table reverse map should let us recover the original name.
    let has_entry = symbol_table.values().any(|orig| orig == "buf");
    assert!(
        has_entry,
        "symbol_table should contain 'buf' as an original name"
    );
}

#[test]
fn anonymizer_preserves_stdlib_function_names() {
    let (anon_cpg, _) = anonymize("void f(char *dst, char *src) { strcpy(dst, src); }");
    // 'strcpy' is a stdlib function and must NOT be anonymized.
    let has_strcpy = anon_cpg
        .ast
        .values()
        .any(|n| n.text.as_deref() == Some("strcpy"));
    assert!(has_strcpy, "'strcpy' should be preserved (stdlib function)");
}

#[test]
fn anonymizer_preserves_field_names() {
    let (anon_cpg, _) = anonymize(
        "struct Point { int coord_x; int coord_y; }; void f(struct Point p) { p.coord_x = 1; }",
    );
    // Struct field names provide semantic context and must not be anonymized.
    let has_field = anon_cpg
        .ast
        .values()
        .any(|n| n.text.as_deref() == Some("coord_x"));
    assert!(
        has_field,
        "field name 'coord_x' should be preserved after anonymization"
    );
}

#[test]
fn anonymizer_loop_index_pattern() {
    let (anon_cpg, symbol_table) = anonymize("void f() { for (int i = 0; i < 10; i++) {} }");
    // Loop index 'i' should be renamed with an 'idx' prefix pattern.
    let has_i = anon_cpg
        .ast
        .values()
        .any(|n| n.text.as_deref() == Some("i"));
    assert!(!has_i, "loop index 'i' should be anonymized");
    let anon_name = symbol_table
        .iter()
        .find(|(_, orig)| *orig == "i")
        .map(|(anon, _)| anon.clone());
    assert!(
        anon_name.is_some(),
        "loop index 'i' should appear in symbol_table"
    );
    let anon = anon_name.unwrap();
    assert!(
        anon.starts_with("idx"),
        "loop index should get 'idx' prefix, got '{anon}'"
    );
}

#[test]
fn anonymizer_symbol_table_round_trip() {
    let src = "void f(int value, char *buffer) { int result = value + 1; }";
    let (anon_cpg, symbol_table) = anonymize(src);
    // For every anon name in the CPG text, the symbol_table maps back to the original.
    let anon_ids: Vec<String> = anon_cpg
        .ast
        .values()
        .filter(|n| n.node_type == "identifier")
        .filter_map(|n| n.text.clone())
        .filter(|t| t.starts_with("var") || t.starts_with("idx") || t.starts_with("tmp"))
        .collect();
    for anon_name in &anon_ids {
        assert!(
            symbol_table.contains_key(anon_name.as_str()),
            "anon name '{anon_name}' not found in symbol_table"
        );
    }
}
