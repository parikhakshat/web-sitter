//! Integration tests for `AllocSizeIndex` across languages and collection/string
//! types: fixed arrays, lists, tuples, strings, and byte strings.
//!
//! Written TDD-style: these assert the size tracker SHOULD report a size for
//! these constructs. Some fail against the current implementation, which only
//! recognizes C-style `array_declarator` sizes and a raw tree-sitter kind of
//! exactly `"string_literal"` (true for C/C++/Java/Rust, but not Go's
//! `interpreted_string_literal`, or Python/JS/TS's `"string"`), plus heap
//! allocator call arguments. Failures here point at engine gaps to close, not
//! test bugs.

use std::collections::HashMap;

use web_sitter::{CpgGenerator, GraphBuildOptions, IrNodeKind, NodeId, SourceLanguage};
use web_ql::{
    alias::AliasIndex,
    cfg::FunctionCfg,
    dfg::DfgIndex,
    engine::{EvalContext, RuleRunner},
    finding::Finding,
    loader::compile_rules,
    kind_index::KindIndex,
    nullability::NullabilityIndex,
    size_tracking::{AllocSizeIndex, SizeValue},
    taint::EndpointRegistry,
};

// ── Test helpers (mirrors tests/integration.rs) ────────────────────────────────

fn parse_source(lang: SourceLanguage, src: &str) -> web_sitter::Cpg {
    let mut cpg_gen = CpgGenerator::new_for_language(lang).expect("parser init");
    cpg_gen
        .generate_from_source_with_options(src.as_bytes(), GraphBuildOptions::default())
        .expect("CPG generation failed")
}

fn parse_c(src: &str) -> web_sitter::Cpg { parse_source(SourceLanguage::C, src) }
fn parse_cpp(src: &str) -> web_sitter::Cpg { parse_source(SourceLanguage::Cpp, src) }
fn parse_java(src: &str) -> web_sitter::Cpg { parse_source(SourceLanguage::Java, src) }
fn parse_python(src: &str) -> web_sitter::Cpg { parse_source(SourceLanguage::Python, src) }
fn parse_go(src: &str) -> web_sitter::Cpg { parse_source(SourceLanguage::Go, src) }
fn parse_js(src: &str) -> web_sitter::Cpg { parse_source(SourceLanguage::JavaScript, src) }
fn parse_ts(src: &str) -> web_sitter::Cpg { parse_source(SourceLanguage::TypeScript, src) }
fn parse_rust(src: &str) -> web_sitter::Cpg { parse_source(SourceLanguage::Rust, src) }

fn run_query(cpg: &web_sitter::Cpg, rule_src: &str) -> Vec<Finding> {
    let dfg = DfgIndex::build(cpg);
    let alias = AliasIndex::build(cpg);
    let sizes = AllocSizeIndex::build(cpg);
    let kind_index = KindIndex::build(cpg);
    let nullability = NullabilityIndex::build(cpg, &kind_index);
    let cfg_cache: HashMap<NodeId, FunctionCfg> = cpg
        .ast
        .iter()
        .filter(|(_, n)| n.kind == IrNodeKind::MethodDef)
        .map(|(&id, _)| (id, FunctionCfg::build_for_function(cpg, id)))
        .collect();
    let summaries = HashMap::new();
    let registry = EndpointRegistry::new();
    let predicate_plans = HashMap::new();
    let predicate_params: HashMap<String, Vec<String>> = HashMap::new();

    let ctx = EvalContext {
        cpg,
        current_file: std::path::Path::new("test"),
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

    let rule_set = compile_rules(rule_src).unwrap_or_else(|e| panic!("rule compilation failed: {e}"));
    RuleRunner::new(ctx).run(&rule_set)
}

/// Directly inspect `AllocSizeIndex` for the first Literal/CollectionExpr/CompositeLit/
/// ArrayInit node matching `pred`, returning its computed `SizeValue`.
fn size_of_first<F: Fn(&web_sitter::AstNode) -> bool>(cpg: &web_sitter::Cpg, pred: F) -> SizeValue {
    let sizes = AllocSizeIndex::build(cpg);
    let node_id = cpg
        .ast
        .iter()
        .find_map(|(&id, n)| if pred(n) { Some(id) } else { None })
        .unwrap_or_else(|| panic!("no matching node found"));
    sizes.size_of(node_id)
}

fn is_concrete(sv: &SizeValue, expected: i64) -> bool {
    matches!(sv, SizeValue::Concrete(n) if *n == expected)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Fixed-size arrays (already-supported baseline — C/C++)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn c_fixed_array_declarator_size_known() {
    let cpg = parse_c("void f(void) { int buf[16]; }");
    let sv = size_of_first(&cpg, |n| n.node_type == "array_declarator");
    assert!(is_concrete(&sv, 16), "expected Concrete(16), got {sv:?}");
}

#[test]
fn cpp_fixed_array_declarator_size_known() {
    let cpg = parse_cpp("void f() { int buf[32]; }");
    let sv = size_of_first(&cpg, |n| n.node_type == "array_declarator");
    assert!(is_concrete(&sv, 32), "expected Concrete(32), got {sv:?}");
}

// ═══════════════════════════════════════════════════════════════════════════════
// String literals across languages
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn c_string_literal_has_known_size() {
    let cpg = parse_c(r#"void f(void) { char *s = "hello"; }"#);
    let findings = run_query(&cpg, r#"
rule "str-size" {
    severity: info
    languages: [c]
    find n: Literal where n.lit_kind() == "String" and n.has_known_size()
}
"#);
    assert!(!findings.is_empty(), "C string literal should have a known size");
}

#[test]
fn cpp_string_literal_size_matches_content_length() {
    // "hello" = 5 chars + NUL terminator = 6, matching the existing C/C++ convention.
    let cpg = parse_cpp(r#"const char* f() { return "hello"; }"#);
    let sv = size_of_first(&cpg, |n| n.kind == IrNodeKind::Literal && n.lit_kind == Some(web_sitter::LiteralKind::String));
    assert!(is_concrete(&sv, 6), "expected Concrete(6) (5 chars + NUL), got {sv:?}");
}

#[test]
fn java_string_literal_has_known_size() {
    let cpg = parse_java(r#"
class F {
    void f() {
        String s = "hello";
    }
}
"#);
    let findings = run_query(&cpg, r#"
rule "str-size" {
    severity: info
    languages: [java]
    find n: Literal where n.lit_kind() == "String" and n.has_known_size()
}
"#);
    assert!(!findings.is_empty(), "Java string literal should have a known size");
}

#[test]
fn python_string_literal_has_known_size() {
    let cpg = parse_python(r#"s = "hello"
"#);
    let findings = run_query(&cpg, r#"
rule "str-size" {
    severity: info
    languages: [python]
    find n: Literal where n.lit_kind() == "String" and n.has_known_size()
}
"#);
    assert!(!findings.is_empty(), "Python string literal should have a known size");
}

#[test]
fn python_string_literal_size_matches_content_length() {
    let cpg = parse_python(r#"s = "hello"
"#);
    let sv = size_of_first(&cpg, |n| n.kind == IrNodeKind::Literal && n.lit_kind == Some(web_sitter::LiteralKind::String));
    assert!(is_concrete(&sv, 5), "expected Concrete(5) for \"hello\", got {sv:?}");
}

#[test]
fn go_string_literal_has_known_size() {
    let cpg = parse_go(r#"
package main
func f() {
    s := "hello"
    _ = s
}
"#);
    let findings = run_query(&cpg, r#"
rule "str-size" {
    severity: info
    languages: [go]
    find n: Literal where n.lit_kind() == "String" and n.has_known_size()
}
"#);
    assert!(!findings.is_empty(), "Go string literal should have a known size");
}

#[test]
fn js_string_literal_has_known_size() {
    let cpg = parse_js(r#"const s = "hello";"#);
    let findings = run_query(&cpg, r#"
rule "str-size" {
    severity: info
    languages: [javascript]
    find n: Literal where n.lit_kind() == "String" and n.has_known_size()
}
"#);
    assert!(!findings.is_empty(), "JS string literal should have a known size");
}

#[test]
fn ts_string_literal_has_known_size() {
    let cpg = parse_ts(r#"const s: string = "hello";"#);
    let findings = run_query(&cpg, r#"
rule "str-size" {
    severity: info
    languages: [typescript]
    find n: Literal where n.lit_kind() == "String" and n.has_known_size()
}
"#);
    assert!(!findings.is_empty(), "TS string literal should have a known size");
}

#[test]
fn rust_string_literal_has_known_size() {
    let cpg = parse_rust(r#"
fn f() {
    let s = "hello";
}
"#);
    let findings = run_query(&cpg, r#"
rule "str-size" {
    severity: info
    languages: [rust]
    find n: Literal where n.lit_kind() == "String" and n.has_known_size()
}
"#);
    assert!(!findings.is_empty(), "Rust string literal should have a known size");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Byte strings
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn rust_byte_string_literal_has_known_size() {
    let cpg = parse_rust(r#"
fn f() {
    let b = b"hello";
}
"#);
    // tree-sitter-rust lexes byte strings under the same "string_literal" node
    // kind as regular strings (the "b" prefix is just part of the token text),
    // not a distinct "byte_string_literal" kind.
    let sv = size_of_first(&cpg, |n| n.node_type == "string_literal");
    assert!(is_concrete(&sv, 5), "expected Concrete(5) for b\"hello\", got {sv:?}");
}

#[test]
fn python_byte_string_literal_has_known_size() {
    let cpg = parse_python(r#"b = b"hello"
"#);
    // Python's grammar lexes byte strings as the same "string" node as regular
    // strings; the size tracker only needs to report *some* concrete length here.
    let sv = size_of_first(&cpg, |n| n.kind == IrNodeKind::Literal && n.text.as_deref() == Some("b\"hello\""));
    assert!(matches!(sv, SizeValue::Concrete(_)), "expected a concrete size for b\"hello\", got {sv:?}");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Lists / arrays / tuples as element-count collections
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn python_list_literal_element_count() {
    let cpg = parse_python("xs = [1, 2, 3, 4]\n");
    let sv = size_of_first(&cpg, |n| n.node_type == "list");
    assert!(is_concrete(&sv, 4), "expected Concrete(4) elements, got {sv:?}");
}

#[test]
fn python_tuple_literal_element_count() {
    let cpg = parse_python("xs = (1, 2, 3)\n");
    let sv = size_of_first(&cpg, |n| n.node_type == "tuple");
    assert!(is_concrete(&sv, 3), "expected Concrete(3) elements, got {sv:?}");
}

#[test]
fn python_set_literal_element_count() {
    let cpg = parse_python("xs = {1, 2, 3, 4, 5}\n");
    let sv = size_of_first(&cpg, |n| n.node_type == "set");
    assert!(is_concrete(&sv, 5), "expected Concrete(5) elements, got {sv:?}");
}

#[test]
fn js_array_literal_element_count() {
    let cpg = parse_js("const xs = [1, 2, 3];");
    let sv = size_of_first(&cpg, |n| n.node_type == "array");
    assert!(is_concrete(&sv, 3), "expected Concrete(3) elements, got {sv:?}");
}

#[test]
fn ts_array_literal_element_count() {
    let cpg = parse_ts("const xs: number[] = [1, 2, 3, 4];");
    let sv = size_of_first(&cpg, |n| n.node_type == "array");
    assert!(is_concrete(&sv, 4), "expected Concrete(4) elements, got {sv:?}");
}

#[test]
fn rust_array_literal_element_count() {
    let cpg = parse_rust(r#"
fn f() {
    let xs = [1, 2, 3, 4, 5];
}
"#);
    let sv = size_of_first(&cpg, |n| n.node_type == "array_expression");
    assert!(is_concrete(&sv, 5), "expected Concrete(5) elements, got {sv:?}");
}

#[test]
fn java_array_initializer_element_count() {
    let cpg = parse_java(r#"
class F {
    void f() {
        int[] xs = {1, 2, 3};
    }
}
"#);
    let sv = size_of_first(&cpg, |n| n.node_type == "array_initializer");
    assert!(is_concrete(&sv, 3), "expected Concrete(3) elements, got {sv:?}");
}

#[test]
fn go_composite_literal_element_count() {
    let cpg = parse_go(r#"
package main
func f() {
    xs := []int{1, 2, 3, 4}
    _ = xs
}
"#);
    let sv = size_of_first(&cpg, |n| n.node_type == "composite_literal");
    assert!(is_concrete(&sv, 4), "expected Concrete(4) elements, got {sv:?}");
}

#[test]
fn c_initializer_list_element_count() {
    let cpg = parse_c("void f(void) { int xs[] = {1, 2, 3}; }");
    let sv = size_of_first(&cpg, |n| n.node_type == "initializer_list");
    assert!(is_concrete(&sv, 3), "expected Concrete(3) elements, got {sv:?}");
}

// ── Query-engine-level: alloc_size()/has_known_size() over collections ────────

#[test]
fn python_list_alloc_size_queryable_via_wql() {
    let cpg = parse_python("xs = [1, 2, 3, 4, 5]\n");
    let findings = run_query(&cpg, r#"
rule "list-size" {
    severity: info
    languages: [python]
    find n: Node where n.raw_kind() == "list" and n.alloc_size() == 5
}
"#);
    assert!(!findings.is_empty(), "Python list literal alloc_size() should equal element count");
}

#[test]
fn go_slice_literal_alloc_size_queryable_via_wql() {
    let cpg = parse_go(r#"
package main
func f() {
    xs := []int{10, 20, 30}
    _ = xs
}
"#);
    let findings = run_query(&cpg, r#"
rule "slice-size" {
    severity: info
    languages: [go]
    find n: Node where n.raw_kind() == "composite_literal" and n.alloc_size() == 3
}
"#);
    assert!(!findings.is_empty(), "Go slice literal alloc_size() should equal element count");
}
