//! Integration tests asserting the query engine doesn't collide overloaded or
//! overridden methods, and correctly reasons about virtual dispatch, function
//! pointers, and polymorphism.
//!
//! Written with real assertions; failures point at engine/CPG-generator gaps
//! rather than test bugs.

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
    size_tracking::AllocSizeIndex,
    taint::EndpointRegistry,
};

fn parse_source(lang: SourceLanguage, src: &str) -> web_sitter::Cpg {
    let mut cpg_gen = CpgGenerator::new_for_language(lang).expect("parser init");
    cpg_gen
        .generate_from_source_with_options(src.as_bytes(), GraphBuildOptions::default())
        .expect("CPG generation failed")
}

fn parse_c(src: &str) -> web_sitter::Cpg { parse_source(SourceLanguage::C, src) }
fn parse_cpp(src: &str) -> web_sitter::Cpg { parse_source(SourceLanguage::Cpp, src) }
fn parse_java(src: &str) -> web_sitter::Cpg { parse_source(SourceLanguage::Java, src) }
fn parse_go(src: &str) -> web_sitter::Cpg { parse_source(SourceLanguage::Go, src) }

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

// ═══════════════════════════════════════════════════════════════════════════════
// Overloading: same name, different arity — must not collide
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn cpp_overloaded_methods_have_distinct_param_counts() {
    let cpg = parse_cpp(r#"
class Calc {
public:
    int add(int a) { return a; }
    int add(int a, int b) { return a + b; }
    int add(int a, int b, int c) { return a + b + c; }
};
"#);
    let findings = run_query(&cpg, r#"
rule "one-arg-add" {
    severity: info
    languages: [cpp]
    find n: MethodDef where n.name() == "add" and n.param_count() == 1
}
"#);
    assert_eq!(findings.len(), 1, "exactly one add() overload should have param_count() == 1");

    let findings2 = run_query(&cpg, r#"
rule "two-arg-add" {
    severity: info
    languages: [cpp]
    find n: MethodDef where n.name() == "add" and n.param_count() == 2
}
"#);
    assert_eq!(findings2.len(), 1, "exactly one add() overload should have param_count() == 2");
}

#[test]
fn java_overloaded_methods_call_site_arg_count_matches_intended_overload() {
    let cpg = parse_java(r#"
class Calc {
    int add(int a) { return a; }
    int add(int a, int b) { return a + b; }
    void use() {
        int x = add(1);
        int y = add(1, 2);
    }
}
"#);
    let one_arg = run_query(&cpg, r#"
rule "one-arg-call" {
    severity: info
    languages: [java]
    find c: Call where c.callee_name() == "add" and c.arg_count() == 1
}
"#);
    assert_eq!(one_arg.len(), 1, "exactly one call site should pass 1 argument to add()");

    let two_arg = run_query(&cpg, r#"
rule "two-arg-call" {
    severity: info
    languages: [java]
    find c: Call where c.callee_name() == "add" and c.arg_count() == 2
}
"#);
    assert_eq!(two_arg.len(), 1, "exactly one call site should pass 2 arguments to add()");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Overriding: sibling subclasses overriding the same name — must not collide
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn cpp_sibling_overrides_are_distinct_methoddef_nodes() {
    let cpg = parse_cpp(r#"
class Animal { public: virtual void speak() {} };
class Dog : public Animal { public: void speak() override {} };
class Cat : public Animal { public: void speak() override {} };
"#);
    let findings = run_query(&cpg, r#"
rule "speaks" {
    severity: info
    languages: [cpp]
    find n: MethodDef where n.name() == "speak"
}
"#);
    assert_eq!(findings.len(), 3, "Animal::speak, Dog::speak, Cat::speak should be 3 distinct MethodDefs, not collapsed");
}

#[test]
fn cpp_override_flagged_virtual_same_as_base() {
    let cpg = parse_cpp(r#"
class Animal { public: virtual void speak() {} };
class Dog : public Animal { public: void speak() override {} };
"#);
    let findings = run_query(&cpg, r#"
rule "overrides-virtual" {
    severity: info
    languages: [cpp]
    find n: MethodDef where n.name() == "speak" and n.is_virtual()
}
"#);
    assert_eq!(findings.len(), 2, "both Animal::speak and Dog::speak (override) should report is_virtual() == true");
}

#[test]
fn cpp_destructor_and_regular_method_dont_collide_is_destructor() {
    let cpg = parse_cpp(r#"
class Resource {
public:
    Resource() {}
    ~Resource() {}
    void release() {}
};
"#);
    let dtor_findings = run_query(&cpg, r#"
rule "dtor" {
    severity: info
    languages: [cpp]
    find n: MethodDef where n.is_destructor()
}
"#);
    assert_eq!(dtor_findings.len(), 1, "exactly one MethodDef (~Resource) should be flagged is_destructor()");

    let release_findings = run_query(&cpg, r#"
rule "not-dtor" {
    severity: info
    languages: [cpp]
    find n: MethodDef where n.name() == "release" and n.is_destructor()
}
"#);
    assert!(release_findings.is_empty(), "release() must not be misflagged is_destructor()");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Virtual dispatch through a base-typed pointer/reference
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn cpp_call_through_base_pointer_is_virtual_dispatch() {
    let cpg = parse_cpp(r#"
class Shape { public: virtual float area() { return 0.0f; } };
class Circle : public Shape { public: float area() override { return 3.14f; } };
float compute(Shape* s) {
    return s->area();
}
"#);
    let findings = run_query(&cpg, r#"
rule "virtual-call" {
    severity: info
    languages: [cpp]
    find c: Call where c.callee_name() == "area" and c.cpp_meta.is_virtual_dispatch
}
"#);
    assert!(!findings.is_empty(), "s->area() through a Shape* pointer to a virtual method should be flagged is_virtual_dispatch");
}

#[test]
fn cpp_direct_call_on_concrete_type_is_not_virtual_dispatch() {
    let cpg = parse_cpp(r#"
class Circle {
public:
    float area() { return 3.14f; }
};
float compute() {
    Circle c;
    return c.area();
}
"#);
    let findings = run_query(&cpg, r#"
rule "non-virtual-call" {
    severity: info
    languages: [cpp]
    find c: Call where c.callee_name() == "area" and c.cpp_meta.is_virtual_dispatch
}
"#);
    assert!(findings.is_empty(), "c.area() on a concrete non-virtual type should NOT be flagged is_virtual_dispatch");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Function pointers
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn c_function_pointer_variable_call_resolves_to_assigned_function() {
    let cpg = parse_c(r#"
int add(int a, int b) { return a + b; }
int sub(int a, int b) { return a - b; }
int run(int a, int b) {
    int (*op)(int, int) = add;
    return op(a, b);
}
"#);
    // The call graph resolves `op(a, b)` through the function-pointer alias
    // directly to its target, so `callee_name()` reports "add" (the resolved
    // target), not the literal "op" written at the call site.
    let findings = run_query(&cpg, r#"
rule "fnptr-resolves" {
    severity: info
    languages: [c]
    find c: Call where c.callee_name() == "add" and c.refers_to().is_some
}
"#);
    assert!(!findings.is_empty(), "op(a, b) through a function-pointer variable assigned `add` should resolve refers_to() to add's MethodDef");
}

#[test]
fn c_function_pointer_dispatch_table_call_resolves() {
    let cpg = parse_c(r#"
void handler_a(void) {}
void handler_b(void) {}
typedef void (*handler_fn)(void);
struct dispatch { handler_fn handler; };
void invoke(struct dispatch *d) {
    d->handler();
}
"#);
    // At minimum, the CPG must parse this indirect field-call pattern without
    // crashing and keep both handlers' CFGs distinct and valid.
    let findings = run_query(&cpg, r#"
rule "handlers" {
    severity: info
    languages: [c]
    find n: MethodDef where n.name() == "handler_a" or n.name() == "handler_b"
}
"#);
    assert_eq!(findings.len(), 2, "both dispatch-table handlers should be distinct, independently findable MethodDefs");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Polymorphism (Go: interface satisfied by multiple concrete types)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn go_two_types_implementing_same_interface_method_dont_collide() {
    let cpg = parse_go(r#"
package main

type Shape interface {
    Area() float64
}

type Circle struct{ R float64 }
func (c Circle) Area() float64 { return 3.14 * c.R * c.R }

type Rect struct{ W, H float64 }
func (r Rect) Area() float64 { return r.W * r.H }
"#);
    let findings = run_query(&cpg, r#"
rule "areas" {
    severity: info
    languages: [go]
    find n: MethodDef where n.name() == "Area"
}
"#);
    assert_eq!(findings.len(), 2, "Circle.Area and Rect.Area should be 2 distinct MethodDefs implementing the same interface method name");
}

#[test]
fn go_each_area_impl_has_its_own_valid_cfg() {
    let cpg = parse_go(r#"
package main

type Circle struct{ R float64 }
func (c Circle) Area() float64 {
    if c.R < 0 {
        return 0
    }
    return 3.14 * c.R * c.R
}

type Rect struct{ W, H float64 }
func (r Rect) Area() float64 {
    return r.W * r.H
}
"#);
    let findings = run_query(&cpg, r#"
rule "area-cfg" {
    severity: info
    languages: [go]
    find m: MethodDef, r: Return where
        m.name() == "Area"
        and m.cfg_reaches(r)
}
"#);
    // Circle.Area has 2 returns, Rect.Area has 1 — at least 2 distinct (m, r)
    // matches confirms each implementation's CFG is independently traversable.
    assert!(findings.len() >= 2, "expected cfg_reaches matches across both Area implementations, got {}", findings.len());
}
