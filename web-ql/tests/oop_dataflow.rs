//! WQL-level integration tests for dataflow/control-flow predicates
//! (`dfg_reaches`, `cfg_reaches`, `refers_to`, `same_function`) evaluated over
//! constructs that cross namespace, class, package, and inheritance
//! (superclass/subclass/abstract-class) boundaries.
//!
//! Complements `web-sitter/tests/cpg_oop_dataflow.rs` (which checks the raw
//! CPG edges) by exercising the same constructs through the query engine —
//! i.e. through `KindIndex`/`DfgIndex`/`FunctionCfg` as a rule author would.

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

fn parse_cpp(src: &str) -> web_sitter::Cpg { parse_source(SourceLanguage::Cpp, src) }
fn parse_java(src: &str) -> web_sitter::Cpg { parse_source(SourceLanguage::Java, src) }
fn parse_python(src: &str) -> web_sitter::Cpg { parse_source(SourceLanguage::Python, src) }
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
// Namespaces
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn cpp_dfg_reaches_through_namespace_qualified_call() {
    let cpg = parse_cpp(r#"
namespace math {
    double square(double x) { return x * x; }
}
double use_math(double y) {
    return math::square(y);
}
"#);
    let findings = run_query(&cpg, r#"
rule "ns-flow" {
    severity: info
    languages: [cpp]
    find p: ParamDef, c: Call where
        p.name() == "y"
        and c.callee_name() == "math::square"
        and p.dfg_reaches(c)
}
"#);
    assert!(!findings.is_empty(), "param `y` should dfg_reach the math::square(y) call");
}

// TDD-red: `enrich_cpp_metadata`'s namespace-context walk (cpg_generator.rs)
// assigns each descendant node the *first* enclosing namespace it finds via a
// first-wins `or_insert`, so for `namespace outer { namespace inner { ... } }`
// every node under `inner` gets tagged with namespace "outer" only — "inner"
// is silently dropped. `function_name_to_id` is registered from that single
// flat `namespace` field, so it only ever gets a key for one level of nesting
// ("outer::helper") and never composes the full "outer::inner::helper" path
// the call site actually uses, so `refers_to()` returns Null here. Fixing this
// needs the namespace-context walk itself to accumulate the full nested path,
// not just the call-graph qualification lookup — left as a known gap.
#[test]
fn cpp_deeply_nested_namespace_call_resolves_callee() {
    let cpg = parse_cpp(r#"
namespace outer {
    namespace inner {
        int helper(int a) { return a + 1; }
    }
}
int caller(int b) {
    return outer::inner::helper(b);
}
"#);
    let findings = run_query(&cpg, r#"
rule "resolve" {
    severity: info
    languages: [cpp]
    find c: Call where
        c.callee_name() == "outer::inner::helper"
        and c.refers_to().is_some
}
"#);
    assert!(!findings.is_empty(), "outer::inner::helper(b) should resolve refers_to() to the MethodDef");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Classes / packages (Java)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn java_dfg_reaches_through_package_qualified_static_call() {
    let cpg = parse_java(r#"
package com.example.util;
class Helper {
    static int identity(int x) { return x; }
}
class Caller {
    int use(int y) {
        return com.example.util.Helper.identity(y);
    }
}
"#);
    let findings = run_query(&cpg, r#"
rule "pkg-flow" {
    severity: info
    languages: [java]
    find p: ParamDef, c: Call where
        p.name() == "y"
        and c.callee_name() == "identity"
        and p.dfg_reaches(c)
}
"#);
    assert!(!findings.is_empty(), "param `y` should dfg_reach the package-qualified identity(y) call");
}

#[test]
fn java_subclass_and_superclass_same_function_is_false() {
    let cpg = parse_java(r#"
class Animal {
    String speak() { return "..."; }
}
class Dog extends Animal {
    String speak() { return "Woof"; }
}
"#);
    let findings = run_query(&cpg, r#"
rule "cross-class" {
    severity: info
    languages: [java]
    find r1: Return, r2: Return where
        r1.id() != r2.id()
        and not r1.same_function(r2)
}
"#);
    assert!(!findings.is_empty(), "Animal.speak's return and Dog.speak's return must not be same_function()");
}

#[test]
fn java_abstract_class_subclass_method_cfg_reaches_return() {
    let cpg = parse_java(r#"
abstract class Shape {
    abstract double area();
}
class Circle extends Shape {
    double radius;
    double area() {
        double r2 = radius * radius;
        return 3.14159 * r2;
    }
}
"#);
    let findings = run_query(&cpg, r#"
rule "cfg-reach" {
    severity: info
    languages: [java]
    find m: MethodDef, r: Return where
        m.name() == "area"
        and m.cfg_reaches(r)
}
"#);
    assert!(!findings.is_empty(), "Circle.area's entry should cfg_reach its return statement");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Python: module-as-namespace + super() dataflow
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn python_dfg_reaches_from_subclass_init_param_into_super_call() {
    let cpg = parse_python(r#"
class Animal:
    def __init__(self, name):
        self.name = name

class Dog(Animal):
    def __init__(self, name):
        super().__init__(name)
"#);
    let findings = run_query(&cpg, r#"
rule "super-flow" {
    severity: info
    languages: [python]
    find p: ParamDef, c: Call where
        p.name() == "name"
        and c.callee_name() == "__init__"
        and p.dfg_reaches(c)
        and p.same_function(c)
}
"#);
    assert!(!findings.is_empty(), "Dog.__init__'s `name` param should dfg_reach super().__init__(name) within the same function");
}

#[test]
fn python_two_sibling_subclass_overrides_dont_collide_in_refers_to() {
    let cpg = parse_python(r#"
class Animal:
    def speak(self):
        return "..."

class Dog(Animal):
    def speak(self):
        return "Woof"

def make_dog_speak(d):
    return d.speak()
"#);
    // Both Dog.speak and Animal.speak exist with the same name; a direct-name
    // call on an unqualified receiver like `d.speak()` should still resolve
    // to exactly one MethodDef (not silently fan out to a wrong node), and
    // whichever it resolves to must be an actual `speak` MethodDef, not the
    // constructor or another unrelated method.
    let findings = run_query(&cpg, r#"
rule "resolve-speak" {
    severity: info
    languages: [python]
    find c: Call where
        c.callee_name() == "speak"
        and c.refers_to().is_some
}
"#);
    assert!(!findings.is_empty(), "d.speak() should resolve refers_to() to a concrete MethodDef");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Go: package-level struct embedding
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn go_dfg_reaches_through_embedded_struct_promoted_method() {
    let cpg = parse_go(r#"
package main

type Base struct{}

func (b Base) Greet(name string) string {
    return "Hello, " + name
}

type Derived struct {
    Base
}

func caller(who string) string {
    d := Derived{}
    return d.Greet(who)
}
"#);
    let findings = run_query(&cpg, r#"
rule "embed-flow" {
    severity: info
    languages: [go]
    find p: ParamDef, c: Call where
        p.name() == "who"
        and c.callee_name() == "Greet"
        and p.dfg_reaches(c)
}
"#);
    assert!(!findings.is_empty(), "param `who` should dfg_reach d.Greet(who) via promoted embedding");
}

#[test]
fn go_cfg_reaches_within_method_defined_on_embedded_type() {
    let cpg = parse_go(r#"
package main

type Base struct{}

func (b Base) Process(x int) int {
    if x > 0 {
        return x * 2
    }
    return 0
}
"#);
    let findings = run_query(&cpg, r#"
rule "cfg-embed" {
    severity: info
    languages: [go]
    find m: MethodDef, r: Return where
        m.name() == "Process"
        and m.cfg_reaches(r)
}
"#);
    assert!(!findings.is_empty(), "Process's entry should cfg_reach at least one of its two return statements");
}
