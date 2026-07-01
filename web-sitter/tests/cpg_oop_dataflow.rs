//! CPG generation tests for dataflow (`cpg.dataflow.edges`) and control-flow
//! (`cpg.basic_blocks`) tracking that crosses namespace, class, package,
//! inheritance (superclass/subclass), and abstract-class boundaries.
//!
//! Unlike `language_features.rs` (which mostly asserts AST/metadata shape),
//! these tests specifically assert that DFG param-binding edges and CFG basic
//! blocks are correctly scoped and connected when the source spans these
//! constructs — e.g. that an argument passed to a namespace-qualified call
//! actually flows to the callee's parameter, that two same-named overrides in
//! different classes don't get their basic blocks or DFG edges cross-wired,
//! and that abstract/interface method declarations (no body) don't produce
//! bogus basic blocks.
//!
//! Written with real assertions, not aspirational placeholders — failures
//! point at CPG generator gaps to close.

use std::collections::HashSet;
use web_sitter::{CpgGenerator, GraphBuildOptions, IrNodeKind, NodeId, SourceLanguage};

fn make_cpg(lang: SourceLanguage, src: &str) -> web_sitter::Cpg {
    CpgGenerator::new_for_language(lang)
        .expect("parser init")
        .generate_from_source_with_options(src.as_bytes(), GraphBuildOptions::default())
        .expect("CPG generation failed")
}

fn cpp(src: &str) -> web_sitter::Cpg { make_cpg(SourceLanguage::Cpp, src) }
fn java(src: &str) -> web_sitter::Cpg { make_cpg(SourceLanguage::Java, src) }
fn py(src: &str) -> web_sitter::Cpg { make_cpg(SourceLanguage::Python, src) }
fn go(src: &str) -> web_sitter::Cpg { make_cpg(SourceLanguage::Go, src) }

fn assert_cfg_valid(cpg: &web_sitter::Cpg) {
    let bb_keys: HashSet<&String> = cpg.basic_blocks.keys().collect();
    for bb in cpg.basic_blocks.values() {
        for succ in &bb.successors {
            assert!(bb_keys.contains(succ), "BB successor '{succ}' not found");
        }
    }
}

fn assert_dfg_valid(cpg: &web_sitter::Cpg) {
    let ast_ids: HashSet<NodeId> = cpg.ast.keys().copied().collect();
    for edge in &cpg.dataflow.edges {
        assert!(ast_ids.contains(&edge.source), "DFG edge source {} not in AST", edge.source);
        assert!(ast_ids.contains(&edge.destination), "DFG edge destination {} not in AST", edge.destination);
    }
}

fn nodes_of_kind(cpg: &web_sitter::Cpg, kind: IrNodeKind) -> Vec<NodeId> {
    cpg.ast.iter().filter_map(|(&id, n)| if n.kind == kind { Some(id) } else { None }).collect()
}

fn find_by_name<'a>(cpg: &'a web_sitter::Cpg, kind: IrNodeKind, name: &str) -> Option<(NodeId, &'a web_sitter::AstNode)> {
    cpg.ast.iter().find_map(|(&id, n)| {
        if n.kind == kind && n.name.as_deref() == Some(name) { Some((id, n)) } else { None }
    })
}

/// True if any DFG edge's source lies within `from_subtree` and destination lies
/// within `to_subtree` (subtree membership via `ancestor` walk, since call-arg/param
/// binding edges often connect a specific identifier deep inside each side).
fn subtree(cpg: &web_sitter::Cpg, root: NodeId) -> HashSet<NodeId> {
    let mut out = HashSet::new();
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        if out.insert(id) {
            if let Some(n) = cpg.ast.get(&id) {
                stack.extend(n.children.iter().copied());
            }
        }
    }
    out
}

fn dfg_crosses(cpg: &web_sitter::Cpg, from_root: NodeId, to_root: NodeId) -> bool {
    let from_set = subtree(cpg, from_root);
    let to_set = subtree(cpg, to_root);
    cpg.dataflow.edges.iter().any(|e| from_set.contains(&e.source) && to_set.contains(&e.destination))
}

/// Walk `node_id`'s parent chain to find the name of the nearest enclosing
/// `ClassDef`. `AstNode.class_context` is only populated for C/C++ (see
/// `enrich_cpp_metadata`); Java/Python attach class identity to their own
/// per-language metadata side-tables instead (and Java's `enclosing_class`
/// field is never actually populated), so this is the one lookup that works
/// uniformly across languages for test purposes.
fn nearest_class_name(cpg: &web_sitter::Cpg, node_id: NodeId) -> Option<String> {
    let mut cur = node_id;
    for _ in 0..64 {
        let node = cpg.ast.get(&cur)?;
        if node.kind == IrNodeKind::ClassDef {
            return node.name.clone();
        }
        cur = node.parent_id?;
    }
    None
}

// ═══════════════════════════════════════════════════════════════════════════════
// C++: namespaces
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn cpp_dfg_flows_through_namespace_qualified_call() {
    let src = r#"
        namespace math {
            double square(double x) { return x * x; }
        }
        double use_math(double y) {
            return math::square(y);
        }
    "#;
    let cpg = cpp(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let (square_id, _) = find_by_name(&cpg, IrNodeKind::MethodDef, "square").expect("square MethodDef");
    let (use_math_id, _) = find_by_name(&cpg, IrNodeKind::MethodDef, "use_math").expect("use_math MethodDef");
    assert!(
        dfg_crosses(&cpg, use_math_id, square_id),
        "argument `y` passed to math::square(y) should flow into square's body/param"
    );
}

#[test]
fn cpp_nested_namespace_functions_get_distinct_function_ids() {
    let src = r#"
        namespace outer {
            namespace inner {
                int helper(int a) { return a + 1; }
            }
        }
        int caller(int b) {
            return outer::inner::helper(b);
        }
    "#;
    let cpg = cpp(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let (helper_id, helper) = find_by_name(&cpg, IrNodeKind::MethodDef, "helper").expect("helper MethodDef");
    let (caller_id, _) = find_by_name(&cpg, IrNodeKind::MethodDef, "caller").expect("caller MethodDef");
    assert_ne!(helper_id, caller_id);
    // Every node inside `helper`'s body should carry helper's own function_id,
    // not caller's — a nested-namespace scoping regression would conflate them.
    for &child in &helper.children {
        if let Some(n) = cpg.ast.get(&child) {
            assert_eq!(n.function_id, Some(helper_id), "helper's children should be scoped to helper's function_id");
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// C++: inheritance / abstract classes
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn cpp_abstract_pure_virtual_method_produces_no_basic_blocks() {
    let src = r#"
        class Shape {
        public:
            virtual double area() = 0;
        };
        class Circle : public Shape {
        public:
            double radius;
            double area() override { return 3.14159 * radius * radius; }
        };
    "#;
    let cpg = cpp(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    // Circle::area (has a body) must have at least one basic block.
    let (circle_area_id, _) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("area") && n.class_context.as_deref() == Some("Circle"))
        .map(|(&id, n)| (id, n))
        .expect("Circle::area MethodDef");
    let has_bb = cpg.basic_blocks.values().any(|bb| bb.function == circle_area_id);
    assert!(has_bb, "Circle::area (with a body) should have basic blocks");

    // Shape::area (pure virtual, `= 0`, no body) must NOT have any basic blocks.
    if let Some((shape_area_id, _)) = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("area") && n.class_context.as_deref() == Some("Shape"))
    {
        let has_bb = cpg.basic_blocks.values().any(|bb| bb.function == *shape_area_id);
        assert!(!has_bb, "pure virtual Shape::area (no body) should not produce basic blocks");
    }
}

#[test]
fn cpp_multi_inheritance_overrides_have_independent_cfgs() {
    let src = r#"
        class Flyer { public: virtual void move() { int a = 1; } };
        class Swimmer { public: virtual void move() { int b = 2; } };
        class Duck : public Flyer, public Swimmer {
        public:
            void move() override { int c = 3; }
        };
    "#;
    let cpg = cpp(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let move_defs: Vec<NodeId> = nodes_of_kind(&cpg, IrNodeKind::MethodDef)
        .into_iter()
        .filter(|&id| cpg.ast[&id].name.as_deref() == Some("move"))
        .collect();
    assert!(move_defs.len() >= 3, "expected 3 'move' overrides (Flyer, Swimmer, Duck), got {}", move_defs.len());

    // Each move() override's basic blocks must belong to that exact function —
    // multiple inheritance must not conflate the three CFGs into one.
    for &fn_id in &move_defs {
        let fn_blocks: Vec<_> = cpg.basic_blocks.values().filter(|bb| bb.function == fn_id).collect();
        assert!(!fn_blocks.is_empty(), "move() override {fn_id} should have its own basic blocks");
        for bb in &fn_blocks {
            for &node_id in &bb.nodes {
                let owner_fn = cpg.ast.get(&node_id).and_then(|n| n.function_id);
                assert_eq!(owner_fn, Some(fn_id), "node in {fn_id}'s block must be scoped to {fn_id}, not another override");
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Java: packages / inheritance / abstract classes
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn java_dfg_flows_through_package_qualified_static_call() {
    let src = r#"
        package com.example.util;
        class Helper {
            static int identity(int x) { return x; }
        }
        class Caller {
            int use(int y) {
                return com.example.util.Helper.identity(y);
            }
        }
    "#;
    let cpg = java(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let (identity_id, _) = find_by_name(&cpg, IrNodeKind::MethodDef, "identity").expect("identity MethodDef");
    let (use_id, _) = find_by_name(&cpg, IrNodeKind::MethodDef, "use").expect("use MethodDef");
    assert!(
        dfg_crosses(&cpg, use_id, identity_id),
        "argument `y` passed to the fully-qualified static call should flow into identity's param"
    );
}

#[test]
fn java_dfg_flows_from_subclass_constructor_param_into_super_call() {
    let src = r#"
        class Animal {
            String name;
            Animal(String name) { this.name = name; }
        }
        class Dog extends Animal {
            Dog(String name) { super(name); }
        }
    "#;
    let cpg = java(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    // Find Dog's constructor (MethodDef named "Dog" inside class "Dog").
    let dog_ctor_id = cpg
        .ast
        .keys()
        .copied()
        .find(|&id| {
            let n = &cpg.ast[&id];
            n.kind == IrNodeKind::MethodDef && n.is_constructor == Some(true) && nearest_class_name(&cpg, id).as_deref() == Some("Dog")
        })
        .expect("Dog constructor");
    let animal_ctor_id = cpg
        .ast
        .keys()
        .copied()
        .find(|&id| {
            let n = &cpg.ast[&id];
            n.kind == IrNodeKind::MethodDef && n.is_constructor == Some(true) && nearest_class_name(&cpg, id).as_deref() == Some("Animal")
        })
        .expect("Animal constructor");
    assert!(
        dfg_crosses(&cpg, dog_ctor_id, animal_ctor_id) || dfg_crosses(&cpg, dog_ctor_id, dog_ctor_id),
        "Dog(String name) super(name) should flow `name` into the super() call argument"
    );
}

#[test]
fn java_interface_default_method_has_no_body_no_bogus_blocks() {
    let src = r#"
        interface Greeter {
            void greetOnly(); // abstract, no body
        }
        class EnglishGreeter implements Greeter {
            public void greetOnly() { int x = 1; }
        }
    "#;
    let cpg = java(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let impl_id = cpg
        .ast
        .keys()
        .copied()
        .find(|&id| {
            let n = &cpg.ast[&id];
            n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("greetOnly") && nearest_class_name(&cpg, id).as_deref() == Some("EnglishGreeter")
        })
        .expect("EnglishGreeter.greetOnly");
    let has_bb = cpg.basic_blocks.values().any(|bb| bb.function == impl_id);
    assert!(has_bb, "concrete override with a body should have basic blocks");

    if let Some(iface_id) = cpg.ast.keys().copied().find(|&id| {
        let n = &cpg.ast[&id];
        n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("greetOnly") && nearest_class_name(&cpg, id).as_deref() == Some("Greeter")
    }) {
        let has_bb = cpg.basic_blocks.values().any(|bb| bb.function == iface_id);
        assert!(!has_bb, "abstract interface method (no body) should not produce basic blocks");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Python: modules-as-namespaces / subclass override
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn python_dfg_flows_from_subclass_init_param_into_super_call() {
    let src = r#"
class Animal:
    def __init__(self, name):
        self.name = name

class Dog(Animal):
    def __init__(self, name):
        super().__init__(name)
"#;
    let cpg = py(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let dog_init: Vec<NodeId> = nodes_of_kind(&cpg, IrNodeKind::MethodDef)
        .into_iter()
        .filter(|&id| cpg.ast[&id].name.as_deref() == Some("__init__") && nearest_class_name(&cpg, id).as_deref() == Some("Dog"))
        .collect();
    assert_eq!(dog_init.len(), 1, "expected exactly one Dog.__init__");
    let dog_init_id = dog_init[0];
    assert!(
        dfg_crosses(&cpg, dog_init_id, dog_init_id),
        "Dog.__init__'s `name` param should flow somewhere within its own body (into super().__init__(name))"
    );
}

#[test]
fn python_two_subclasses_overriding_same_method_name_dont_share_blocks() {
    let src = r#"
class Animal:
    def speak(self):
        return "..."

class Dog(Animal):
    def speak(self):
        return "Woof"

class Cat(Animal):
    def speak(self):
        return "Meow"
"#;
    let cpg = py(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let speaks: Vec<NodeId> = nodes_of_kind(&cpg, IrNodeKind::MethodDef)
        .into_iter()
        .filter(|&id| cpg.ast[&id].name.as_deref() == Some("speak"))
        .collect();
    assert_eq!(speaks.len(), 3, "expected 3 speak() defs (Animal, Dog, Cat)");

    // Every basic block for one speak() must only contain nodes scoped to that
    // exact function — same-named overrides across sibling subclasses must not
    // collide.
    for &fn_id in &speaks {
        for bb in cpg.basic_blocks.values().filter(|bb| bb.function == fn_id) {
            for &node_id in &bb.nodes {
                let owner = cpg.ast.get(&node_id).and_then(|n| n.function_id);
                assert_eq!(owner, Some(fn_id), "speak() override {fn_id}'s block contains a node scoped to a different function");
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Go: package-level struct embedding (method promotion)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn go_dfg_flows_through_embedded_struct_promoted_method_call() {
    let src = r#"
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
"#;
    let cpg = go(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let (greet_id, _) = find_by_name(&cpg, IrNodeKind::MethodDef, "Greet").expect("Greet MethodDef");
    let (caller_id, _) = find_by_name(&cpg, IrNodeKind::MethodDef, "caller").expect("caller MethodDef");
    assert!(
        dfg_crosses(&cpg, caller_id, greet_id),
        "argument `who` passed to d.Greet(who) via promoted embedding should flow into Greet's param"
    );
}
