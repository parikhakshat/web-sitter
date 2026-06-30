//! Unit/integration tests for complex language features across all supported languages.
//!
//! Covers: namespaces, custom structs/types, classes with inheritance, virtual dispatch,
//! overloading/overriding, lambda/closure functions, deep interprocedural chains,
//! cross-file analysis (workspace index), and language-specific quirks.
//!
//! Tests are written with real assertions and are in TDD red state for languages
//! where the lifter is not yet fully implemented.

use std::collections::HashSet;
use web_sitter::{
    CpgGenerator, GraphBuildOptions, IrNodeKind, NodeId, SourceLanguage,
};

// ── Shared helpers ─────────────────────────────────────────────────────────────

fn make_cpg(lang: SourceLanguage, src: &str) -> web_sitter::Cpg {
    CpgGenerator::new_for_language(lang)
        .expect("parser init")
        .generate_from_source_with_options(src.as_bytes(), GraphBuildOptions::default())
        .expect("CPG generation failed")
}

fn cpp(src: &str) -> web_sitter::Cpg {
    make_cpg(SourceLanguage::Cpp, src)
}
fn java(src: &str) -> web_sitter::Cpg {
    make_cpg(SourceLanguage::Java, src)
}
fn py(src: &str) -> web_sitter::Cpg {
    make_cpg(SourceLanguage::Python, src)
}
fn go(src: &str) -> web_sitter::Cpg {
    make_cpg(SourceLanguage::Go, src)
}
fn js(src: &str) -> web_sitter::Cpg {
    make_cpg(SourceLanguage::JavaScript, src)
}
fn ts(src: &str) -> web_sitter::Cpg {
    make_cpg(SourceLanguage::TypeScript, src)
}
fn rs(src: &str) -> web_sitter::Cpg {
    make_cpg(SourceLanguage::Rust, src)
}

fn assert_cfg_valid(cpg: &web_sitter::Cpg) {
    let bb_keys: HashSet<&String> = cpg.basic_blocks.keys().collect();
    for bb in cpg.basic_blocks.values() {
        for succ in &bb.successors {
            assert!(bb_keys.contains(succ), "BB successor '{succ}' not found");
        }
        for exc in &bb.exception_successors {
            assert!(bb_keys.contains(exc), "Exception successor BB '{exc}' not found");
        }
    }
}

fn assert_dfg_valid(cpg: &web_sitter::Cpg) {
    let ast_ids: HashSet<NodeId> = cpg.ast.keys().copied().collect();
    for edge in &cpg.dataflow.edges {
        assert!(ast_ids.contains(&edge.source), "DFG edge source {} not in AST", edge.source);
        assert!(
            ast_ids.contains(&edge.destination),
            "DFG edge destination {} not in AST",
            edge.destination
        );
    }
}

fn find_node_by_kind_and_name<'a>(
    cpg: &'a web_sitter::Cpg,
    kind: IrNodeKind,
    name: &str,
) -> Option<(NodeId, &'a web_sitter::AstNode)> {
    cpg.ast.iter().find_map(|(&id, n)| {
        if n.kind == kind && n.name.as_deref() == Some(name) {
            Some((id, n))
        } else {
            None
        }
    })
}

fn nodes_of_kind(cpg: &web_sitter::Cpg, kind: IrNodeKind) -> Vec<NodeId> {
    cpg.ast.iter().filter_map(|(&id, n)| if n.kind == kind { Some(id) } else { None }).collect()
}

// ═══════════════════════════════════════════════════════════════════════════════
// C++ TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// ── C++: Namespaces ───────────────────────────────────────────────────────────

#[test]
fn cpp_nested_namespaces_produce_namespace_nodes() {
    let src = r#"
        namespace outer {
            namespace inner {
                int value = 42;
                void helper() {}
            }
        }
    "#;
    let cpg = cpp(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let ns_nodes: Vec<_> = cpg.ast.values().filter(|n| n.kind == IrNodeKind::Namespace).collect();
    assert!(!ns_nodes.is_empty(), "nested namespaces should produce Namespace nodes");
}

#[test]
fn cpp_namespace_qualified_function_name() {
    let src = r#"
        namespace math {
            double square(double x) { return x * x; }
            double cube(double x) { return x * x * x; }
        }
        double use_math() {
            return math::square(3.0) + math::cube(2.0);
        }
    "#;
    let cpg = cpp(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let methods: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::MethodDef)
        .collect();
    assert!(methods.len() >= 3, "expected at least 3 function definitions, got {}", methods.len());
    let square = cpg.ast.values().find(|n| n.name.as_deref() == Some("square"));
    assert!(square.is_some(), "function 'square' should be in AST");
}

#[test]
fn cpp_inline_namespace_qualified_name() {
    let src = r#"
        namespace v1 {
            inline namespace v2 {
                struct Point { int x; int y; };
            }
        }
    "#;
    let cpg = cpp(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    assert!(!cpg.ast.is_empty());
}

#[test]
fn cpp_anonymous_namespace() {
    let src = r#"
        namespace {
            static int counter = 0;
            void increment() { counter++; }
        }
    "#;
    let cpg = cpp(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let incr = cpg.ast.values().find(|n| n.name.as_deref() == Some("increment"));
    assert!(incr.is_some(), "anonymous namespace function should appear in AST");
}

// ── C++: Structs and custom types ─────────────────────────────────────────────

#[test]
fn cpp_struct_with_fields_and_methods() {
    let src = r#"
        struct Vector3 {
            float x, y, z;
            Vector3(float x, float y, float z) : x(x), y(y), z(z) {}
            float length() const { return x*x + y*y + z*z; }
            Vector3 operator+(const Vector3& other) const {
                return Vector3(x+other.x, y+other.y, z+other.z);
            }
        };
    "#;
    let cpg = cpp(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let class = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "Vector3");
    assert!(class.is_some(), "expected ClassDef for 'Vector3'");

    let fields: Vec<_> =
        cpg.ast.values().filter(|n| n.kind == IrNodeKind::FieldDef).collect();
    assert!(!fields.is_empty(), "Vector3 should have field definitions");
}

#[test]
fn cpp_typedef_and_using_alias() {
    let src = r#"
        typedef unsigned long long uint64;
        using Byte = unsigned char;
        using IntPtr = int*;
        uint64 count = 0;
        Byte flags = 0;
    "#;
    let cpg = cpp(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let aliases: Vec<_> =
        cpg.ast.values().filter(|n| n.kind == IrNodeKind::TypeAlias).collect();
    assert!(!aliases.is_empty(), "typedef/using declarations should produce TypeAlias nodes");
}

#[test]
fn cpp_template_struct() {
    let src = r#"
        template<typename T>
        struct Pair {
            T first;
            T second;
            Pair(T a, T b) : first(a), second(b) {}
            T max() const { return first > second ? first : second; }
        };
        int use_pair() {
            Pair<int> p(3, 7);
            return p.max();
        }
    "#;
    let cpg = cpp(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let pair_class = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "Pair");
    assert!(pair_class.is_some(), "expected ClassDef for template 'Pair'");
    let (pair_id, _) = pair_class.unwrap();
    let meta = cpg.cpp_meta(pair_id);
    assert!(meta.is_some(), "Pair should have CppNodeMetadata");
    let params = meta.unwrap().template_params.as_deref().unwrap_or(&[]);
    assert!(
        params.contains(&"T".to_string()),
        "template_params should include 'T', got {:?}",
        params
    );
}

// ── C++: Inheritance and virtual dispatch ──────────────────────────────────────

#[test]
fn cpp_single_inheritance_base_classes() {
    let src = r#"
        class Animal {
        public:
            virtual void speak() = 0;
            virtual ~Animal() {}
            int age;
        };
        class Dog : public Animal {
        public:
            void speak() override { int x = 1; }
            std::string name;
        };
        class Cat : public Animal {
        public:
            void speak() override { int x = 2; }
        };
    "#;
    let cpg = cpp(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    // C++ stores base_classes on the IrNode directly, not in CppNodeMetadata
    let dog = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "Dog");
    assert!(dog.is_some(), "expected ClassDef for 'Dog'");
    let (_, dog_node) = dog.unwrap();
    let dog_bases = dog_node.base_classes.as_deref().unwrap_or(&[]);
    assert!(
        dog_bases.iter().any(|b| b.contains("Animal")),
        "Dog.base_classes should include Animal, got {:?}",
        dog_bases
    );

    let cat = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "Cat");
    assert!(cat.is_some(), "expected ClassDef for 'Cat'");
    let (_, cat_node) = cat.unwrap();
    let cat_bases = cat_node.base_classes.as_deref().unwrap_or(&[]);
    assert!(
        cat_bases.iter().any(|b| b.contains("Animal")),
        "Cat.base_classes should include Animal, got {:?}",
        cat_bases
    );
}

#[test]
fn cpp_virtual_methods_flagged() {
    let src = r#"
        class Shape {
        public:
            virtual double area() const { return 0.0; }
            virtual double perimeter() const { return 0.0; }
            virtual ~Shape() {}
        };
        class Circle : public Shape {
            double r;
        public:
            Circle(double r) : r(r) {}
            double area() const override { return 3.14159 * r * r; }
            double perimeter() const override { return 2.0 * 3.14159 * r; }
        };
    "#;
    let cpg = cpp(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let virtual_fns: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::MethodDef && n.is_virtual == Some(true))
        .collect();
    assert!(
        !virtual_fns.is_empty(),
        "Shape virtual methods should be flagged with is_virtual=true"
    );
}

#[test]
fn cpp_multiple_inheritance() {
    let src = r#"
        struct Flyable {
            virtual void fly() = 0;
        };
        struct Swimmable {
            virtual void swim() = 0;
        };
        class Duck : public Flyable, public Swimmable {
        public:
            void fly() override { int x = 1; }
            void swim() override { int x = 2; }
        };
    "#;
    let cpg = cpp(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    // C++ stores base_classes on the IrNode directly
    let duck = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "Duck");
    assert!(duck.is_some(), "expected ClassDef for 'Duck'");
    let (_, duck_node) = duck.unwrap();
    let bases = duck_node.base_classes.as_deref().unwrap_or(&[]);
    assert!(
        bases.len() >= 2,
        "Duck should have at least 2 base classes, got {:?}",
        bases
    );
}

#[test]
fn cpp_constructor_destructor_in_hierarchy() {
    let src = r#"
        class Base {
        public:
            Base() { int init = 1; }
            virtual ~Base() { int cleanup = 0; }
        };
        class Derived : public Base {
        public:
            Derived() : Base() { int extra = 2; }
            ~Derived() override { int extra_cleanup = 0; }
        };
    "#;
    let cpg = cpp(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let constructors: Vec<_> = cpg
        .ast
        .iter()
        .filter_map(|(&id, n)| {
            if n.kind == IrNodeKind::MethodDef && n.is_constructor == Some(true) {
                cpg.cpp_meta(id)
            } else {
                None
            }
        })
        .collect();
    assert!(!constructors.is_empty(), "constructors should be flagged with is_constructor=true");

    let destructors: Vec<_> = cpg
        .ast
        .iter()
        .filter_map(|(&id, n)| {
            if n.kind == IrNodeKind::MethodDef && n.is_destructor == Some(true) {
                cpg.cpp_meta(id)
            } else {
                None
            }
        })
        .collect();
    assert!(!destructors.is_empty(), "destructors should be flagged with is_destructor=true");
}

// ── C++: Operator overloading ─────────────────────────────────────────────────

#[test]
fn cpp_comparison_operator_overloads() {
    let src = r#"
        struct Point {
            int x, y;
            bool operator==(const Point& o) const { return x==o.x && y==o.y; }
            bool operator<(const Point& o) const { return x<o.x || (x==o.x && y<o.y); }
            bool operator!=(const Point& o) const { return !(*this == o); }
        };
    "#;
    let cpg = cpp(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let methods: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::MethodDef)
        .collect();
    assert!(methods.len() >= 3, "expected 3 operator overloads as MethodDef nodes");
}

#[test]
fn cpp_arithmetic_operator_overloads() {
    let src = r#"
        struct Complex {
            double re, im;
            Complex operator+(const Complex& o) const { return {re+o.re, im+o.im}; }
            Complex operator*(const Complex& o) const {
                return {re*o.re - im*o.im, re*o.im + im*o.re};
            }
            Complex& operator+=(const Complex& o) { re+=o.re; im+=o.im; return *this; }
        };
    "#;
    let cpg = cpp(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    assert!(!cpg.ast.is_empty());
}

// ── C++: Lambda functions ─────────────────────────────────────────────────────

#[test]
fn cpp_lambda_no_capture() {
    let src = r#"
        int apply(int x, int(*fn)(int)) { return fn(x); }
        int main() {
            auto sq = [](int x) { return x * x; };
            return apply(5, sq);
        }
    "#;
    let cpg = cpp(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let lambdas: Vec<_> =
        cpg.ast.values().filter(|n| n.kind == IrNodeKind::LambdaDef).collect();
    assert!(!lambdas.is_empty(), "lambda expression should produce LambdaDef node");
}

#[test]
fn cpp_lambda_capture_by_value_and_ref() {
    let src = r#"
        int main() {
            int base = 10;
            int factor = 3;
            auto by_val = [base, factor](int x) { return base + factor * x; };
            auto by_ref = [&base](int x) { return base += x; };
            auto all_val = [=](int x) { return base * x + factor; };
            auto all_ref = [&](int x) { base = x; factor = x; return x; };
            return by_val(5) + by_ref(2) + all_val(1) + all_ref(0);
        }
    "#;
    let cpg = cpp(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let lambdas = nodes_of_kind(&cpg, IrNodeKind::LambdaDef);
    assert!(lambdas.len() >= 4, "expected at least 4 lambda expressions, got {}", lambdas.len());
}

#[test]
fn cpp_lambda_as_parameter_generic() {
    let src = r#"
        #include <vector>
        template<typename F>
        void for_each_pair(int a, int b, F fn) {
            fn(a, b);
        }
        int main() {
            int result = 0;
            for_each_pair(3, 4, [&result](int a, int b) { result = a + b; });
            return result;
        }
    "#;
    let cpg = cpp(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let lambdas = nodes_of_kind(&cpg, IrNodeKind::LambdaDef);
    assert!(!lambdas.is_empty(), "lambda passed as template arg should produce LambdaDef");
}

// ── C++: Deep interprocedural chains ──────────────────────────────────────────

#[test]
fn cpp_deep_call_chain_five_levels() {
    let src = r#"
        int level5(int x) { return x + 1; }
        int level4(int x) { return level5(x * 2); }
        int level3(int x) { return level4(x + 3); }
        int level2(int x) { return level3(x - 1); }
        int level1(int x) { return level2(x * x); }
        int entry(int x) { return level1(x); }
    "#;
    let cpg = cpp(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let fns: Vec<_> = (1..=5)
        .map(|i| format!("level{}", i))
        .chain(std::iter::once("entry".to_string()))
        .filter(|name| {
            cpg.ast.values().any(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some(name))
        })
        .collect();
    assert_eq!(fns.len(), 6, "all 6 functions in call chain should be in AST, got {:?}", fns);

    let all_callees: Vec<String> = cpg
        .call_graph
        .values()
        .flat_map(|e| e.calls.iter().map(|c| c.callee.clone()))
        .collect();
    for name in &["level2", "level3", "level4", "level5"] {
        assert!(
            all_callees.contains(&name.to_string()),
            "call chain: '{name}' should appear as a callee in the call graph"
        );
    }
}

#[test]
fn cpp_mutual_recursion_detected() {
    let src = r#"
        bool is_even(int n);
        bool is_odd(int n) { return n == 0 ? false : is_even(n - 1); }
        bool is_even(int n) { return n == 0 ? true : is_odd(n - 1); }
    "#;
    let cpg = cpp(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    assert!(cpg.ast.values().any(|n| n.name.as_deref() == Some("is_even")));
    assert!(cpg.ast.values().any(|n| n.name.as_deref() == Some("is_odd")));
}

// ── C++: Visibility and access specifiers ─────────────────────────────────────

#[test]
fn cpp_class_visibility_specifiers() {
    let src = r#"
        class Account {
        public:
            Account(double balance) : balance_(balance) {}
            double get_balance() const { return balance_; }
            void deposit(double amount) { balance_ += amount; }
        protected:
            virtual void audit(double amount) { int x = 0; }
        private:
            double balance_;
            void internal_check() { int x = 0; }
        };
    "#;
    let cpg = cpp(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    // C++ visibility is stored on the IrNode directly
    let pub_methods: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::MethodDef && n.visibility.as_deref() == Some("public"))
        .collect();
    assert!(!pub_methods.is_empty(), "public methods should have visibility='public' on IrNode");

    let internal_check = cpg
        .ast
        .values()
        .find(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("internal_check"));
    assert!(internal_check.is_some(), "internal_check should appear in AST");
    assert_eq!(
        internal_check.unwrap().visibility.as_deref(),
        Some("private"),
        "internal_check should have visibility='private'"
    );
}

// ── C++: Class hierarchy in workspace index ───────────────────────────────────

#[test]
fn cpp_class_hierarchy_populated_in_workspace() {
    let src = r#"
        class Vehicle { public: virtual void move() {} };
        class Car : public Vehicle { public: void move() override {} };
        class ElectricCar : public Car { public: void move() override {} };
    "#;
    let cpg = cpp(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let hierarchy = &cpg.workspace.class_hierarchy;
    assert!(
        !hierarchy.is_empty(),
        "class hierarchy should be populated for inherited classes"
    );
    let car_supers = hierarchy.get("Car").cloned().unwrap_or_default();
    assert!(
        car_supers.iter().any(|s| s.contains("Vehicle")),
        "Car should list Vehicle as supertype, got {:?}",
        car_supers
    );
    let ecar_supers = hierarchy.get("ElectricCar").cloned().unwrap_or_default();
    assert!(
        ecar_supers.iter().any(|s| s.contains("Car")),
        "ElectricCar should list Car as supertype, got {:?}",
        ecar_supers
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// JAVA TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// ── Java: Packages and classes ────────────────────────────────────────────────

#[test]
fn java_class_in_package() {
    let src = r#"
        package com.example.shapes;
        public class Circle {
            private double radius;
            public Circle(double radius) { this.radius = radius; }
            public double area() { return Math.PI * radius * radius; }
        }
    "#;
    let cpg = java(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let class = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "Circle");
    assert!(class.is_some(), "expected ClassDef for 'Circle'");
    let (class_id, _) = class.unwrap();
    let meta = cpg.java_meta(class_id).expect("Circle should have JavaNodeMetadata");
    assert_eq!(meta.package_name.as_deref(), Some("com.example.shapes"));
}

#[test]
fn java_single_inheritance_extends() {
    let src = r#"
        public class Animal {
            public String name;
            public Animal(String name) { this.name = name; }
            public String sound() { return "..."; }
        }
        public class Dog extends Animal {
            public Dog(String name) { super(name); }
            @Override
            public String sound() { return "Woof"; }
            public void fetch() { int x = 1; }
        }
        public class Cat extends Animal {
            public Cat(String name) { super(name); }
            @Override
            public String sound() { return "Meow"; }
        }
    "#;
    let cpg = java(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let dog = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "Dog");
    assert!(dog.is_some(), "expected ClassDef for 'Dog'");
    let (dog_id, _) = dog.unwrap();
    let meta = cpg.java_meta(dog_id).expect("Dog should have JavaNodeMetadata");
    assert!(
        meta.extends_type.as_deref().map(|s| s.contains("Animal")).unwrap_or(false),
        "Dog should extend Animal, got {:?}",
        meta.extends_type
    );

    let sound_overrides: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("sound"))
        .collect();
    assert!(
        sound_overrides.len() >= 2,
        "both Dog and Cat should override sound(), found {} definitions",
        sound_overrides.len()
    );
}

#[test]
fn java_interface_implementation() {
    let src = r#"
        public interface Drawable {
            void draw();
            default String getDescription() { return "drawable"; }
        }
        public interface Resizable {
            void resize(double factor);
        }
        public class Rectangle implements Drawable, Resizable {
            private double width, height;
            public Rectangle(double w, double h) { this.width = w; this.height = h; }
            @Override
            public void draw() { int x = 0; }
            @Override
            public void resize(double factor) { width *= factor; height *= factor; }
        }
    "#;
    let cpg = java(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let rect = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "Rectangle");
    assert!(rect.is_some(), "expected ClassDef for 'Rectangle'");
    let (rect_id, _) = rect.unwrap();
    let meta = cpg.java_meta(rect_id).expect("Rectangle should have JavaNodeMetadata");
    assert!(
        meta.implements_types.len() >= 2,
        "Rectangle should implement at least 2 interfaces, got {:?}",
        meta.implements_types
    );
}

#[test]
fn java_abstract_class() {
    let src = r#"
        public abstract class Template {
            public final void execute() {
                step1();
                step2();
                step3();
            }
            protected abstract void step1();
            protected abstract void step2();
            protected void step3() { int x = 0; }
        }
        public class ConcreteTemplate extends Template {
            @Override
            protected void step1() { int a = 1; }
            @Override
            protected void step2() { int b = 2; }
        }
    "#;
    let cpg = java(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let tmpl = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "Template");
    assert!(tmpl.is_some(), "expected ClassDef for abstract 'Template'");
    let (tmpl_id, _) = tmpl.unwrap();
    let meta = cpg.java_meta(tmpl_id).expect("Template should have JavaNodeMetadata");
    assert!(meta.is_abstract, "Template should be flagged as abstract");
}

#[test]
fn java_method_overloading() {
    let src = r#"
        public class Calculator {
            public int add(int a, int b) { return a + b; }
            public double add(double a, double b) { return a + b; }
            public int add(int a, int b, int c) { return a + b + c; }
            public String add(String a, String b) { return a + b; }
        }
    "#;
    let cpg = java(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let add_methods: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("add"))
        .collect();
    assert_eq!(add_methods.len(), 4, "expected 4 overloads of 'add', got {}", add_methods.len());
}

#[test]
fn java_lambda_functional_interface() {
    let src = r#"
        import java.util.function.Function;
        import java.util.function.Predicate;
        public class LambdaDemo {
            public static void demo() {
                Function<Integer, Integer> square = x -> x * x;
                Function<Integer, Integer> doubler = (x) -> x * 2;
                Predicate<Integer> isPositive = x -> x > 0;
                Function<Integer, String> toString = x -> "value: " + x;
                int result = square.apply(5);
                boolean check = isPositive.test(-1);
            }
        }
    "#;
    let cpg = java(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let lambdas = nodes_of_kind(&cpg, IrNodeKind::LambdaDef);
    assert!(lambdas.len() >= 4, "expected at least 4 lambda expressions, got {}", lambdas.len());
}

#[test]
fn java_enum_with_methods() {
    let src = r#"
        public enum Planet {
            MERCURY(3.303e+23, 2.4397e6),
            VENUS(4.869e+24, 6.0518e6),
            EARTH(5.976e+24, 6.37814e6);

            private final double mass;
            private final double radius;

            Planet(double mass, double radius) {
                this.mass = mass;
                this.radius = radius;
            }

            double surfaceGravity() {
                final double G = 6.67300E-11;
                return G * mass / (radius * radius);
            }
        }
    "#;
    let cpg = java(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let enum_nodes = nodes_of_kind(&cpg, IrNodeKind::EnumDef);
    assert!(!enum_nodes.is_empty(), "enum Planet should produce an EnumDef node");
    let planet_enum = find_node_by_kind_and_name(&cpg, IrNodeKind::EnumDef, "Planet");
    assert!(planet_enum.is_some(), "expected EnumDef named 'Planet'");

    let enum_consts = nodes_of_kind(&cpg, IrNodeKind::EnumConstant);
    assert!(
        enum_consts.len() >= 3,
        "Planet enum should have at least 3 constants, got {}",
        enum_consts.len()
    );
}

#[test]
fn java_generic_class() {
    let src = r#"
        public class Stack<T> {
            private Object[] elements;
            private int size = 0;
            @SuppressWarnings("unchecked")
            public T pop() { return (T) elements[--size]; }
            public void push(T item) { elements[size++] = item; }
            public boolean isEmpty() { return size == 0; }
        }
    "#;
    let cpg = java(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let stack = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "Stack");
    assert!(stack.is_some(), "expected ClassDef for generic 'Stack'");
    let (stack_id, _) = stack.unwrap();
    let meta = cpg.java_meta(stack_id).expect("Stack should have JavaNodeMetadata");
    assert!(
        !meta.generic_type_params.is_empty(),
        "Stack should have generic type params, got {:?}",
        meta.generic_type_params
    );
}

#[test]
fn java_deep_interprocedural_chain() {
    let src = r#"
        public class Pipeline {
            public static int start(int x) { return normalize(x); }
            private static int normalize(int x) { return validate(Math.abs(x)); }
            private static int validate(int x) { return transform(x > 0 ? x : 1); }
            private static int transform(int x) { return aggregate(x * 2); }
            private static int aggregate(int x) { return finalize(x + 100); }
            private static int finalize(int x) { return x % 1000; }
        }
    "#;
    let cpg = java(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let fn_names = ["start", "normalize", "validate", "transform", "aggregate", "finalize"];
    for name in &fn_names {
        assert!(
            cpg.ast.values().any(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some(name)),
            "method '{}' should be in AST",
            name
        );
    }

    let callees: Vec<_> = cpg
        .call_graph
        .values()
        .flat_map(|e| e.calls.iter().map(|c| c.callee.clone()))
        .collect();
    for name in &["normalize", "validate", "transform", "aggregate", "finalize"] {
        assert!(
            callees.contains(&name.to_string()),
            "'{name}' should appear as a callee in the call graph"
        );
    }
}

#[test]
fn java_inner_class_and_anonymous_class() {
    let src = r#"
        public class Outer {
            private int x = 10;

            public class Inner {
                public int getX() { return x; }
            }

            static class StaticNested {
                public int compute(int n) { return n * n; }
            }

            interface Callback {
                void invoke();
            }

            public Callback makeCallback() {
                return new Callback() {
                    @Override
                    public void invoke() { int done = 1; }
                };
            }
        }
    "#;
    let cpg = java(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let classes: Vec<_> = cpg.ast.values().filter(|n| n.kind == IrNodeKind::ClassDef).collect();
    assert!(classes.len() >= 2, "expected at least Outer + Inner + StaticNested classes");
}

// ═══════════════════════════════════════════════════════════════════════════════
// PYTHON TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// ── Python: Classes and inheritance ───────────────────────────────────────────

#[test]
fn python_class_with_dunder_methods() {
    let src = r#"
class Vector:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __add__(self, other):
        return Vector(self.x + other.x, self.y + other.y)

    def __repr__(self):
        return f"Vector({self.x}, {self.y})"

    def __len__(self):
        return 2

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y
"#;
    let cpg = py(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let vector = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "Vector");
    assert!(vector.is_some(), "expected ClassDef for 'Vector'");

    for dunder in &["__init__", "__add__", "__repr__", "__len__", "__eq__"] {
        assert!(
            cpg.ast.values().any(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some(dunder)),
            "expected MethodDef for '{dunder}'"
        );
    }
}

#[test]
fn python_single_inheritance_method_override() {
    let src = r#"
class Animal:
    def __init__(self, name):
        self.name = name

    def speak(self):
        return "..."

    def describe(self):
        return f"{self.name} says {self.speak()}"

class Dog(Animal):
    def speak(self):
        return "Woof"

class Cat(Animal):
    def speak(self):
        return "Meow"

class Duck(Animal):
    def speak(self):
        return "Quack"
"#;
    let cpg = py(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    for cls in &["Animal", "Dog", "Cat", "Duck"] {
        assert!(
            cpg.ast.values().any(|n| n.kind == IrNodeKind::ClassDef && n.name.as_deref() == Some(cls)),
            "expected ClassDef for '{cls}'"
        );
    }

    let speak_defs: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("speak"))
        .collect();
    assert!(
        speak_defs.len() >= 4,
        "expected 4 speak() definitions (base + 3 overrides), got {}",
        speak_defs.len()
    );

    let dog = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "Dog");
    assert!(dog.is_some());
    let dog_node = dog.unwrap().1;
    assert!(
        dog_node.base_classes.as_ref().map(|b| b.iter().any(|s| s.contains("Animal"))).unwrap_or(false),
        "Dog.base_classes should include Animal, got {:?}",
        dog_node.base_classes
    );
}

#[test]
fn python_multiple_inheritance_mixin() {
    let src = r#"
class Loggable:
    def log(self, msg):
        print(f"LOG: {msg}")

class Serializable:
    def serialize(self):
        return str(self.__dict__)

class Config(Loggable, Serializable):
    def __init__(self, name, value):
        self.name = name
        self.value = value

    def apply(self):
        self.log(f"applying {self.name}={self.value}")
        return self.serialize()
"#;
    let cpg = py(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let config = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "Config");
    assert!(config.is_some(), "expected ClassDef for 'Config'");
    let config_node = config.unwrap().1;
    let bases = config_node.base_classes.as_deref().unwrap_or(&[]);
    assert!(
        bases.len() >= 2,
        "Config should inherit from at least 2 classes, got {:?}",
        bases
    );
}

#[test]
fn python_property_decorator() {
    let src = r#"
class Temperature:
    def __init__(self, celsius):
        self._celsius = celsius

    @property
    def celsius(self):
        return self._celsius

    @celsius.setter
    def celsius(self, value):
        if value < -273.15:
            raise ValueError("Below absolute zero")
        self._celsius = value

    @property
    def fahrenheit(self):
        return self._celsius * 9/5 + 32
"#;
    let cpg = py(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let decorators_seen: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::Decorator)
        .collect();
    assert!(!decorators_seen.is_empty(), "expected Decorator nodes for @property");
}

#[test]
fn python_classmethod_and_staticmethod() {
    let src = r#"
class Counter:
    _count = 0

    def __init__(self):
        Counter._count += 1

    @classmethod
    def get_count(cls):
        return cls._count

    @staticmethod
    def reset():
        Counter._count = 0

    @classmethod
    def create_multiple(cls, n):
        return [cls() for _ in range(n)]
"#;
    let cpg = py(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let get_count_id = cpg
        .ast
        .iter()
        .find_map(|(&id, n)| {
            if n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("get_count") {
                Some(id)
            } else {
                None
            }
        });
    assert!(get_count_id.is_some(), "expected MethodDef for 'get_count'");
    let meta = cpg.python_meta(get_count_id.unwrap());
    assert!(meta.is_some(), "get_count should have PythonNodeMetadata");
    assert!(meta.unwrap().is_classmethod, "get_count should be flagged as classmethod");

    let reset_id = cpg
        .ast
        .iter()
        .find_map(|(&id, n)| {
            if n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("reset") {
                Some(id)
            } else {
                None
            }
        });
    assert!(reset_id.is_some(), "expected MethodDef for 'reset'");
    let reset_meta = cpg.python_meta(reset_id.unwrap());
    assert!(reset_meta.is_some(), "reset should have PythonNodeMetadata");
    assert!(reset_meta.unwrap().is_staticmethod, "reset should be flagged as staticmethod");
}

// ── Python: Lambda and closures ───────────────────────────────────────────────

#[test]
fn python_lambda_expressions() {
    let src = r#"
square = lambda x: x * x
add = lambda x, y: x + y
clamp = lambda val, lo, hi: max(lo, min(hi, val))
identity = lambda x: x
nums = [1, 2, 3, 4, 5]
evens = list(filter(lambda x: x % 2 == 0, nums))
doubled = list(map(lambda x: x * 2, nums))
"#;
    let cpg = py(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let lambdas = nodes_of_kind(&cpg, IrNodeKind::LambdaDef);
    assert!(lambdas.len() >= 6, "expected at least 6 lambda expressions, got {}", lambdas.len());
}

#[test]
fn python_closure_captures_enclosing_variable() {
    let src = r#"
def make_adder(n):
    def adder(x):
        return x + n
    return adder

def make_multiplier(factor):
    def multiply(x):
        return x * factor
    return multiply

def make_counter(start=0):
    count = [start]
    def increment():
        count[0] += 1
        return count[0]
    return increment
"#;
    let cpg = py(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    for name in &["make_adder", "make_multiplier", "make_counter", "adder", "multiply", "increment"] {
        assert!(
            cpg.ast.values().any(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some(name)),
            "expected MethodDef for '{name}'"
        );
    }
}

#[test]
fn python_generator_function() {
    let src = r#"
def fibonacci():
    a, b = 0, 1
    while True:
        yield a
        a, b = b, a + b

def take(n, gen):
    result = []
    for i, v in enumerate(gen):
        if i >= n:
            break
        result.append(v)
    return result

def range_gen(start, stop, step=1):
    current = start
    while current < stop:
        yield current
        current += step
"#;
    let cpg = py(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let yields = nodes_of_kind(&cpg, IrNodeKind::Yield);
    assert!(!yields.is_empty(), "yield expressions should produce Yield nodes");

    let fib_id = cpg
        .ast
        .iter()
        .find_map(|(&id, n)| {
            if n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("fibonacci") {
                Some(id)
            } else {
                None
            }
        });
    assert!(fib_id.is_some(), "expected MethodDef for 'fibonacci'");
    let meta = cpg.python_meta(fib_id.unwrap());
    assert!(meta.is_some(), "fibonacci should have PythonNodeMetadata");
    assert!(meta.unwrap().is_generator, "fibonacci should be flagged as is_generator");
}

#[test]
fn python_async_function_and_await() {
    let src = r#"
import asyncio

async def fetch_data(url):
    await asyncio.sleep(1)
    return url

async def process(urls):
    results = []
    for url in urls:
        data = await fetch_data(url)
        results.append(data)
    return results

async def main():
    urls = ["http://a.com", "http://b.com"]
    return await process(urls)
"#;
    let cpg = py(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let awaits = nodes_of_kind(&cpg, IrNodeKind::Await);
    assert!(!awaits.is_empty(), "await expressions should produce Await nodes");

    let fetch_id = cpg
        .ast
        .iter()
        .find_map(|(&id, n)| {
            if n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("fetch_data") {
                Some(id)
            } else {
                None
            }
        });
    assert!(fetch_id.is_some());
    let meta = cpg.python_meta(fetch_id.unwrap());
    assert!(meta.is_some(), "fetch_data should have PythonNodeMetadata");
    assert!(meta.unwrap().is_async, "fetch_data should be flagged as async");
}

#[test]
fn python_decorator_factory() {
    let src = r#"
def retry(times=3):
    def decorator(fn):
        def wrapper(*args, **kwargs):
            for attempt in range(times):
                try:
                    return fn(*args, **kwargs)
                except Exception as e:
                    if attempt == times - 1:
                        raise
            return None
        return wrapper
    return decorator

@retry(times=5)
def unstable_operation():
    import random
    if random.random() < 0.5:
        raise ValueError("failed")
    return "ok"
"#;
    let cpg = py(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let decorator_nodes = nodes_of_kind(&cpg, IrNodeKind::Decorator);
    assert!(!decorator_nodes.is_empty(), "decorator application should produce Decorator nodes");
}

#[test]
fn python_walrus_operator() {
    let src = r#"
data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
if n := len(data):
    print(f"List has {n} items")

while chunk := data[:3]:
    data = data[3:]
    process = chunk

results = [y for x in range(20) if (y := x ** 2) > 10]
"#;
    let cpg = py(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let walrus = nodes_of_kind(&cpg, IrNodeKind::NamedExpr);
    assert!(!walrus.is_empty(), "walrus operator should produce NamedExpr nodes");
}

#[test]
fn python_deep_call_chain() {
    let src = r#"
def sanitize(raw):
    return raw.strip()

def parse(text):
    return sanitize(text).split(',')

def validate(items):
    return [x for x in parse(items) if x]

def enrich(items):
    return {i: v for i, v in enumerate(validate(items))}

def store(data):
    result = enrich(data)
    return len(result)

def process_input(raw_input):
    return store(raw_input)
"#;
    let cpg = py(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    for name in &["sanitize", "parse", "validate", "enrich", "store", "process_input"] {
        assert!(
            cpg.ast.values().any(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some(name)),
            "function '{name}' should be in AST"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// RUST TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// ── Rust: Structs and impl blocks ─────────────────────────────────────────────

#[test]
fn rust_struct_with_impl_block() {
    let src = r#"
struct Rectangle {
    width: f64,
    height: f64,
}

impl Rectangle {
    fn new(width: f64, height: f64) -> Self {
        Rectangle { width, height }
    }

    fn area(&self) -> f64 {
        self.width * self.height
    }

    fn perimeter(&self) -> f64 {
        2.0 * (self.width + self.height)
    }

    fn is_square(&self) -> bool {
        (self.width - self.height).abs() < f64::EPSILON
    }
}
"#;
    let cpg = rs(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let rect = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "Rectangle");
    assert!(rect.is_some(), "expected ClassDef for 'Rectangle' struct");

    let impl_blocks = nodes_of_kind(&cpg, IrNodeKind::ImplBlock);
    assert!(!impl_blocks.is_empty(), "expected ImplBlock for Rectangle");

    for method in &["new", "area", "perimeter", "is_square"] {
        assert!(
            cpg.ast.values().any(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some(method)),
            "method '{method}' should be in AST"
        );
    }
}

#[test]
fn rust_trait_definition_and_impl() {
    let src = r#"
trait Animal {
    fn name(&self) -> &str;
    fn sound(&self) -> &str;
    fn describe(&self) -> String {
        format!("{} says {}", self.name(), self.sound())
    }
}

struct Dog {
    name: String,
}

struct Cat {
    name: String,
}

impl Animal for Dog {
    fn name(&self) -> &str { &self.name }
    fn sound(&self) -> &str { "Woof" }
}

impl Animal for Cat {
    fn name(&self) -> &str { &self.name }
    fn sound(&self) -> &str { "Meow" }
}
"#;
    let cpg = rs(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let trait_nodes = nodes_of_kind(&cpg, IrNodeKind::TraitDef);
    assert!(!trait_nodes.is_empty(), "expected TraitDef for 'Animal'");

    let impl_blocks = nodes_of_kind(&cpg, IrNodeKind::ImplBlock);
    assert!(
        impl_blocks.len() >= 2,
        "expected at least 2 ImplBlocks (Dog + Cat), got {}",
        impl_blocks.len()
    );

    let sound_methods: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("sound"))
        .collect();
    assert!(sound_methods.len() >= 2, "expected at least 2 sound() impls");
}

#[test]
fn rust_trait_objects_dyn_dispatch() {
    let src = r#"
trait Drawable {
    fn draw(&self);
    fn bounding_box(&self) -> (f64, f64, f64, f64);
}

struct Circle { x: f64, y: f64, r: f64 }
struct Rect { x: f64, y: f64, w: f64, h: f64 }

impl Drawable for Circle {
    fn draw(&self) { let _ = self.r; }
    fn bounding_box(&self) -> (f64, f64, f64, f64) {
        (self.x - self.r, self.y - self.r, self.x + self.r, self.y + self.r)
    }
}

impl Drawable for Rect {
    fn draw(&self) { let _ = self.w; }
    fn bounding_box(&self) -> (f64, f64, f64, f64) {
        (self.x, self.y, self.x + self.w, self.y + self.h)
    }
}

fn render_all(shapes: &[Box<dyn Drawable>]) {
    for shape in shapes {
        shape.draw();
        let _ = shape.bounding_box();
    }
}
"#;
    let cpg = rs(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let trait_def = find_node_by_kind_and_name(&cpg, IrNodeKind::TraitDef, "Drawable");
    assert!(trait_def.is_some(), "expected TraitDef for 'Drawable'");
}

#[test]
fn rust_generic_struct_and_function() {
    let src = r#"
struct Stack<T> {
    items: Vec<T>,
}

impl<T> Stack<T> {
    fn new() -> Self {
        Stack { items: Vec::new() }
    }

    fn push(&mut self, item: T) {
        self.items.push(item);
    }

    fn pop(&mut self) -> Option<T> {
        self.items.pop()
    }

    fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

fn largest<T: PartialOrd>(list: &[T]) -> &T {
    let mut largest = &list[0];
    for item in list {
        if item > largest { largest = item; }
    }
    largest
}
"#;
    let cpg = rs(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let stack = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "Stack");
    assert!(stack.is_some(), "expected ClassDef for generic 'Stack'");

    let largest_fn = find_node_by_kind_and_name(&cpg, IrNodeKind::MethodDef, "largest");
    assert!(largest_fn.is_some(), "expected MethodDef for generic 'largest'");
    let (largest_id, _) = largest_fn.unwrap();
    let meta = cpg.rust_meta(largest_id);
    assert!(meta.is_some(), "largest should have RustNodeMetadata");
    let rust_meta = meta.unwrap();
    assert!(
        !rust_meta.generic_params.is_empty() || !rust_meta.trait_bounds.is_empty(),
        "largest should have generic params or trait bounds"
    );
}

#[test]
fn rust_closures_capturing_environment() {
    let src = r#"
fn make_adder(n: i32) -> impl Fn(i32) -> i32 {
    move |x| x + n
}

fn apply_twice<F: Fn(i32) -> i32>(f: F, x: i32) -> i32 {
    f(f(x))
}

fn compose<F, G>(f: F, g: G) -> impl Fn(i32) -> i32
where
    F: Fn(i32) -> i32,
    G: Fn(i32) -> i32,
{
    move |x| f(g(x))
}

fn main() {
    let add5 = make_adder(5);
    let result = apply_twice(|x| x * 2, 3);
    let double_then_add5 = compose(make_adder(5), |x| x * 2);
    let _ = add5(10) + result + double_then_add5(3);
}
"#;
    let cpg = rs(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    // Rust lifter maps closure_expression → LambdaDef (not ClosureExpr)
    let closures = nodes_of_kind(&cpg, IrNodeKind::LambdaDef);
    assert!(closures.len() >= 3, "expected at least 3 closure expressions, got {}", closures.len());
}

#[test]
fn rust_match_expression_with_guards() {
    let src = r#"
#[derive(Debug)]
enum Shape {
    Circle(f64),
    Rectangle(f64, f64),
    Triangle(f64, f64, f64),
}

fn area(shape: &Shape) -> f64 {
    match shape {
        Shape::Circle(r) => std::f64::consts::PI * r * r,
        Shape::Rectangle(w, h) => w * h,
        Shape::Triangle(a, b, c) => {
            let s = (a + b + c) / 2.0;
            (s * (s - a) * (s - b) * (s - c)).sqrt()
        }
    }
}

fn classify(n: i32) -> &'static str {
    match n {
        i32::MIN..=-1 => "negative",
        0 => "zero",
        1..=9 => "small",
        10..=99 => "medium",
        _ if n % 2 == 0 => "large even",
        _ => "large odd",
    }
}
"#;
    let cpg = rs(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let match_nodes = nodes_of_kind(&cpg, IrNodeKind::MatchExpr);
    assert!(match_nodes.len() >= 2, "expected at least 2 match expressions, got {}", match_nodes.len());

    let arms = nodes_of_kind(&cpg, IrNodeKind::MatchArm);
    assert!(arms.len() >= 6, "expected at least 6 match arms total, got {}", arms.len());
}

#[test]
fn rust_module_hierarchy() {
    let src = r#"
mod utils {
    pub fn helper(x: i32) -> i32 { x + 1 }

    pub mod math {
        pub fn square(x: f64) -> f64 { x * x }
        pub fn cube(x: f64) -> f64 { x * x * x }
    }

    mod private_impl {
        pub(super) fn internal(x: i32) -> i32 { x * 2 }
    }
}

use utils::math::square;

fn main() {
    let a = utils::helper(5);
    let b = square(3.0);
    let c = utils::math::cube(2.0);
    let _ = (a, b, c);
}
"#;
    let cpg = rs(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let modules = nodes_of_kind(&cpg, IrNodeKind::ModDef);
    assert!(modules.len() >= 2, "expected at least 2 module definitions, got {}", modules.len());

    let use_decls = nodes_of_kind(&cpg, IrNodeKind::UseDecl);
    assert!(!use_decls.is_empty(), "expected UseDecl node for 'use utils::math::square'");
}

#[test]
fn rust_unsafe_block_and_raw_pointer() {
    let src = r#"
unsafe fn dangerous(ptr: *const i32) -> i32 {
    *ptr
}

fn safe_wrapper(val: &i32) -> i32 {
    unsafe { dangerous(val as *const i32) }
}

fn raw_pointer_demo() {
    let x = 42i32;
    let ptr = &x as *const i32;
    let result = unsafe {
        *ptr
    };
    let _ = result;
}
"#;
    let cpg = rs(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let unsafe_blocks = nodes_of_kind(&cpg, IrNodeKind::UnsafeBlock);
    assert!(!unsafe_blocks.is_empty(), "expected UnsafeBlock nodes");

    let dangerous = find_node_by_kind_and_name(&cpg, IrNodeKind::MethodDef, "dangerous");
    assert!(dangerous.is_some(), "expected MethodDef for 'dangerous'");
    let (did, _) = dangerous.unwrap();
    let meta = cpg.rust_meta(did);
    assert!(meta.is_some(), "dangerous should have RustNodeMetadata");
    assert!(meta.unwrap().is_unsafe, "dangerous should be flagged as is_unsafe");
}

#[test]
fn rust_deep_call_chain_across_impls() {
    let src = r#"
trait Stage {
    fn process(&self, input: i32) -> i32;
}

struct Parser;
struct Validator;
struct Transformer;
struct Serializer;

impl Stage for Parser {
    fn process(&self, input: i32) -> i32 { input.abs() }
}
impl Stage for Validator {
    fn process(&self, input: i32) -> i32 { if input > 0 { input } else { 1 } }
}
impl Stage for Transformer {
    fn process(&self, input: i32) -> i32 { input * 2 }
}
impl Stage for Serializer {
    fn process(&self, input: i32) -> i32 { input % 1000 }
}

fn run_pipeline(input: i32) -> i32 {
    let stages: Vec<Box<dyn Stage>> = vec![
        Box::new(Parser),
        Box::new(Validator),
        Box::new(Transformer),
        Box::new(Serializer),
    ];
    stages.iter().fold(input, |acc, s| s.process(acc))
}
"#;
    let cpg = rs(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let trait_def = find_node_by_kind_and_name(&cpg, IrNodeKind::TraitDef, "Stage");
    assert!(trait_def.is_some(), "expected TraitDef for 'Stage'");

    let impl_blocks = nodes_of_kind(&cpg, IrNodeKind::ImplBlock);
    assert!(impl_blocks.len() >= 4, "expected at least 4 ImplBlock nodes, got {}", impl_blocks.len());
}

// ═══════════════════════════════════════════════════════════════════════════════
// GO TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// ── Go: Structs, interfaces, methods ──────────────────────────────────────────

#[test]
fn go_struct_with_methods_and_interface() {
    let src = r#"
package main

type Animal interface {
    Sound() string
    Name() string
}

type Dog struct {
    name string
    breed string
}

func (d Dog) Sound() string { return "Woof" }
func (d Dog) Name() string { return d.name }
func (d Dog) Breed() string { return d.breed }

type Cat struct {
    name string
}

func (c Cat) Sound() string { return "Meow" }
func (c Cat) Name() string { return c.name }

func MakeNoise(a Animal) string {
    return a.Name() + " says " + a.Sound()
}
"#;
    let cpg = go(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let dog = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "Dog");
    assert!(dog.is_some(), "expected ClassDef for 'Dog' struct");

    let sound_impls: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("Sound"))
        .collect();
    assert!(
        sound_impls.len() >= 2,
        "expected Sound() defined for both Dog and Cat, got {}",
        sound_impls.len()
    );
}

#[test]
fn go_struct_embedding() {
    let src = r#"
package main

type Base struct {
    ID   int
    Name string
}

func (b Base) Describe() string {
    return b.Name
}

type Employee struct {
    Base
    Department string
    Salary     float64
}

type Manager struct {
    Employee
    Reports []string
}

func NewManager(name string, dept string) Manager {
    return Manager{
        Employee: Employee{
            Base:       Base{Name: name},
            Department: dept,
        },
    }
}
"#;
    let cpg = go(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let employee = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "Employee");
    assert!(employee.is_some(), "expected ClassDef for 'Employee'");

    let manager = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "Manager");
    assert!(manager.is_some(), "expected ClassDef for 'Manager'");
}

#[test]
fn go_interface_with_type_assertion() {
    let src = r#"
package main

type Stringer interface {
    String() string
}

type MyInt int

func (m MyInt) String() string {
    return "MyInt"
}

func printIfStringer(v interface{}) string {
    if s, ok := v.(Stringer); ok {
        return s.String()
    }
    return "not a stringer"
}
"#;
    let cpg = go(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let assertions = nodes_of_kind(&cpg, IrNodeKind::TypeAssertion);
    assert!(!assertions.is_empty(), "type assertion should produce TypeAssertion nodes");
}

#[test]
fn go_type_switch() {
    let src = r#"
package main

func describe(v interface{}) string {
    switch val := v.(type) {
    case int:
        return "int"
    case string:
        return "string: " + val
    case bool:
        if val { return "true" }
        return "false"
    case []int:
        return "int slice"
    default:
        return "unknown"
    }
}
"#;
    let cpg = go(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let type_switches = nodes_of_kind(&cpg, IrNodeKind::TypeSwitch);
    assert!(!type_switches.is_empty(), "type switch should produce TypeSwitch nodes");

    let type_cases = nodes_of_kind(&cpg, IrNodeKind::TypeCase);
    assert!(type_cases.len() >= 4, "expected at least 4 type cases, got {}", type_cases.len());
}

#[test]
fn go_closure_and_higher_order_function() {
    let src = r#"
package main

func makeCounter(start int) func() int {
    count := start
    return func() int {
        count++
        return count
    }
}

func filter(nums []int, pred func(int) bool) []int {
    var result []int
    for _, n := range nums {
        if pred(n) {
            result = append(result, n)
        }
    }
    return result
}

func compose(f, g func(int) int) func(int) int {
    return func(x int) int {
        return f(g(x))
    }
}

func main() {
    counter := makeCounter(0)
    evens := filter([]int{1,2,3,4}, func(n int) bool { return n%2 == 0 })
    double := func(x int) int { return x * 2 }
    addOne := func(x int) int { return x + 1 }
    doubleAddOne := compose(addOne, double)
    _ = counter() + len(evens) + doubleAddOne(5)
}
"#;
    let cpg = go(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let lambdas = nodes_of_kind(&cpg, IrNodeKind::LambdaDef);
    assert!(lambdas.len() >= 4, "expected at least 4 function literals, got {}", lambdas.len());
}

#[test]
fn go_goroutine_and_channel() {
    let src = r#"
package main

func producer(ch chan<- int, n int) {
    for i := 0; i < n; i++ {
        ch <- i
    }
    close(ch)
}

func consumer(ch <-chan int) int {
    sum := 0
    for v := range ch {
        sum += v
    }
    return sum
}

func pipeline() int {
    ch := make(chan int, 10)
    go producer(ch, 5)
    return consumer(ch)
}
"#;
    let cpg = go(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let go_stmts = nodes_of_kind(&cpg, IrNodeKind::GoStmt);
    assert!(!go_stmts.is_empty(), "goroutine launch should produce GoStmt nodes");

    let send_stmts = nodes_of_kind(&cpg, IrNodeKind::SendStmt);
    assert!(!send_stmts.is_empty(), "channel send should produce SendStmt nodes");
}

#[test]
fn go_defer_and_panic_recover() {
    let src = r#"
package main

func safeDiv(a, b int) (result int, err error) {
    defer func() {
        if r := recover(); r != nil {
            err = fmt.Errorf("recovered: %v", r)
        }
    }()
    if b == 0 {
        panic("division by zero")
    }
    return a / b, nil
}

func withCleanup(name string) {
    defer fmt.Println("cleanup:", name)
    defer func() {
        fmt.Println("inner cleanup")
    }()
    fmt.Println("working:", name)
}
"#;
    let cpg = go(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let defers = nodes_of_kind(&cpg, IrNodeKind::DeferStmt);
    assert!(defers.len() >= 2, "expected at least 2 defer statements, got {}", defers.len());
}

#[test]
fn go_interface_composition() {
    let src = r#"
package main

type Reader interface {
    Read() string
}

type Writer interface {
    Write(s string)
}

type ReadWriter interface {
    Reader
    Writer
}

type Buffer struct {
    data string
}

func (b *Buffer) Read() string { return b.data }
func (b *Buffer) Write(s string) { b.data += s }

func process(rw ReadWriter) {
    rw.Write("hello")
    _ = rw.Read()
}
"#;
    let cpg = go(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let reader = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "Reader");
    assert!(reader.is_some(), "expected ClassDef for 'Reader' interface");
    let (rid, _) = reader.unwrap();
    let meta = cpg.go_meta(rid);
    assert!(meta.is_some(), "Reader should have GoNodeMetadata");
    assert!(meta.unwrap().is_interface, "Reader should be flagged as is_interface");
}

// ═══════════════════════════════════════════════════════════════════════════════
// JAVASCRIPT TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// ── JavaScript: ES6 classes and inheritance ───────────────────────────────────

#[test]
fn js_es6_class_with_inheritance() {
    let src = r#"
class Shape {
    constructor(color) {
        this.color = color;
    }
    area() { return 0; }
    toString() { return `${this.constructor.name}(${this.color})`; }
}

class Circle extends Shape {
    constructor(color, radius) {
        super(color);
        this.radius = radius;
    }
    area() { return Math.PI * this.radius ** 2; }
}

class Rectangle extends Shape {
    constructor(color, width, height) {
        super(color);
        this.width = width;
        this.height = height;
    }
    area() { return this.width * this.height; }
}
"#;
    let cpg = js(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let shape = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "Shape");
    assert!(shape.is_some(), "expected ClassDef for 'Shape'");

    let circle = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "Circle");
    assert!(circle.is_some(), "expected ClassDef for 'Circle'");
    let circle_node = circle.unwrap().1;
    assert!(
        circle_node.base_classes.as_ref().map(|b| b.iter().any(|s| s.contains("Shape"))).unwrap_or(false),
        "Circle.base_classes should include Shape, got {:?}",
        circle_node.base_classes
    );

    let area_defs: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("area"))
        .collect();
    assert!(area_defs.len() >= 3, "expected 3 area() definitions, got {}", area_defs.len());
}

#[test]
fn js_arrow_functions_various_forms() {
    let src = r#"
const identity = x => x;
const add = (a, b) => a + b;
const square = (x) => { return x * x; };
const greet = name => ({ message: `Hello, ${name}!` });
const makeAdder = n => x => x + n;
const noop = () => {};
"#;
    let cpg = js(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let lambdas = nodes_of_kind(&cpg, IrNodeKind::LambdaDef);
    assert!(lambdas.len() >= 6, "expected at least 6 arrow functions, got {}", lambdas.len());

    for (id, _) in cpg.ast.iter().filter(|(_, n)| n.kind == IrNodeKind::LambdaDef) {
        if let Some(meta) = cpg.js_meta(*id) {
            assert!(meta.is_arrow, "all LambdaDefs from => syntax should have is_arrow=true");
        }
    }
}

#[test]
fn js_generator_function() {
    let src = r#"
function* range(start, end, step = 1) {
    for (let i = start; i < end; i += step) {
        yield i;
    }
}

function* fibonacci() {
    let [a, b] = [0, 1];
    while (true) {
        yield a;
        [a, b] = [b, a + b];
    }
}

function* take(n, gen) {
    let count = 0;
    for (const val of gen) {
        if (count++ >= n) return;
        yield val;
    }
}
"#;
    let cpg = js(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let yields = nodes_of_kind(&cpg, IrNodeKind::YieldExpr);
    assert!(yields.len() >= 3, "expected at least 3 yield expressions, got {}", yields.len());

    let fib_id = cpg
        .ast
        .iter()
        .find_map(|(&id, n)| {
            if n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("fibonacci") {
                Some(id)
            } else {
                None
            }
        });
    assert!(fib_id.is_some(), "expected MethodDef for 'fibonacci'");
    let meta = cpg.js_meta(fib_id.unwrap());
    assert!(meta.is_some(), "fibonacci should have JsNodeMetadata");
    assert!(meta.unwrap().is_generator, "fibonacci should be flagged as is_generator");
}

#[test]
fn js_async_await_chain() {
    let src = r#"
async function fetchUser(id) {
    const response = await fetch(`/api/users/${id}`);
    return response.json();
}

async function fetchPosts(userId) {
    const user = await fetchUser(userId);
    const posts = await fetch(`/api/posts?userId=${user.id}`);
    return posts.json();
}

async function main() {
    try {
        const posts = await fetchPosts(42);
        return posts.length;
    } catch (e) {
        return 0;
    }
}
"#;
    let cpg = js(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let fetch_user_id = cpg
        .ast
        .iter()
        .find_map(|(&id, n)| {
            if n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("fetchUser") {
                Some(id)
            } else {
                None
            }
        });
    assert!(fetch_user_id.is_some(), "expected MethodDef for 'fetchUser'");
    let meta = cpg.js_meta(fetch_user_id.unwrap());
    assert!(meta.is_some(), "fetchUser should have JsNodeMetadata");
    assert!(meta.unwrap().is_async, "fetchUser should be flagged as is_async");
}

#[test]
fn js_optional_chaining_and_nullish() {
    let src = r#"
function getCity(user) {
    return user?.address?.city ?? "Unknown";
}

function getLength(arr) {
    return arr?.length ?? 0;
}

function callMethod(obj) {
    return obj?.toString?.() ?? "";
}

const config = {
    server: {
        host: "localhost",
        port: 8080,
    }
};
const port = config?.server?.port ?? 3000;
"#;
    let cpg = js(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let opt_chains = nodes_of_kind(&cpg, IrNodeKind::OptionalChain);
    assert!(!opt_chains.is_empty(), "optional chaining should produce OptionalChain nodes");
}

#[test]
fn js_closure_and_iife() {
    let src = r#"
const counter = (function() {
    let count = 0;
    return {
        increment: function() { count++; },
        decrement: function() { count--; },
        value: function() { return count; }
    };
})();

function makeAdder(x) {
    return function(y) {
        return x + y;
    };
}

const memoize = (fn) => {
    const cache = new Map();
    return (...args) => {
        const key = JSON.stringify(args);
        if (cache.has(key)) return cache.get(key);
        const result = fn(...args);
        cache.set(key, result);
        return result;
    };
};
"#;
    let cpg = js(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let lambdas = nodes_of_kind(&cpg, IrNodeKind::LambdaDef);
    let methods = nodes_of_kind(&cpg, IrNodeKind::MethodDef);
    let total = lambdas.len() + methods.len();
    assert!(total >= 3, "expected at least 3 function definitions (IIFE + makeAdder + memoize), got {}", total);
}

#[test]
fn js_class_private_fields_and_static() {
    let src = r#"
class BankAccount {
    #balance = 0;
    #owner;
    static #interestRate = 0.05;

    constructor(owner, initialBalance) {
        this.#owner = owner;
        this.#balance = initialBalance;
    }

    deposit(amount) {
        if (amount > 0) this.#balance += amount;
    }

    withdraw(amount) {
        if (amount <= this.#balance) this.#balance -= amount;
    }

    get balance() { return this.#balance; }
    get owner() { return this.#owner; }

    static getInterestRate() { return BankAccount.#interestRate; }
}
"#;
    let cpg = js(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let account = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "BankAccount");
    assert!(account.is_some(), "expected ClassDef for 'BankAccount'");
}

// ═══════════════════════════════════════════════════════════════════════════════
// TYPESCRIPT TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// ── TypeScript: Interfaces and generics ───────────────────────────────────────

#[test]
fn ts_interface_declaration() {
    let src = r#"
interface Printable {
    print(): void;
    toString(): string;
}

interface Comparable<T> {
    compareTo(other: T): number;
    equals(other: T): boolean;
}

interface Named {
    readonly name: string;
    displayName?: string;
}
"#;
    let cpg = ts(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let interfaces = nodes_of_kind(&cpg, IrNodeKind::InterfaceDecl);
    assert!(interfaces.len() >= 3, "expected at least 3 interfaces, got {}", interfaces.len());
}

#[test]
fn ts_class_implements_interface_with_generics() {
    let src = r#"
interface Repository<T, ID> {
    findById(id: ID): T | null;
    save(entity: T): T;
    delete(id: ID): boolean;
    findAll(): T[];
}

interface User {
    id: number;
    name: string;
    email: string;
}

class UserRepository implements Repository<User, number> {
    private users: Map<number, User> = new Map();

    findById(id: number): User | null {
        return this.users.get(id) ?? null;
    }

    save(user: User): User {
        this.users.set(user.id, user);
        return user;
    }

    delete(id: number): boolean {
        return this.users.delete(id);
    }

    findAll(): User[] {
        return Array.from(this.users.values());
    }
}
"#;
    let cpg = ts(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let repo = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "UserRepository");
    assert!(repo.is_some(), "expected ClassDef for 'UserRepository'");
    let (repo_id, _) = repo.unwrap();
    let meta = cpg.ts_meta(repo_id);
    assert!(meta.is_some(), "UserRepository should have TsNodeMetadata");
    let ts_meta = meta.unwrap();
    assert!(
        !ts_meta.implements_types.is_empty(),
        "UserRepository should implement at least one interface, got {:?}",
        ts_meta.implements_types
    );
}

#[test]
fn ts_abstract_class() {
    let src = r#"
abstract class Animal {
    abstract sound(): string;
    abstract name: string;

    describe(): string {
        return `${this.name} says ${this.sound()}`;
    }

    move(distance: number = 0): void {
        console.log(`${this.name} moved ${distance}m.`);
    }
}

class Snake extends Animal {
    name = "Snake";
    sound(): string { return "hiss"; }
}

class Horse extends Animal {
    name = "Horse";
    sound(): string { return "neigh"; }
    override move(distance: number = 45): void {
        super.move(distance);
    }
}
"#;
    let cpg = ts(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let animal = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "Animal");
    assert!(animal.is_some(), "expected ClassDef for abstract 'Animal'");
    let (animal_id, _) = animal.unwrap();
    let meta = cpg.ts_meta(animal_id);
    assert!(meta.is_some(), "Animal should have TsNodeMetadata");
    assert!(meta.unwrap().is_abstract, "Animal should be flagged as is_abstract");

    // TS stores extends in ts_meta.extends_type, not in node.base_classes
    let snake = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "Snake");
    assert!(snake.is_some(), "expected ClassDef for 'Snake'");
    let (snake_id, _) = snake.unwrap();
    let snake_meta = cpg.ts_meta(snake_id).expect("Snake should have TsNodeMetadata");
    assert!(
        snake_meta.extends_type.as_deref().map(|t| t.contains("Animal")).unwrap_or(false),
        "Snake ts_meta.extends_type should include Animal, got {:?}",
        snake_meta.extends_type
    );
}

#[test]
fn ts_namespace_declaration() {
    let src = r#"
namespace Geometry {
    export interface Point {
        x: number;
        y: number;
    }

    export class Circle {
        constructor(public center: Point, public radius: number) {}
        area(): number { return Math.PI * this.radius ** 2; }
    }

    export namespace Utils {
        export function distance(a: Point, b: Point): number {
            return Math.sqrt((a.x - b.x) ** 2 + (a.y - b.y) ** 2);
        }
    }
}
"#;
    let cpg = ts(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let namespaces = nodes_of_kind(&cpg, IrNodeKind::Namespace);
    assert!(!namespaces.is_empty(), "TypeScript namespace should produce Namespace nodes");

    let geom = find_node_by_kind_and_name(&cpg, IrNodeKind::Namespace, "Geometry");
    assert!(geom.is_some(), "expected Namespace node named 'Geometry'");
    // Verify nested namespace is also present
    let utils_ns = find_node_by_kind_and_name(&cpg, IrNodeKind::Namespace, "Utils");
    assert!(utils_ns.is_some(), "expected nested Namespace node named 'Utils'");
}

#[test]
fn ts_enum_const_and_regular() {
    let src = r#"
enum Direction {
    Up = "UP",
    Down = "DOWN",
    Left = "LEFT",
    Right = "RIGHT"
}

const enum Color {
    Red,
    Green,
    Blue,
}

enum Status {
    Active = 1,
    Inactive = 0,
    Pending = -1,
}
"#;
    let cpg = ts(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let enums = nodes_of_kind(&cpg, IrNodeKind::EnumDecl);
    assert!(enums.len() >= 3, "expected at least 3 enum declarations, got {}", enums.len());

    let color_enum = cpg
        .ast
        .iter()
        .find(|(_, n)| n.kind == IrNodeKind::EnumDecl && n.name.as_deref() == Some("Color"));
    assert!(color_enum.is_some(), "expected EnumDecl named 'Color'");
    let (color_id, _) = color_enum.unwrap();
    let meta = cpg.ts_meta(*color_id);
    assert!(meta.is_some(), "Color enum should have TsNodeMetadata");
    assert!(meta.unwrap().enum_is_const, "const enum Color should have enum_is_const=true");
}

#[test]
fn ts_generic_function_with_constraints() {
    let src = r#"
function first<T>(arr: T[]): T | undefined {
    return arr[0];
}

function merge<T extends object, U extends object>(a: T, b: U): T & U {
    return { ...a, ...b };
}

function getProperty<T, K extends keyof T>(obj: T, key: K): T[K] {
    return obj[key];
}

interface HasId {
    id: number;
}

function findById<T extends HasId>(items: T[], id: number): T | undefined {
    return items.find(item => item.id === id);
}
"#;
    let cpg = ts(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    for name in &["first", "merge", "getProperty", "findById"] {
        assert!(
            cpg.ast.values().any(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some(name)),
            "expected MethodDef for '{name}'"
        );
    }

    let merge_id = cpg
        .ast
        .iter()
        .find_map(|(&id, n)| {
            if n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("merge") {
                Some(id)
            } else {
                None
            }
        });
    assert!(merge_id.is_some());
    let meta = cpg.ts_meta(merge_id.unwrap());
    assert!(meta.is_some(), "merge should have TsNodeMetadata");
    assert!(
        !meta.unwrap().generic_constraints.is_empty(),
        "merge should have generic constraints"
    );
}

#[test]
fn ts_type_predicate_and_narrowing() {
    let src = r#"
interface Fish { swim(): void; }
interface Bird { fly(): void; }

function isFish(pet: Fish | Bird): pet is Fish {
    return (pet as Fish).swim !== undefined;
}

function isBird(pet: Fish | Bird): pet is Bird {
    return (pet as Bird).fly !== undefined;
}

function move(pet: Fish | Bird): void {
    if (isFish(pet)) {
        pet.swim();
    } else {
        pet.fly();
    }
}
"#;
    let cpg = ts(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let predicates = nodes_of_kind(&cpg, IrNodeKind::TypePredicate);
    assert!(
        !predicates.is_empty(),
        "type predicate return types should produce TypePredicate nodes"
    );
}

#[test]
fn ts_decorator_on_class_and_method() {
    let src = r#"
function sealed(constructor: Function) {
    Object.seal(constructor);
    Object.seal(constructor.prototype);
}

function log(target: any, key: string, descriptor: PropertyDescriptor) {
    const original = descriptor.value;
    descriptor.value = function(...args: any[]) {
        console.log(`Calling ${key}`);
        return original.apply(this, args);
    };
    return descriptor;
}

@sealed
class Greeter {
    greeting: string;
    constructor(message: string) {
        this.greeting = message;
    }
    @log
    greet(): string {
        return `Hello, ${this.greeting}`;
    }
}
"#;
    let cpg = ts(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let greeter = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "Greeter");
    assert!(greeter.is_some(), "expected ClassDef for 'Greeter'");
    let (greeter_id, _) = greeter.unwrap();
    let meta = cpg.ts_meta(greeter_id);
    assert!(meta.is_some(), "Greeter should have TsNodeMetadata");
    assert!(
        !meta.unwrap().decorator_names.is_empty(),
        "Greeter should have decorator_names populated"
    );
}

#[test]
fn ts_intersection_and_union_types() {
    let src = r#"
type StringOrNumber = string | number;
type Nullable<T> = T | null | undefined;
type AdminUser = { id: number } & { role: 'admin' } & { permissions: string[] };

function formatValue(value: StringOrNumber): string {
    if (typeof value === 'string') {
        return value.toUpperCase();
    }
    return value.toFixed(2);
}

function coalesce<T>(value: Nullable<T>, fallback: T): T {
    return value ?? fallback;
}
"#;
    let cpg = ts(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let type_aliases = nodes_of_kind(&cpg, IrNodeKind::TypeAlias);
    assert!(type_aliases.len() >= 3, "expected at least 3 type aliases, got {}", type_aliases.len());
}

// ═══════════════════════════════════════════════════════════════════════════════
// CROSS-LANGUAGE: Interprocedural chain tests
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn cpp_six_level_call_chain_with_data_flow() {
    let src = r#"
        int sanitize(int raw) { return raw < 0 ? -raw : raw; }
        int normalize(int x) { return sanitize(x) % 100; }
        int transform(int x) { return normalize(x) * 2; }
        int aggregate(int x, int y) { return transform(x) + transform(y); }
        int finalize(int x, int y) { int t = aggregate(x, y); return t > 50 ? 50 : t; }
        int pipeline(int a, int b) { return finalize(a, b); }
    "#;
    let cpg = cpp(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let all_fns = ["sanitize", "normalize", "transform", "aggregate", "finalize", "pipeline"];
    for name in &all_fns {
        assert!(
            cpg.ast.values().any(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some(name)),
            "function '{name}' should be in AST"
        );
    }

    let callees: Vec<_> = cpg
        .call_graph
        .values()
        .flat_map(|e| e.calls.iter().map(|c| c.callee.clone()))
        .collect();
    for callee in &["sanitize", "normalize", "transform", "aggregate", "finalize"] {
        assert!(callees.contains(&callee.to_string()), "'{callee}' should appear as callee");
    }

    let defs: Vec<_> = cpg.dataflow.definitions.iter().map(|d| d.variable.clone()).collect();
    assert!(!defs.is_empty(), "data flow should have variable definitions");
}

#[test]
fn java_deep_chain_with_exception_flow() {
    let src = r#"
        public class Processor {
            public static String run(String input) throws Exception {
                return format(validate(parse(input)));
            }
            private static String[] parse(String s) {
                if (s == null) throw new IllegalArgumentException("null");
                return s.split(",");
            }
            private static String[] validate(String[] parts) {
                if (parts.length == 0) throw new IllegalStateException("empty");
                return parts;
            }
            private static String format(String[] parts) {
                StringBuilder sb = new StringBuilder();
                for (String p : parts) sb.append(p.trim());
                return sb.toString();
            }
        }
    "#;
    let cpg = java(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    for name in &["run", "parse", "validate", "format"] {
        assert!(
            cpg.ast.values().any(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some(name)),
            "method '{name}' should be in AST"
        );
    }

    let throw_nodes = nodes_of_kind(&cpg, IrNodeKind::Throw);
    assert!(throw_nodes.len() >= 2, "expected at least 2 throw statements, got {}", throw_nodes.len());
}

// ═══════════════════════════════════════════════════════════════════════════════
// EDGE CASES AND LANGUAGE QUIRKS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn cpp_lambda_in_template_parameter() {
    let src = r#"
        #include <algorithm>
        void sort_descending(int* begin, int* end) {
            std::sort(begin, end, [](int a, int b) { return a > b; });
        }
        int find_first(int* begin, int* end, int target) {
            auto it = std::find_if(begin, end, [target](int x) { return x == target; });
            return (it != end) ? *it : -1;
        }
    "#;
    let cpg = cpp(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let lambdas = nodes_of_kind(&cpg, IrNodeKind::LambdaDef);
    assert!(lambdas.len() >= 2, "lambdas in std::sort/find_if args should produce LambdaDef nodes");
}

#[test]
fn cpp_template_specialization() {
    let src = r#"
        template<typename T>
        struct TypeTraits {
            static bool is_integral() { return false; }
        };
        template<>
        struct TypeTraits<int> {
            static bool is_integral() { return true; }
        };
        template<>
        struct TypeTraits<long> {
            static bool is_integral() { return true; }
        };
    "#;
    let cpg = cpp(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    assert!(!cpg.ast.is_empty());
}

#[test]
fn python_class_decorators_metadata() {
    let src = r#"
from dataclasses import dataclass
from typing import ClassVar

@dataclass
class Point:
    x: float
    y: float
    count: ClassVar[int] = 0

    def distance(self) -> float:
        return (self.x ** 2 + self.y ** 2) ** 0.5

@dataclass(frozen=True)
class ImmutablePoint:
    x: float
    y: float
"#;
    let cpg = py(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let point = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "Point");
    assert!(point.is_some(), "expected ClassDef for 'Point'");
    let decorator_nodes = nodes_of_kind(&cpg, IrNodeKind::Decorator);
    assert!(!decorator_nodes.is_empty(), "@dataclass should produce Decorator nodes");
}

#[test]
fn python_super_call_in_init() {
    let src = r#"
class A:
    def __init__(self, x):
        self.x = x

class B(A):
    def __init__(self, x, y):
        super().__init__(x)
        self.y = y

class C(B):
    def __init__(self, x, y, z):
        super().__init__(x, y)
        self.z = z
"#;
    let cpg = py(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    for cls in &["A", "B", "C"] {
        assert!(
            cpg.ast.values().any(|n| n.kind == IrNodeKind::ClassDef && n.name.as_deref() == Some(cls)),
            "expected ClassDef for '{cls}'"
        );
    }
    let super_calls: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::Call)
        .filter(|n| n.name.as_deref() == Some("super") || n.text.as_deref().map(|t| t.contains("super")).unwrap_or(false))
        .collect();
    assert!(!super_calls.is_empty(), "super() calls should appear in call graph");
}

#[test]
fn rust_lifetime_annotations() {
    let src = r#"
struct StrSplit<'a, 'b> {
    remainder: &'a str,
    delimiter: &'b str,
}

impl<'a, 'b> StrSplit<'a, 'b> {
    fn new(s: &'a str, d: &'b str) -> Self {
        StrSplit { remainder: s, delimiter: d }
    }
}

fn longest<'a>(x: &'a str, y: &'a str) -> &'a str {
    if x.len() > y.len() { x } else { y }
}

fn first_word<'a>(s: &'a str) -> &'a str {
    match s.find(' ') {
        Some(idx) => &s[..idx],
        None => s,
    }
}
"#;
    let cpg = rs(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let lifetime_refs = nodes_of_kind(&cpg, IrNodeKind::LifetimeRef);
    assert!(!lifetime_refs.is_empty(), "lifetime annotations should produce LifetimeRef nodes");

    let longest_id = cpg
        .ast
        .iter()
        .find_map(|(&id, n)| {
            if n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some("longest") {
                Some(id)
            } else {
                None
            }
        });
    assert!(longest_id.is_some(), "expected MethodDef for 'longest'");
    let meta = cpg.rust_meta(longest_id.unwrap());
    assert!(meta.is_some(), "longest should have RustNodeMetadata");
    assert!(
        !meta.unwrap().lifetimes.is_empty(),
        "longest should have lifetimes recorded"
    );
}

#[test]
fn rust_derive_macros() {
    let src = r#"
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Point {
    x: i32,
    y: i32,
}

#[derive(Debug, Clone, Default)]
struct Config {
    name: String,
    value: i32,
    enabled: bool,
}

#[derive(Debug)]
enum Color {
    Red,
    Green,
    Blue,
    Custom(u8, u8, u8),
}
"#;
    let cpg = rs(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let point = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "Point");
    assert!(point.is_some(), "expected ClassDef for 'Point'");
    let (point_id, _) = point.unwrap();
    let meta = cpg.rust_meta(point_id);
    assert!(meta.is_some(), "Point should have RustNodeMetadata");
    assert!(
        !meta.unwrap().derive_macros.is_empty(),
        "Point should have derive macros recorded"
    );
}

#[test]
fn go_multiple_return_values() {
    let src = r#"
package main

func divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, fmt.Errorf("division by zero")
    }
    return a / b, nil
}

func minMax(nums []int) (min, max int) {
    min, max = nums[0], nums[0]
    for _, n := range nums[1:] {
        if n < min { min = n }
        if n > max { max = n }
    }
    return
}

func swap(a, b int) (int, int) {
    return b, a
}
"#;
    let cpg = go(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    for name in &["divide", "minMax", "swap"] {
        assert!(
            cpg.ast.values().any(|n| n.kind == IrNodeKind::MethodDef && n.name.as_deref() == Some(name)),
            "function '{name}' should be in AST"
        );
    }
}

#[test]
fn js_prototype_chain_quirk() {
    let src = r#"
function Animal(name) {
    this.name = name;
}
Animal.prototype.speak = function() {
    return this.name + " makes a noise.";
};

function Dog(name) {
    Animal.call(this, name);
}
Dog.prototype = Object.create(Animal.prototype);
Dog.prototype.constructor = Dog;
Dog.prototype.speak = function() {
    return this.name + " barks.";
};

const d = new Dog("Rex");
const sound = d.speak();
"#;
    let cpg = js(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    assert!(!cpg.ast.is_empty());
    let animal_fn = cpg.ast.values().find(|n| n.name.as_deref() == Some("Animal"));
    assert!(animal_fn.is_some(), "Animal constructor function should appear in AST");
}

#[test]
fn ts_conditional_type_and_infer() {
    let src = r#"
type IsArray<T> = T extends any[] ? true : false;
type ElementType<T> = T extends (infer E)[] ? E : never;
type Flatten<T> = T extends Array<infer Item> ? Item : T;

type ReturnType<T extends (...args: any) => any> =
    T extends (...args: any) => infer R ? R : any;

type Parameters<T extends (...args: any) => any> =
    T extends (...args: infer P) => any ? P : never;
"#;
    let cpg = ts(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let type_aliases = nodes_of_kind(&cpg, IrNodeKind::TypeAlias);
    assert!(type_aliases.len() >= 5, "expected at least 5 type aliases, got {}", type_aliases.len());
}

#[test]
fn cpp_crtp_static_polymorphism() {
    let src = r#"
        template<typename Derived>
        class Base {
        public:
            void interface_method() {
                static_cast<Derived*>(this)->implementation();
            }
            void common_method() { int x = 1; }
        };

        class Concrete1 : public Base<Concrete1> {
        public:
            void implementation() { int a = 1; }
        };

        class Concrete2 : public Base<Concrete2> {
        public:
            void implementation() { int b = 2; }
        };

        template<typename T>
        void call_interface(Base<T>& obj) {
            obj.interface_method();
        }
    "#;
    let cpg = cpp(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let base = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "Base");
    assert!(base.is_some(), "expected ClassDef for CRTP 'Base'");

    let concretes = ["Concrete1", "Concrete2"]
        .iter()
        .filter(|&&name| {
            cpg.ast.values().any(|n| n.kind == IrNodeKind::ClassDef && n.name.as_deref() == Some(name))
        })
        .count();
    assert_eq!(concretes, 2, "expected both Concrete1 and Concrete2 ClassDef nodes");
}

#[test]
fn python_metaclass() {
    let src = r#"
class SingletonMeta(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]

class Singleton(metaclass=SingletonMeta):
    def __init__(self, value):
        self.value = value

class Registry(metaclass=SingletonMeta):
    def __init__(self):
        self.entries = {}

    def register(self, key, value):
        self.entries[key] = value
"#;
    let cpg = py(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let singleton_meta = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "SingletonMeta");
    assert!(singleton_meta.is_some(), "expected ClassDef for 'SingletonMeta'");

    let singleton = find_node_by_kind_and_name(&cpg, IrNodeKind::ClassDef, "Singleton");
    assert!(singleton.is_some(), "expected ClassDef for 'Singleton'");
    let (sid, _) = singleton.unwrap();
    let meta = cpg.python_meta(sid);
    assert!(meta.is_some(), "Singleton should have PythonNodeMetadata");
    let pmeta = meta.unwrap();
    assert!(
        pmeta.metaclass.as_deref().map(|m| m.contains("SingletonMeta")).unwrap_or(false),
        "Singleton.metaclass should be 'SingletonMeta', got {:?}",
        pmeta.metaclass
    );
}

#[test]
fn rust_impl_multiple_traits_for_one_type() {
    let src = r#"
use std::fmt;

struct Matrix {
    data: [[f64; 2]; 2],
}

impl Matrix {
    fn new(a: f64, b: f64, c: f64, d: f64) -> Self {
        Matrix { data: [[a, b], [c, d]] }
    }

    fn det(&self) -> f64 {
        self.data[0][0] * self.data[1][1] - self.data[0][1] * self.data[1][0]
    }
}

impl fmt::Display for Matrix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[[{}, {}], [{}, {}]]",
            self.data[0][0], self.data[0][1],
            self.data[1][0], self.data[1][1])
    }
}

impl Default for Matrix {
    fn default() -> Self {
        Matrix { data: [[1.0, 0.0], [0.0, 1.0]] }
    }
}
"#;
    let cpg = rs(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let impl_blocks = nodes_of_kind(&cpg, IrNodeKind::ImplBlock);
    assert!(
        impl_blocks.len() >= 3,
        "expected at least 3 ImplBlocks for Matrix (inherent + Display + Default), got {}",
        impl_blocks.len()
    );

    for (id, _) in cpg.ast.iter().filter(|(_, n)| n.kind == IrNodeKind::ImplBlock) {
        let meta = cpg.rust_meta(*id);
        assert!(meta.is_some(), "every ImplBlock should have RustNodeMetadata");
        let rmeta = meta.unwrap();
        assert!(rmeta.self_type.is_some(), "ImplBlock should have self_type set");
    }
}
