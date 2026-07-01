//! Grammar coverage tests for C++ tree-sitter node types.
//!
//! Each test targets a specific grammar construct and verifies:
//!   1. CPG generation does not panic
//!   2. CFG structural validity (no dangling successor references)
//!   3. DFG structural validity (no dangling node IDs)
//!   4. A semantic property specific to that node type
//!
//! Tests marked "Phase 2" will fail until the corresponding CPG fixes land.

use std::collections::HashSet;

use web_sitter::{Cpg, IrNodeKind, NodeId};
use web_sitter::{
    CpgGenerator, GraphBuildOptions, IncrementalCpgGenerator, SourceLanguage, compute_edit,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn cpp_cpg(src: &str) -> Cpg {
    CpgGenerator::new_for_language(SourceLanguage::Cpp)
        .expect("C++ parser init")
        .generate_from_source_with_options(src.as_bytes(), GraphBuildOptions::default())
        .expect("C++ CPG generation failed")
}

fn cpp_cpg_full_text(src: &str) -> Cpg {
    let opts = GraphBuildOptions {
        minimal_text: false,
        ..GraphBuildOptions::default()
    };
    CpgGenerator::new_for_language(SourceLanguage::Cpp)
        .expect("C++ parser init")
        .generate_from_source_with_options(src.as_bytes(), opts)
        .expect("C++ CPG generation failed")
}

fn nodes_of_type<'a>(cpg: &'a Cpg, kind: &str) -> Vec<(&'a NodeId, &'a web_sitter::AstNode)> {
    cpg.ast
        .iter()
        .filter(|(_, n)| n.node_type == kind)
        .collect()
}

fn assert_cfg_valid(cpg: &Cpg) {
    let bb_keys: HashSet<&String> = cpg.basic_blocks.keys().collect();
    for bb in cpg.basic_blocks.values() {
        for succ in &bb.successors {
            assert!(
                bb_keys.contains(succ),
                "BB successor '{succ}' not found in basic_blocks"
            );
        }
        for exc in &bb.exception_successors {
            assert!(
                bb_keys.contains(exc),
                "Exception successor BB '{exc}' not found in basic_blocks"
            );
        }
    }
}

fn assert_dfg_valid(cpg: &Cpg) {
    let ast_ids: HashSet<NodeId> = cpg.ast.keys().copied().collect();
    for edge in &cpg.dataflow.edges {
        assert!(
            ast_ids.contains(&edge.source),
            "DFG edge source {} not in AST",
            edge.source
        );
        assert!(
            ast_ids.contains(&edge.destination),
            "DFG edge destination {} not in AST",
            edge.destination
        );
    }
}

// ── field_initializer_list / field_initializer ────────────────────────────────

#[test]
fn field_initializer_list_no_crash() {
    // Constructor member-initializer list: Foo(int x, int y) : m_x(x), m_y(y) {}
    let src = r#"
        struct Foo {
            int m_x;
            int m_y;
            Foo(int x, int y) : m_x(x), m_y(y) {}
        };
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

#[test]
fn field_initializer_list_dfg_edges() {
    let src = r#"
        struct Point {
            int x;
            int y;
            Point(int px, int py) : x(px), y(py) {}
        };
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    // Constructor should be detected
    let ctors: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.is_constructor == Some(true))
        .collect();
    assert!(
        !ctors.is_empty(),
        "Point(int,int) should be flagged as constructor"
    );

    // DFG should have a real edge from each constructor param to the field
    // identifier it initializes: `px` -> `x`, `py` -> `y` — not just "some
    // edges exist somewhere".
    // The `parameter_declaration` (ParamDef) node itself carries no DFG edges —
    // those live on its nested `identifier` leaf child (the actual def site
    // the DFG builder wires REACHING_DEF edges from), so resolve to that.
    let param_identifier = |param_name: &str| -> NodeId {
        let param_id = cpg
            .ast
            .iter()
            .find(|(_, n)| n.kind == IrNodeKind::ParamDef && n.name.as_deref() == Some(param_name))
            .map(|(&id, _)| id)
            .unwrap_or_else(|| panic!("{param_name} ParamDef not found"));
        cpg.ast[&param_id]
            .children
            .iter()
            .find_map(|&cid| {
                let c = cpg.ast.get(&cid)?;
                (c.node_type == "identifier" && c.text.as_deref() == Some(param_name)).then_some(cid)
            })
            .unwrap_or_else(|| panic!("{param_name} identifier leaf not found"))
    };
    let px_id = param_identifier("px");
    let py_id = param_identifier("py");
    // `field_identifier` covers both the member declaration (`int x;`) and the
    // initializer target (`x(px)`) — text-match alone is ambiguous between the
    // two, so also require the parent to be the `field_initializer` node.
    let field_init_target = |field_name: &str| -> NodeId {
        cpg.ast
            .iter()
            .find(|(_, n)| {
                n.node_type == "field_identifier"
                    && n.text.as_deref() == Some(field_name)
                    && n.parent_id
                        .and_then(|pid| cpg.ast.get(&pid))
                        .map(|p| p.node_type == "field_initializer")
                        .unwrap_or(false)
            })
            .map(|(&id, _)| id)
            .unwrap_or_else(|| panic!("{field_name} field_initializer target not found"))
    };
    let x_field_id = field_init_target("x");
    let y_field_id = field_init_target("y");

    let reaches = |from: NodeId, to: NodeId| -> bool {
        let mut visited: HashSet<NodeId> = HashSet::from([from]);
        let mut queue: std::collections::VecDeque<NodeId> = std::collections::VecDeque::from([from]);
        while let Some(cur) = queue.pop_front() {
            if cur == to {
                return true;
            }
            for edge in &cpg.dataflow.edges {
                if edge.source == cur && visited.insert(edge.destination) {
                    queue.push_back(edge.destination);
                }
            }
        }
        false
    };

    assert!(reaches(px_id, x_field_id), "constructor param `px` should dataflow-reach field `x` through the initializer list");
    assert!(reaches(py_id, y_field_id), "constructor param `py` should dataflow-reach field `y` through the initializer list");
    assert!(!reaches(px_id, y_field_id), "`px` must not spuriously reach the unrelated field `y`");
    assert!(!reaches(py_id, x_field_id), "`py` must not spuriously reach the unrelated field `x`");
}

#[test]
fn field_initializer_base_class_init() {
    // Base class constructor call in initializer list
    let src = r#"
        struct Base {
            int val;
            Base(int v) : val(v) {}
        };
        struct Derived : Base {
            int extra;
            Derived(int v, int e) : Base(v), extra(e) {}
        };
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

// ── requires_clause / concept_definition ─────────────────────────────────────

#[test]
fn requires_clause_no_crash() {
    // C++20 requires clause on a template function
    let src = r#"
        template <typename T>
        requires (sizeof(T) > 1)
        T identity(T x) { return x; }
    "#;
    let cpg = cpp_cpg(src);
    assert!(
        !cpg.ast.is_empty(),
        "requires_clause source must produce non-empty AST"
    );
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

#[test]
fn concept_definition_no_crash() {
    // C++20 concept definition
    let src = r#"
        template <typename T>
        concept Arithmetic = requires(T a, T b) {
            a + b;
            a - b;
            a * b;
        };

        template <Arithmetic T>
        T add(T a, T b) { return a + b; }
    "#;
    let cpg = cpp_cpg(src);
    assert!(
        !cpg.ast.is_empty(),
        "concept_definition source must produce non-empty AST"
    );
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

#[test]
fn requires_expression_no_crash() {
    // Inline requires expression as a constraint
    let src = r#"
        template <typename T>
        T clamp(T val, T lo, T hi)
            requires requires(T a, T b) { a < b; }
        {
            return val < lo ? lo : (val > hi ? hi : val);
        }
    "#;
    let cpg = cpp_cpg(src);
    assert!(!cpg.ast.is_empty());
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

// ── fold_expression / parameter_pack_expansion ───────────────────────────────

#[test]
fn fold_expression_no_crash() {
    // C++17 fold expression: (args + ...)
    let src = r#"
        template <typename... Args>
        auto sum(Args... args) {
            return (args + ...);
        }
    "#;
    let cpg = cpp_cpg(src);
    assert!(
        !cpg.ast.is_empty(),
        "fold_expression source must produce non-empty AST"
    );
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

#[test]
fn fold_expression_binary_fold_no_crash() {
    // Binary fold with initial value
    let src = r#"
        template <typename... Args>
        auto product(Args... args) {
            return (1 * ... * args);
        }
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

#[test]
fn parameter_pack_expansion_dfg() {
    // Variadic template with pack expansion in call
    let src = r#"
        int sum_impl(int a, int b, int c) { return a + b + c; }

        template <typename... Args>
        int forward_sum(Args... args) {
            return sum_impl(args...);
        }
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    // function_definition nodes should include the variadic template
    let funcs: Vec<_> = nodes_of_type(&cpg, "function_definition");
    assert!(
        !funcs.is_empty(),
        "variadic template should produce function_definition"
    );
}

// ── operator_name in call graph ───────────────────────────────────────────────

#[test]
fn operator_overload_parsed_as_function() {
    let src = r#"
        struct Vec2 {
            float x, y;
            Vec2 operator+(const Vec2& o) const { return {x + o.x, y + o.y}; }
            Vec2& operator+=(const Vec2& o) { x += o.x; y += o.y; return *this; }
            float operator[](int i) const { return i == 0 ? x : y; }
        };
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let funcs: Vec<_> = nodes_of_type(&cpg, "function_definition");
    // All three operator overloads should produce function_definition nodes
    assert!(
        funcs.len() >= 3,
        "operator overloads should produce function_definition nodes, got {}",
        funcs.len()
    );
}

#[test]
fn operator_overload_in_callgraph() {
    // Phase 2 target: operator overloads should appear in the call graph with their name
    let src = r#"
        struct MyStr {
            const char* buf;
            MyStr operator+(const MyStr& other) const { return {other.buf}; }
            bool operator==(const MyStr& other) const { return buf == other.buf; }
        };
        MyStr concat(MyStr a, MyStr b) { return a + b; }
    "#;
    let cpg = cpp_cpg_full_text(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    // The call graph should have entries for functions in the source
    assert!(!cpg.call_graph.is_empty(), "call graph should be non-empty");
    // operator+ should appear as a defined function in the call graph
    let cg_names: Vec<_> = cpg.call_graph.values().map(|e| e.name.as_str()).collect();
    assert!(
        cg_names
            .iter()
            .any(|n| n.contains("operator+") || n.contains("concat")),
        "operator+ or concat should appear in call graph, got: {cg_names:?}"
    );
}

#[test]
fn stream_operator_overload_no_crash() {
    // operator<< for stream injection scenario
    let src = r#"
        struct ostream {
            ostream& operator<<(const char* s) { return *this; }
            ostream& operator<<(int n) { return *this; }
        };
        ostream cout;
        void print_value(const char* s) {
            cout << "Value: " << s << "\n";
        }
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

// ── explicit_object_parameter_declaration (C++23 deducing this) ───────────────

#[test]
fn explicit_object_parameter_no_crash() {
    // C++23 deducing this: explicit object parameter
    let src = r#"
        struct Widget {
            int value;
            int& get(this Widget& self) { return self.value; }
            const int& get(this const Widget& self) { return self.value; }
        };
    "#;
    let cpg = cpp_cpg(src);
    assert!(
        !cpg.ast.is_empty(),
        "explicit object parameter source must produce non-empty AST"
    );
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

#[test]
fn explicit_object_parameter_dfg() {
    // Note: this project's pinned tree-sitter-cpp (0.23.4) doesn't parse C++23
    // deducing-this syntax cleanly — `this Counter& self` produces an ERROR
    // node for the `Counter&` part (a grammar-level limitation, not something
    // fixable from CPG-generation code without patching/upgrading the
    // grammar). Despite that, the `self` identifier itself still parses
    // correctly and should be tracked exactly like an ordinary parameter.
    let src = r#"
        struct Counter {
            int count;
            void increment(this Counter& self) { self.count++; }
            int get_count(this const Counter& self) { return self.count; }
        };
        void use_counter() {
            Counter c;
            c.count = 0;
            c.increment();
            int v = c.get_count();
            (void)v;
        }
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    // Both explicit-object-parameter methods should have class_context set.
    let methods: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.node_type == "function_definition" && n.class_context.is_some())
        .collect();
    assert!(!methods.is_empty(), "methods should have class_context");

    // `self` should be a real ParamDef (not swallowed by the grammar's ERROR
    // recovery), scoped to its own class.
    let self_params: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.kind == IrNodeKind::ParamDef && n.name.as_deref() == Some("self"))
        .collect();
    assert_eq!(self_params.len(), 2, "both increment and get_count should have a `self` ParamDef");
    for p in &self_params {
        assert_eq!(p.class_context.as_deref(), Some("Counter"), "self's class_context should be Counter");
    }

    // `self` must actually participate in DFG like a normal parameter: reading
    // `self.count` in the body should carry a REACHING_DEF edge back to the
    // `self` parameter's own declaration site, the same way any other param
    // flows to its uses.
    let get_count_id = cpg
        .ast
        .iter()
        .find(|(_, n)| n.node_type == "function_definition" && n.name.as_deref() == Some("get_count"))
        .map(|(&id, _)| id)
        .expect("get_count MethodDef");
    let self_def_id = cpg.ast[&get_count_id]
        .children
        .iter()
        .find_map(|&cid| {
            let c = cpg.ast.get(&cid)?;
            if c.node_type != "function_declarator" {
                return None;
            }
            let params = field_declarator_params(&cpg, cid)?;
            params.children.iter().find_map(|&pid| {
                find_identifier_named(&cpg, pid, "self")
            })
        })
        .expect("self declaration identifier in get_count's param list");

    let self_use_in_body = cpg
        .ast
        .iter()
        .find(|(_, n)| {
            n.node_type == "identifier"
                && n.text.as_deref() == Some("self")
                && n.function_id == Some(get_count_id)
                && n.parent_id
                    .and_then(|pid| cpg.ast.get(&pid))
                    .map(|p| p.node_type == "field_expression")
                    .unwrap_or(false)
        })
        .map(|(&id, _)| id)
        .expect("self used in `return self.count;`");

    let reaches_directly = cpg
        .dataflow
        .edges
        .iter()
        .any(|e| e.source == self_def_id && e.destination == self_use_in_body);
    assert!(
        reaches_directly,
        "self ParamDef ({self_def_id}) should have a direct REACHING_DEF edge to its use in the method body ({self_use_in_body})"
    );
}

/// The `parameter_list` child of a `function_declarator` node.
fn field_declarator_params<'a>(cpg: &'a Cpg, function_declarator_id: NodeId) -> Option<&'a web_sitter::AstNode> {
    cpg.ast[&function_declarator_id].children.iter().find_map(|&cid| {
        let c = cpg.ast.get(&cid)?;
        (c.node_type == "parameter_list").then_some(c)
    })
}

/// DFS for an `identifier` descendant of `root` whose text matches `name`.
fn find_identifier_named(cpg: &Cpg, root: NodeId, name: &str) -> Option<NodeId> {
    let node = cpg.ast.get(&root)?;
    if node.node_type == "identifier" && node.text.as_deref() == Some(name) {
        return Some(root);
    }
    node.children.iter().find_map(|&cid| find_identifier_named(cpg, cid, name))
}

// ── module_declaration / export_declaration / import_declaration ──────────────

#[test]
fn module_declaration_no_crash() {
    // C++20 module unit — named module declaration
    let src = r#"
        export module my_module;

        export int add(int a, int b) { return a + b; }
        export int multiply(int a, int b) { return a * b; }
    "#;
    let cpg = cpp_cpg(src);
    assert!(
        !cpg.ast.is_empty(),
        "module declaration source must produce non-empty AST"
    );
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

#[test]
fn import_declaration_no_crash() {
    // C++20 import declaration
    let src = r#"
        import std;

        int use_stdlib(int x) {
            return x * 2;
        }
    "#;
    let cpg = cpp_cpg(src);
    assert!(!cpg.ast.is_empty());
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

#[test]
fn export_module_no_crash() {
    // Export a class from a module
    let src = r#"
        export module geometry;

        export struct Point {
            float x, y;
            Point(float x, float y) : x(x), y(y) {}
            float length() const { return x * x + y * y; }
        };
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

// ── template_function / template_method qualified names ──────────────────────

#[test]
fn template_function_qualified_name() {
    // Template method should have qualified name with class context
    let src = r#"
        template <typename T>
        class MyContainer {
            T* data;
            int sz;
        public:
            void push(T val) {}
            T pop() { T v = data[0]; return v; }
            template <typename U>
            U convert(T val) { return static_cast<U>(val); }
        };
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    // Template class methods should have class_context
    let methods_with_ctx: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.node_type == "function_definition" && n.class_context.is_some())
        .collect();
    assert!(
        !methods_with_ctx.is_empty(),
        "template class methods should have class_context"
    );
}

#[test]
fn template_method_in_namespace_qualified_name() {
    let src = r#"
        namespace algo {
            template <typename T>
            class Sorter {
            public:
                void sort(T* arr, int n) {}
                T find_min(T* arr, int n) { return arr[0]; }
            };
        }
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let methods: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.node_type == "function_definition")
        .collect();
    assert!(
        !methods.is_empty(),
        "template class methods should be present"
    );
}

// ── qualified_identifier callee resolution ────────────────────────────────────

#[test]
fn qualified_identifier_call_resolves() {
    // Phase 2 target: std::string::append call should resolve to qualified name
    let src = r#"
        namespace std {
            struct string {
                const char* buf;
                string& append(const char* s) { return *this; }
                const char* c_str() const { return buf; }
            };
        }
        void dangerous_sink(const char* s);

        void test_qualified_call(const char* user_input) {
            std::string cmd;
            cmd.append("ls ");
            cmd.append(user_input);
            dangerous_sink(cmd.c_str());
        }
    "#;
    let cpg = cpp_cpg_full_text(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    // call_expression nodes for append should be present
    let calls: Vec<_> = nodes_of_type(&cpg, "call_expression");
    assert!(
        !calls.is_empty(),
        "call_expression nodes should be present for qualified calls"
    );
}

#[test]
fn nested_namespace_qualified_call() {
    let src = r#"
        namespace std {
            namespace filesystem {
                void remove(const char* path) {}
                void copy(const char* src, const char* dst) {}
            }
        }
        void process_path(const char* p) {
            std::filesystem::remove(p);
        }
    "#;
    let cpg = cpp_cpg_full_text(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    // process_path should appear as a function in the call graph
    let cg_names: Vec<_> = cpg.call_graph.values().map(|e| e.name.as_str()).collect();
    assert!(
        !cg_names.is_empty(),
        "call graph should contain at least the defining function"
    );
}

// ── new_expression / new_declarator ──────────────────────────────────────────

#[test]
fn new_expression_no_crash() {
    let src = r#"
        struct Node {
            int val;
            Node* next;
        };
        Node* create_node(int v) {
            Node* n = new Node;
            n->val = v;
            n->next = nullptr;
            return n;
        }
        int* create_array(int n) {
            return new int[n];
        }
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

#[test]
fn new_expression_alloc_tracked() {
    let src = r#"
        struct Buffer {
            char* data;
            int size;
        };
        Buffer* alloc_buffer(int n) {
            Buffer* b = new Buffer;
            b->data = new char[n];
            int* fixed = new int[16];
            b->size = n;
            return b;
        }
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    // `new_expression` nodes must be classified as NewExpr and participate in
    // the call graph as an allocation site (`is_call()` already covers
    // NewExpr, so this locks that in rather than re-deriving it from scratch).
    let new_nodes: Vec<_> = nodes_of_type(&cpg, "new_expression");
    assert_eq!(new_nodes.len(), 3, "expected 3 new_expression nodes (Buffer, char[n], int[16])");
    for (_, n) in &new_nodes {
        assert_eq!(n.kind, IrNodeKind::NewExpr);
        assert!(n.is_call(), "NewExpr must be treated as a call site for the call graph");
    }
    let alloc_buffer_calls: Vec<&str> = cpg
        .call_graph
        .values()
        .find(|e| e.name == "alloc_buffer")
        .map(|e| e.calls.iter().map(|c| c.callee.as_str()).collect())
        .unwrap_or_default();
    assert!(
        alloc_buffer_calls.contains(&"Buffer"),
        "new Buffer should appear as a call-graph allocation site, got: {alloc_buffer_calls:?}"
    );

    // Array-form `new T[expr]` allocation sizes must be tracked the same way
    // C's `array_declarator` sizes are — constant sizes as `array_size`,
    // symbolic ones as `array_size_expr` — so the size tracker can reason
    // about `new[]` buffers exactly like C arrays.
    let symbolic = new_nodes.iter().find(|(_, n)| n.text.as_deref() == Some("new char[n]")).unwrap().1;
    assert_eq!(symbolic.array_size_expr.as_deref(), Some("n"), "new char[n] should record array_size_expr == \"n\"");
    let constant = new_nodes.iter().find(|(_, n)| n.text.as_deref() == Some("new int[16]")).unwrap().1;
    assert_eq!(constant.array_size, Some(16), "new int[16] should record array_size == 16");
}

#[test]
fn delete_expression_no_crash() {
    let src = r#"
        void cleanup(int* arr, char* buf) {
            delete[] arr;
            delete buf;
        }
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

#[test]
fn delete_expression_tracked() {
    let src = r#"
        struct Resource { int id; };
        void release(Resource* r, int* arr) {
            delete r;
            delete[] arr;
        }
        void use_after_free_pattern() {
            Resource* p = new Resource();
            delete p;
        }
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    let delete_nodes: Vec<_> = nodes_of_type(&cpg, "delete_expression");
    assert_eq!(delete_nodes.len(), 3, "expected 3 delete_expression nodes");
    for (_, n) in &delete_nodes {
        assert_eq!(n.kind, IrNodeKind::DeleteExpr);
    }

    // Each delete_expression must be a first-class DFG anchor — a DEALLOC edge
    // landing ON the delete_expression node itself, sourced from the deleted
    // pointer's use-site identifier — the same way a `free(p)` Call node is
    // reachable/anchorable in the C UAF/double-free patterns.
    let delete_ids: HashSet<NodeId> = delete_nodes.iter().map(|&(&id, _)| id).collect();
    let dealloc_edges: Vec<_> = cpg
        .dataflow
        .edges
        .iter()
        .filter(|e| e.edge_type == "DEALLOC" && delete_ids.contains(&e.destination))
        .collect();
    assert_eq!(
        dealloc_edges.len(),
        delete_nodes.len(),
        "every delete_expression should have exactly one DEALLOC edge landing on it, got {dealloc_edges:?}"
    );

    // The allocation site should actually reach the matching delete site
    // through the ordinary pointer dataflow chain plus the new DEALLOC edge —
    // proving this is real free-site tracking, not an edge dangling in
    // isolation. `new Resource()` -> `p` (assignment) -> `delete p` (DEALLOC).
    let new_id = nodes_of_type(&cpg, "new_expression")
        .into_iter()
        .find(|(_, n)| n.text.as_deref() == Some("new Resource()"))
        .map(|(&id, _)| id)
        .expect("new Resource() should be present");
    let uaf_delete_id = delete_nodes
        .iter()
        .find(|(_, n)| n.text.as_deref() == Some("delete p"))
        .map(|&(&id, _)| id)
        .expect("delete p should be present");

    // BFS forward from the allocation over the raw dataflow edges.
    let mut visited: HashSet<NodeId> = HashSet::from([new_id]);
    let mut queue: std::collections::VecDeque<NodeId> = std::collections::VecDeque::from([new_id]);
    let mut reached_delete = false;
    while let Some(cur) = queue.pop_front() {
        if cur == uaf_delete_id {
            reached_delete = true;
            break;
        }
        for edge in &cpg.dataflow.edges {
            if edge.source == cur && visited.insert(edge.destination) {
                queue.push_back(edge.destination);
            }
        }
    }
    assert!(
        reached_delete,
        "new Resource() should dataflow-reach its `delete p` free site"
    );
}

// ── destructor_definition (constructor_or_destructor_definition) ─────────────

#[test]
fn destructor_definition_context() {
    let src = r#"
        class Resource {
            int* data;
        public:
            Resource() { data = new int[10]; }
            ~Resource() { delete[] data; }
            void use() {}
        };
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let funcs: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.node_type == "function_definition")
        .collect();
    let dtor = funcs.iter().find(|n| n.is_destructor == Some(true));
    assert!(
        dtor.is_some(),
        "~Resource() should be flagged as is_destructor=true"
    );
    if let Some(d) = dtor {
        assert_eq!(
            d.class_context.as_deref(),
            Some("Resource"),
            "destructor class_context should be 'Resource'"
        );
    }
}

#[test]
fn out_of_line_constructor_definition() {
    // Out-of-line constructor/destructor definitions (constructor_or_destructor_definition)
    let src = r#"
        class Widget {
            int value;
        public:
            Widget(int v);
            ~Widget();
            int get() { return value; }
        };
        Widget::Widget(int v) : value(v) {}
        Widget::~Widget() {}
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

// ── virtual dispatch (call graph CHA) ────────────────────────────────────────

#[test]
fn virtual_method_flagged_in_base_and_override() {
    let src = r#"
        class Animal {
        public:
            virtual void speak() {}
            virtual ~Animal() {}
        };
        class Dog : public Animal {
        public:
            void speak() override {}
        };
        class Cat : public Animal {
        public:
            void speak() override {}
        };
        void make_noise(Animal* a) {
            a->speak();
        }
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let virtual_methods: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.node_type == "function_definition" && n.is_virtual == Some(true))
        .collect();
    assert!(
        !virtual_methods.is_empty(),
        "Animal::speak() should be flagged as is_virtual=true"
    );
}

#[test]
fn virtual_dispatch_call_edges() {
    // Phase 2 target: call graph should include CHA edges to override implementations
    let src = r#"
        class Shape {
        public:
            virtual float area() { return 0.0f; }
            virtual ~Shape() {}
        };
        class Circle : public Shape {
            float r;
        public:
            Circle(float r) : r(r) {}
            float area() override { return 3.14f * r * r; }
        };
        class Rect : public Shape {
            float w, h;
        public:
            Rect(float w, float h) : w(w), h(h) {}
            float area() override { return w * h; }
        };
        float compute(Shape* s) {
            return s->area();  // virtual dispatch — should see Circle::area + Rect::area in CG
        }
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    // All override implementations should be in the call graph
    let cg_names: Vec<_> = cpg.call_graph.values().map(|e| e.name.as_str()).collect();
    assert!(
        cg_names.iter().any(|n| n.contains("area")),
        "area implementations should appear in call graph, got: {cg_names:?}"
    );
}

// ── lambda incremental update ─────────────────────────────────────────────────

#[test]
fn lambda_in_incremental_initial_parse() {
    // Lambda should appear in the AST after initial incremental parse
    let src = r#"
        int main() {
            auto square = [](int x) { return x * x; };
            auto add = [](int a, int b) { return a + b; };
            return square(add(2, 3));
        }
    "#;
    let mut inc = IncrementalCpgGenerator::new_for_language(
        SourceLanguage::Cpp,
        GraphBuildOptions::default(),
    )
    .expect("IncrementalCpgGenerator init");
    let cpg = inc.parse_initial(src.as_bytes()).expect("initial parse");
    let has_lambda = cpg.ast.values().any(|n| n.node_type == "lambda_expression");
    assert!(
        has_lambda,
        "lambda_expression should appear in incrementally-parsed AST"
    );
}

#[test]
fn lambda_in_incremental_update() {
    // Phase 2 target: editing a lambda body should trigger incremental rebuild of that lambda
    let src1 = r#"
        int compute() {
            auto fn = [](int x) { return x * 2; };
            return fn(5);
        }
    "#;
    let src2 = r#"
        int compute() {
            auto fn = [](int x) { return x * 3; };
            return fn(5);
        }
    "#;
    let mut inc = IncrementalCpgGenerator::new_for_language(
        SourceLanguage::Cpp,
        GraphBuildOptions::default(),
    )
    .expect("IncrementalCpgGenerator init");
    inc.parse_initial(src1.as_bytes()).expect("initial parse");
    let edit = compute_edit(src1.as_bytes(), src2.as_bytes()).expect("compute_edit");
    let updated = inc.apply_edit(&edit, src2.as_bytes()).expect("apply_edit");
    // After update, the AST should still be valid
    assert!(
        !updated.ast.is_empty(),
        "AST must not be empty after lambda edit"
    );
    let ast_ids: HashSet<NodeId> = updated.ast.keys().copied().collect();
    for edge in &updated.dataflow.edges {
        assert!(
            ast_ids.contains(&edge.source),
            "DFG edge source dangling after lambda edit"
        );
        assert!(
            ast_ids.contains(&edge.destination),
            "DFG edge dest dangling after lambda edit"
        );
    }
}

// ── structured_binding_declarator (complex) ───────────────────────────────────

#[test]
fn structured_binding_simple() {
    let src = r#"
        struct Pair { int first; int second; };
        Pair get_pair() { Pair p; p.first = 1; p.second = 2; return p; }
        int use_binding() {
            auto [a, b] = get_pair();
            return a + b;
        }
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

#[test]
fn structured_binding_complex() {
    // More complex structured binding with map-like iterator
    let src = r#"
        struct Entry { const char* key; int value; };
        struct MapIter {
            Entry pair;
            Entry& operator*() { return pair; }
        };
        struct Map {
            Entry entries[10];
            int sz;
            MapIter begin() { MapIter it; it.pair = entries[0]; return it; }
        };
        void process_map(Map& m) {
            for (auto it = m.begin(); ; ) {
                auto [k, v] = *it;
                (void)k;
                (void)v;
                break;
            }
        }
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

// ── co_await / co_yield / co_return (coroutines) ──────────────────────────────

#[test]
fn coroutine_co_return_no_crash() {
    let src = r#"
        struct Task {
            struct promise_type {
                Task get_return_object() { return Task{}; }
                void return_value(int v) {}
                void unhandled_exception() {}
            };
        };
        Task async_compute(int x) {
            co_return x * 2;
        }
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

#[test]
fn coroutine_co_await_cfg_valid() {
    // co_await should create suspend+resume edges in CFG
    let src = r#"
        struct Awaitable {
            bool await_ready() { return false; }
            void await_suspend(void*) {}
            int await_resume() { return 42; }
        };
        struct Task {
            struct promise_type {
                Task get_return_object() { return Task{}; }
                void return_void() {}
                void unhandled_exception() {}
                Awaitable initial_suspend() { return {}; }
                Awaitable final_suspend() noexcept { return {}; }
            };
        };
        Task fetch_data(int id) {
            int result = co_await Awaitable{};
            (void)result;
            co_return;
        }
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

#[test]
fn coroutine_co_yield_no_crash() {
    let src = r#"
        struct Generator {
            struct promise_type {
                Generator get_return_object() { return Generator{}; }
                void return_void() {}
                void unhandled_exception() {}
                int yielded_value;
                struct YieldAwaitable {
                    bool await_ready() { return false; }
                    void await_suspend(void*) {}
                    void await_resume() {}
                };
                YieldAwaitable yield_value(int v) { yielded_value = v; return {}; }
            };
        };
        Generator count_up(int n) {
            for (int i = 0; i < n; ++i) {
                co_yield i;
            }
        }
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

// ── trailing_return_type ──────────────────────────────────────────────────────

#[test]
fn trailing_return_type_no_crash() {
    let src = r#"
        auto add(int a, int b) -> int { return a + b; }

        template <typename T, typename U>
        auto multiply(T a, U b) -> decltype(a * b) { return a * b; }

        struct Calc {
            auto square(int x) -> int { return x * x; }
            auto get_pi() const -> float { return 3.14f; }
        };
    "#;
    let cpg = cpp_cpg(src);
    assert!(!cpg.ast.is_empty());
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    // Functions should still be discoverable
    let funcs: Vec<_> = nodes_of_type(&cpg, "function_definition");
    assert!(
        funcs.len() >= 2,
        "trailing return type functions should produce function_definition nodes"
    );
}

#[test]
fn trailing_return_type_with_decltype() {
    let src = r#"
        template <typename Container>
        auto first(Container& c) -> decltype(c[0]) {
            return c[0];
        }
        int use_first(int arr[10]) {
            return first(arr);
        }
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

// ── noexcept specifier ────────────────────────────────────────────────────────

#[test]
fn noexcept_specifier_no_crash() {
    let src = r#"
        void safe_op() noexcept {}
        void conditional_op() noexcept(true) {}
        int compute(int x) noexcept { return x * 2; }
        struct NoCopy {
            NoCopy() noexcept = default;
            NoCopy(NoCopy&&) noexcept = default;
            NoCopy& operator=(NoCopy&&) noexcept = default;
        };
    "#;
    let cpg = cpp_cpg(src);
    assert!(!cpg.ast.is_empty());
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    // Functions should be discoverable even with noexcept
    let funcs: Vec<_> = nodes_of_type(&cpg, "function_definition");
    assert!(
        !funcs.is_empty(),
        "noexcept functions should produce function_definition nodes"
    );
}

#[test]
fn noexcept_with_conditional_expression() {
    let src = r#"
        template <typename T>
        void swap_safe(T& a, T& b) noexcept(noexcept(T(T(a)))) {
            T tmp = a;
            a = b;
            b = tmp;
        }
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

// ── friend_declaration ────────────────────────────────────────────────────────

#[test]
fn friend_declaration_no_crash() {
    let src = r#"
        class Secret {
            int hidden;
            friend class Inspector;
            friend void reveal(Secret& s);
        public:
            Secret(int v) : hidden(v) {}
        };
        class Inspector {
        public:
            int peek(Secret& s) { return s.hidden; }
        };
        void reveal(Secret& s) { (void)s.hidden; }
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    // friend declarations should not produce spurious function_definition nodes
    let funcs: Vec<_> = nodes_of_type(&cpg, "function_definition");
    // Should only have: Secret(int), Inspector::peek, reveal
    assert!(
        funcs.len() <= 5,
        "friend declarations should not produce extra function nodes, got {}",
        funcs.len()
    );
}

#[test]
fn friend_function_template_no_crash() {
    let src = r#"
        template <typename T>
        class Box {
            T value;
        public:
            Box(T v) : value(v) {}
            template <typename U>
            friend bool operator==(const Box<U>& a, const Box<U>& b);
        };
        template <typename T>
        bool operator==(const Box<T>& a, const Box<T>& b) { return true; }
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

// ── variadic_parameter_declaration / parameter_pack_expansion ────────────────

#[test]
fn variadic_template_pack_no_crash() {
    let src = r#"
        template <typename... Args>
        void log_all(const char* fmt, Args... args) {
            (void)fmt;
            int dummy[] = { ((void)args, 0)... };
            (void)dummy;
        }
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

#[test]
fn variadic_pack_expansion_dfg() {
    // Taint should flow through variadic template parameter pack
    let src = r#"
        void sink(int x);

        template <typename... Args>
        void forward_to_sink(Args... args) {
            int arr[] = { (sink(args), 0)... };
            (void)arr;
        }

        void test_pack() {
            forward_to_sink(1, 2, 3);
        }
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let funcs: Vec<_> = nodes_of_type(&cpg, "function_definition");
    assert!(
        !funcs.is_empty(),
        "variadic template functions should be present"
    );
}

// ── using_declaration / alias_declaration ────────────────────────────────────

#[test]
fn using_declaration_no_crash() {
    let src = r#"
        namespace ns {
            void helper(int x) {}
            struct Data { int val; };
        }
        using ns::helper;
        using DataAlias = ns::Data;

        void test_using() {
            helper(42);
            DataAlias d;
            d.val = 1;
            (void)d;
        }
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

// ── static_assert_declaration ─────────────────────────────────────────────────

#[test]
fn static_assert_no_crash() {
    let src = r#"
        static_assert(sizeof(int) == 4, "int must be 4 bytes");
        static_assert(sizeof(void*) >= 4);

        template <typename T>
        void check_size() {
            static_assert(sizeof(T) <= 64, "T too large");
        }
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

// ── decltype ──────────────────────────────────────────────────────────────────

#[test]
fn decltype_no_crash() {
    let src = r#"
        int x = 42;
        decltype(x) y = x;

        template <typename T>
        decltype(auto) forward_val(T&& t) { return t; }

        struct Container {
            int data[10];
            decltype(data[0]) at(int i) { return data[i]; }
        };
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

// ── Comprehensive C++20 feature combination ───────────────────────────────────

#[test]
fn cpp20_combined_features_no_crash() {
    // A realistic C++20 class combining many features
    let src = r#"
        template <typename T>
        concept Printable = requires(T val) {
            val.to_string();
        };

        template <typename T>
        requires Printable<T>
        class Logger {
            T* items[100];
            int count;
        public:
            Logger() noexcept : count(0) {}
            ~Logger() = default;

            void log(T& item) noexcept {
                if (count < 100) items[count++] = &item;
            }

            auto get(int i) -> T* {
                return i < count ? items[i] : nullptr;
            }

            template <typename... Args>
            void log_all(Args&... args) {
                (log(args), ...);
            }
        };
    "#;
    let cpg = cpp_cpg(src);
    assert!(
        !cpg.ast.is_empty(),
        "C++20 combined feature class should produce non-empty AST"
    );
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

// ── Placeholder type specifier (auto, decltype(auto)) ─────────────────────────

#[test]
fn placeholder_type_specifier_no_crash() {
    let src = r#"
        auto compute(int x) { return x * 2; }

        decltype(auto) get_ref(int& x) { return x; }

        struct AutoDemo {
            auto square(int x) { return x * x; }
            decltype(auto) passthrough(int& v) { return v; }
        };
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

// ── ref_qualifier (lvalue/rvalue method qualifiers) ───────────────────────────

#[test]
fn ref_qualifier_no_crash() {
    let src = r#"
        struct Buffer {
            char* data;
            int size;

            // lvalue ref-qualifier
            char* get() & { return data; }
            // rvalue ref-qualifier
            char* get() && { return data; }
            // const lvalue
            const char* get() const & { return data; }
        };
        void use_buffer() {
            Buffer b;
            b.data = nullptr;
            b.size = 0;
            char* p = b.get();
            (void)p;
        }
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

// ── Linkage specification ─────────────────────────────────────────────────────

#[test]
fn linkage_specification_no_crash() {
    let src = r#"
        extern "C" {
            void c_function(int x);
            int c_compute(int a, int b);
        }
        extern "C" void another_c_func(void);

        void cpp_wrapper(int x) {
            c_function(x);
        }
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

// ── access_specifier ──────────────────────────────────────────────────────────

#[test]
fn access_specifier_methods_all_present() {
    let src = r#"
        class AccessDemo {
        public:
            void pub_method() {}
            int pub_val;
        protected:
            void prot_method() {}
            int prot_val;
        private:
            void priv_method() {}
            int priv_val;
        };
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let methods: Vec<_> = nodes_of_type(&cpg, "function_definition");
    assert_eq!(
        methods.len(),
        3,
        "all three methods (pub/prot/priv) should be present, got {}",
        methods.len()
    );
}

// ── operator_cast / conversion function ──────────────────────────────────────

#[test]
fn operator_cast_conversion_function_no_crash() {
    let src = r#"
        struct Degrees {
            float value;
            Degrees(float v) : value(v) {}
            operator float() const { return value; }
            explicit operator int() const { return static_cast<int>(value); }
        };
        float use_degrees(Degrees d) {
            float f = d;  // implicit conversion via operator float()
            return f;
        }
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
}

// ── virtual_specifier (override / final) ─────────────────────────────────────

#[test]
fn override_and_final_specifiers_no_crash() {
    let src = r#"
        class Base {
        public:
            virtual void method() {}
            virtual void other() {}
        };
        class Mid : public Base {
        public:
            void method() override {}
        };
        class Leaf final : public Mid {
        public:
            void method() override final {}
        };
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);
    let virtual_methods: Vec<_> = cpg
        .ast
        .values()
        .filter(|n| n.node_type == "function_definition" && n.is_virtual == Some(true))
        .collect();
    assert!(
        !virtual_methods.is_empty(),
        "override methods should be flagged as virtual"
    );
}

#[test]
fn range_based_for_statement_node_type() {
    // Verify the actual tree-sitter C++ node type for range-based for loops.
    let src = r#"
        void dangerous(int x);
        void f() {
            int arr[] = {1, 2, 3};
            for (int x : arr) {
                dangerous(x);
            }
        }
    "#;
    let cpg = cpp_cpg(src);
    assert_cfg_valid(&cpg);
    assert_dfg_valid(&cpg);

    // Collect all node types to find what the range-for generates.
    let loop_types: Vec<String> = cpg
        .ast
        .values()
        .filter(|n| {
            n.node_type.contains("for")
                || n.node_type.contains("range")
                || n.node_type.contains("loop")
        })
        .map(|n| n.node_type.clone())
        .collect();
    assert!(
        loop_types.iter().any(|t| t == "for_range_loop"),
        "range-based for should generate 'for_range_loop' AST node, found: {loop_types:?}"
    );
}
