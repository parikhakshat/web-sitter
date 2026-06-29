# web-ql Language Reference

**web-ql** (internally *ScuzzQL*) is a declarative query language for analyzing [Code Property Graphs](graph_schema.md) produced by [web-sitter](ir.md). Rules are written in `.wql` files, compiled to a typed query plan, and evaluated against AST, control-flow (CFG), data-flow (DFG), and taint layers of a CPG.

web-ql is designed for security rules, static-analysis checks, and custom program queries that need structural matching, interprocedural data flow, and taint tracking in one language.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Compilation Pipeline](#compilation-pipeline)
3. [Lexical Structure](#lexical-structure)
4. [File Structure](#file-structure)
5. [Rules](#rules)
6. [Search Queries](#search-queries)
7. [Type System](#type-system)
8. [Expressions](#expressions)
9. [Node Methods](#node-methods)
10. [CFG Predicates](#cfg-predicates)
11. [DFG Predicates](#dfg-predicates)
12. [Pattern Matching](#pattern-matching)
13. [User-Defined Predicates](#user-defined-predicates)
14. [Taint Analysis](#taint-analysis)
15. [Endpoint Definitions](#endpoint-definitions)
16. [Built-in Security Endpoints](#built-in-security-endpoints)
17. [Evaluation Model](#evaluation-model)
18. [Workspace Scanning](#workspace-scanning)
19. [Findings](#findings)
20. [CLI: web-scan](#cli-web-scan)
21. [Best Practices](#best-practices)
22. [Grammar Summary](#grammar-summary)

---

## Quick Start

A minimal structural rule finds dangerous calls by name:

```wql
rule "dangerous-eval" {
    severity: high
    languages: [javascript, python]
    message: "Use of eval()"
    tags: ["cwe-95"]
    find n: Call where n.callee_name() == "eval"
}
```

A taint rule connects user input to a dangerous sink:

```wql
source py_input = find n: Call where
    n.callee_name() in ["input", "request.args.get"]

sink py_exec = find n: Call where
    n.callee_name() in ["os.system", "subprocess.run"]

rule "command-injection" {
    severity: critical
    languages: [python]
    message: "User input reaches command execution"
    taint {
        sources: ["py_input"]
        sinks:   ["py_exec"]
    }
}
```

Compile and evaluate from Rust:

```rust
use web_ql::{compile_rules, Workspace, builtin_endpoint_registry};

let rule_set = compile_rules(include_str!("rules.wql"))?;
let mut ws = Workspace::new(builtin_endpoint_registry());
// ws.upsert_file(path, cpg, content_hash);
ws.build_cross_file_edges();
let findings = ws.scan(&rule_set);
```

Or scan a repository from the command line:

```sh
cargo run -p web-scan -- scan web-ql-queries/python --repo /path/to/project
```

---

## Compilation Pipeline

Every `.wql` file passes through four stages:

```
Source text
    │
    ▼
Lexer (logos)          →  Token stream + spans
    │
    ▼
Parser                 →  AST (RuleFile)
    │
    ▼
Planner (type-check)   →  QueryPlan + RuleSet
    │
    ▼
Engine / TaintEngine   →  Vec<Finding>
```

| Stage | Crate module | Output |
|---|---|---|
| Lex | `web_ql::lexer` | `SpannedToken` |
| Parse | `web_ql::parser::parse_rule_file` | `ast::RuleFile` |
| Plan | `web_ql::planner::Planner` | `ir::RuleSet` |
| Evaluate | `web_ql::engine::RuleRunner` | `finding::Finding` |

`compile_rules(source)` runs parse + plan and returns a `RuleSet` ready for evaluation. Planning performs method validity checks (e.g. `arg()` only on `Call` bindings) and lowers relational methods (`dfg_reaches`, `dominates`, …) into CFG/DFG plan nodes.

---

## Lexical Structure

### Comments

```wql
// Line comment

/* Block comment */
```

Comments are stripped during lexing and do not appear in the token stream.

### Identifiers and Keywords

Identifiers match `[a-zA-Z_][a-zA-Z0-9_]*`. Keywords are reserved and cannot be used as binding names.

| Category | Keywords |
|---|---|
| Top-level | `rule`, `pred`, `source`, `sink`, `sanitizer`, `propagator` |
| Clauses | `find`, `where`, `taint` |
| Logic | `and`, `or`, `not`, `let`, `in`, `matches` |
| Quantifiers | `exists`, `forall` |
| Taint keys | `sources`, `sinks`, `sanitizers`, `propagators`, `require_interprocedural`, `require_same_function`, `max_call_depth` |
| Rule metadata | `severity`, `languages`, `tags`, `message` |
| Severity values | `critical`, `high`, `medium`, `low`, `info` |
| Propagator body | `pattern`, `from`, `to` |
| Type names | `Node`, `Expr`, `Stmt`, `Decl`, `Call`, `MethodDef`, … (see [Type System](#type-system)) |
| Literals | `true`, `false`, `null` |

### Literals

| Form | Example | Notes |
|---|---|---|
| String | `"hello"` | Supports `\"`, `\\`, `\n`, `\t`, `\r` |
| Integer | `42` | Signed 64-bit |
| Float | `3.14`, `1e-3` | |
| Boolean | `true`, `false` | |
| Null | `null` | |
| Regex | `/eval\(/i` | Delimited `/…/flags`; flags: `gimsuy` |
| List | `["a", "b", "c"]` | Homogeneous literal lists |

### String Matching

String comparisons support glob-style wildcards in string literals:

| Pattern | Meaning |
|---|---|
| `"exec"` | Exact match |
| `"subprocess.*"` | Prefix match (`subprocess.` + anything) |
| `"*system"` | Suffix match |
| `"*query*"` | Contains match |

Regex literals (`/pattern/flags`) use full Rust regex semantics.

---

## File Structure

A `.wql` file is a sequence of top-level items. Order matters only for name resolution: predicates and endpoints must be defined before use.

```ebnf
file        ::= item*
item        ::= rule | predicate | source | sink | sanitizer | propagator
```

Multiple items can appear in one file. An empty file (or comment-only file) is valid.

---

## Rules

### Syntax

```wql
rule "<id>" {
    [severity: <level>]
    [languages: [<lang>, ...]]
    [tags: ["<tag>", ...]]
    [message: "<text>"]
    [<clause> ...]
}
```

- **`<id>`** — Stable rule identifier (string literal). Used in findings and caching.
- **Clauses** — One or more `find` (search) or `taint` clauses. A rule matches when **any** clause matches (disjunction).
- **Metadata** — All metadata fields are optional. Unspecified `severity` defaults to `info` in output.

### Severity

```wql
severity: critical | high | medium | low | info
```

### Language Filter

When `languages` is set, the rule is skipped for CPGs whose `SourceLanguage` is not listed:

```wql
languages: [c, cpp, go, java, python, javascript, typescript, rust]
```

Omit `languages` to apply the rule to all supported languages.

### Tags and Message

```wql
tags: ["cwe-78", "injection", "security"]
message: "OS command injection: tainted input reaches shell execution"
```

`message` is emitted on every finding. `tags` are attached verbatim for downstream filtering (SARIF, dashboards, etc.).

---

## Search Queries

Search clauses perform structural and relational matching over CPG nodes.

### Syntax

```wql
find <binding>[, <binding> ...] where <expr>
```

Each binding introduces a typed variable ranging over AST nodes of the given type:

```wql
find n: Call where n.callee_name() == "exec"

find a: Call, b: Call where
    a.callee_name() == "read"
    and b.callee_name() == "write"
    and a.dfg_reaches(b)
```

Bindings are enumerated as a Cartesian product: for two bindings, every pair of matching-type nodes is considered, then the `where` expression filters the combination.

### Binding Types

Each binding `: Type` restricts candidates to nodes whose `IrNodeKind` is a member of that type alias. See [Type System](#type-system).

---

## Type System

### Supersets

| Type | Covers |
|---|---|
| `Node` | Every `IrNodeKind` in the IR |
| `Expr` | Expression nodes (calls, literals, operators, …) |
| `Stmt` | Statement nodes (blocks, loops, returns, …) |
| `Decl` | Declaration nodes (params, locals, methods, classes, …) |

### Concrete Types

| Type | `IrNodeKind` |
|---|---|
| `Call` | `Call` |
| `MethodDef` | `MethodDef` |
| `ClassDef` | `ClassDef` |
| `Identifier` | `Identifier` |
| `Literal` | `Literal` |
| `Assign` | `Assign` |
| `BinaryOp` | `BinaryOp` |
| `Return` | `Return` |
| `Loop` | `Loop` |
| `Conditional` | `Conditional` |
| `Block` | `Block` |
| `Try` | `Try` |
| `Catch` | `Catch` |
| `ParamDef` | `ParamDef` |
| `LocalDef` | `LocalDef` |
| `FieldDef` | `FieldDef` |
| `MemberAccess` | `MemberAccess` |
| `Subscript` | `Subscript` |
| `Cast` | `Cast` |
| `GoStmt` | `GoStmt` |
| `DeferStmt` | `DeferStmt` |
| `MatchExpr` | `MatchExpr` |
| `Comprehension` | `Comprehension` |
| `Await` | `Await` |
| `Yield` | `Yield` |
| `UnsafeBlock` | `UnsafeBlock` |
| `ImplBlock` | `ImplBlock` |

### Escape Hatches

```wql
find n: NodeType("call_expression") where n.raw_kind == "call_expression"
```

`NodeType("…")` matches the raw tree-sitter kind string stored in `IrNode::node_type`, bypassing the `IrNodeKind` taxonomy. Useful for language-specific grammar nodes not yet mapped to a dedicated type alias.

---

## Expressions

### Operator Precedence

From lowest to highest binding strength:

| Precedence | Operators / forms |
|---|---|
| 1 | `or` |
| 2 | `and` |
| 3 | `not` |
| 4 | `let … in …` |
| 5 | Comparisons: `==`, `!=`, `<`, `>`, `<=`, `>=`, `in`, `matches` |
| 6 | Method chains: `expr.method(args).field` |
| 7 | Primary: literals, identifiers, `(…)`, `exists(…)`, `forall(…)`, predicate calls |

Use parentheses to override precedence:

```wql
find n: Call where
    (n.callee_name() == "foo" or n.callee_name() == "bar")
    and n.line > 10
```

### Comparisons

```wql
n.name == "exec"
n.line > 42
n.callee_name() != "safe"
n.callee_name() in ["read", "recv", "fgets"]
n.callee_name() in /^(system|popen)$/
```

The `in` operator accepts a literal list or a regex literal on the right-hand side.

### Quantifiers

```wql
exists(p: ParamDef | p.has_ancestor(n.function_id()))
forall(c: Call | c.callee_name() != "free")
```

Syntax: `exists(var: Type | body)` and `forall(var: Type | body)`.

The quantified variable is in scope only within `body`. Nested quantifiers are supported.

### Let Bindings

Bind an intermediate node derived from a method chain:

```wql
find n: Call where
    let arg = n.arg(0) in arg.dfg_reaches(sink)
```

- Syntax: `let <var> = <method_chain> in <expr>`
- The RHS of `=` must be a method chain (no comparison operators).
- If the binding evaluates to a non-node value, the enclosing predicate is false.

### Predicate Calls

```wql
find n: Call where is_dangerous(n)
```

User-defined predicates are invoked as functions. See [User-Defined Predicates](#user-defined-predicates).

---

## Node Methods

Methods are called on bound node variables: `n.method()` or `n.method(arg)`.

Field-style access (`n.name`) is equivalent to zero-argument method call (`n.name()`).

### Universal Methods

Available on any node binding:

| Method | Returns | Description |
|---|---|---|
| `id()` | node | The node's `NodeId` |
| `name()` | string \| null | Short name (`IrNode::name`) |
| `text()` | string \| null | Source text span |
| `raw_kind()` | string | Original tree-sitter kind |
| `line()`, `end_line()` | int | 1-based source line range |
| `file()` | string \| null | Source file path |
| `namespace()` | string \| null | Enclosing namespace |
| `class_context()` | string \| null | Enclosing class name |
| `function_id()` | node \| null | Enclosing function `MethodDef` node |
| `basic_block()` | int \| null | CFG basic-block index |
| `parent()` | node \| null | Immediate AST parent |
| `child(i)` | node \| null | *i*-th child (0-based) |
| `children()` | node \| null | First child |
| `ancestor(ty?)` | node \| null | Walk up; optional type filter string |
| `has_ancestor(ty?)` | bool | Whether an ancestor exists |
| `descendant(ty?)` | node \| null | BFS first descendant |
| `has_descendant(ty?)` | bool | Whether a descendant exists |
| `is_some()` | bool | Always `true` when node is valid |
| `is_none()` | bool | Always `false` when node is valid |
| `cpp_meta()`, `go_meta()`, … | null | Reserved for per-language metadata |

### Call Methods

| Method | Returns | Description |
|---|---|---|
| `callee_name()` | string | Unqualified callee name |
| `qualified_callee()` | string | Fully-qualified callee when available |
| `callee_kind()` | string | `internal`, `workspace_local`, `external_decl`, `library`, or `unknown` |
| `arg(i)` | node | *i*-th argument expression |
| `arg_count()` | int | Number of arguments |
| `has_arg(node)` | bool | Whether `node` is a direct argument |
| `receiver()` | node \| null | Implicit receiver (first child) |
| `return_value()` | node | The call node itself as value expression |
| `refers_to()` | node \| null | Resolved callee declaration |

### MethodDef Methods

| Method | Returns | Description |
|---|---|---|
| `is_constructor()`, `is_destructor()`, `is_virtual()` | bool | C++ / OOP flags |
| `visibility()` | string \| null | Access modifier |
| `param(i)`, `param_count()` | node / int | Parameter definitions |
| `return_type()` | string \| null | Return type signature text |

### Literal Methods

| Method | Returns | Description |
|---|---|---|
| `lit_kind()` | string | `String`, `Int`, `Float`, `Bool`, `Char`, `Null`, `Template`, … |
| `string_value()` | string \| null | Decoded string content |
| `int_value()` | int \| null | Parsed integer from text |

### ClassDef Methods

| Method | Returns | Description |
|---|---|---|
| `base_classes()` | string \| null | First base class / interface name |
| `implements()` | string \| null | First implemented interface |

### Identifier Methods

| Method | Returns | Description |
|---|---|---|
| `refers_to()` | node \| null | Resolved declaration node |

---

## CFG Predicates

Relational methods that consult the control-flow graph. Both operands must be bound node variables in scope.

| Method | Meaning |
|---|---|
| `a.dominates(b)` | Every path from function entry to `b` passes through `a` |
| `a.post_dominates(b)` | Every path from `b` to function exit passes through `a` |
| `a.same_block(b)` | `a` and `b` are in the same basic block |
| `a.cfg_reaches(b)` | There is a control-flow path from `a` to `b` |
| `a.cfg_reaches_without(b, barrier)` | Path from `a` to `b` that does not pass through `barrier` |
| `n.in_loop()` | `n` is inside a loop body (back-edge detection) |
| `n.loop_has_no_exit()` | `n` is in a loop SCC with no exit to outside |
| `n.in_exception_path()` | `n` is on an exception-handling path |
| `a.same_function(b)` | `a` and `b` share the same `function_id` |

Example — guard dominates dangerous call:

```wql
find guard: Conditional, sink: Call where
    guard.same_function(sink)
    and guard.dominates(sink)
    and sink.callee_name() == "system"
```

---

## DFG Predicates

Relational methods over the data-flow graph.

| Method | Meaning |
|---|---|
| `a.dfg_flows_to(b)` | Direct DFG edge from `a` to `b` |
| `a.dfg_reaches(b)` | Transitive data-flow reachability |
| `n.dfg_def("x")` | `n` is a definition site for variable `x` |
| `n.dfg_use("x")` | `n` is a use site for variable `x` |

Example — tainted argument reaches sink:

```wql
find src: Call, sink: Call where
    src.callee_name() == "read"
    and sink.callee_name() == "write"
    and src.dfg_reaches(sink)
```

---

## Pattern Matching

Structural patterns match node fields inline:

```wql
find n: Call where
    n.arg(0) matches Literal { lit_kind: "String" }

find n: Call where
    not n.arg(1) matches Literal { lit_kind: "Bool" }
```

Syntax: `<expr> matches <Type> { <field>: <constraint>, ... }`

- `<Type>` is a type expression (`Literal`, `Call`, …).
- Field constraints are equality comparisons against `IrNode` fields: `name`, `text`, `raw_kind`, `lit_kind`, `namespace`, `visibility`, `line`, `end_line`.
- The left-hand side is typically a method chain (`n.arg(0)`); variable references are also supported.

---

## User-Defined Predicates

Reusable boolean expressions over typed parameters:

```wql
pred is_shell_exec(n: Call) {
    n.callee_name() in ["system", "popen", "execv"]
}

pred has_string_arg(n: Call) =
    exists(a: Literal | a.has_ancestor(n.id()) and a.lit_kind() == "String")

rule "shell-with-literal" {
    find n: Call where is_shell_exec(n) and not has_string_arg(n)
}
```

### Syntax

```wql
pred <name>(<param>: <Type>, ...) { <expr> }
pred <name>(<param>: <Type>, ...) = <expr>
```

Predicate bodies are full expressions (including quantifiers and `let`). Predicates are compiled once and inlined at call sites during planning.

---

## Taint Analysis

Taint clauses perform interprocedural source-to-sink reachability analysis with sanitizer and propagator support.

### Syntax

```wql
taint {
    sources:      [<endpoint>, ...]
    sinks:        [<endpoint>, ...]
    [sanitizers: [<endpoint>, ...]]
    [propagators: [<endpoint>, ...]]
    [require_interprocedural: true | false]
    [require_same_function: true | false]
    [max_call_depth: <n>]
}
```

### Endpoint References

Each entry in `sources`, `sinks`, `sanitizers`, or `propagators` is a named reference:

```wql
sources: ["c.io_sources", py_user_input]
sinks:   ["c.exec_ops", sql_exec(param)]
```

- **String form** — `"c.io_sources"` or bare `c.io_sources` (equivalent).
- **Parameterized form** — `name(arg1, arg2)` for endpoints that accept arguments (reserved for future use; most builtins ignore args).

### Options

| Key | Default | Description |
|---|---|---|
| `require_interprocedural` | `true` | Follow calls across function boundaries via `FunctionSummary` |
| `max_call_depth` | `10` | Maximum call-stack depth for interprocedural expansion |
| `require_same_function` | `false` | Restrict taint paths to a single function |

### How Taint Works

1. **Resolve endpoints** — Named sources/sinks/sanitizers are looked up in the `EndpointRegistry`. Custom `source`/`sink`/`sanitizer` definitions in the same file are evaluated as search plans. Built-in sets from `security_patterns` are pre-registered.
2. **Seed** — All source nodes are marked tainted.
3. **Propagate** — Taint flows along DFG edges, call-return edges, and registered propagators (e.g. `memcpy` arg0 → arg1).
4. **Sanitize** — Nodes matching sanitizer definitions block taint propagation through them.
5. **Report** — For each reachable source→sink pair, emit a finding with the taint path.

Cross-file taint requires `Workspace::build_cross_file_edges()` before scanning.

### Example

```wql
source py_user_input = find n: Call where
    n.callee_name() in ["input", "request.args.get"]

sink py_exec_sinks = find n: Call where
    n.callee_name() in ["os.system", "subprocess.run"]

sanitizer py_shell_false = find n: Call where
    n.callee_name() in ["subprocess.run", "subprocess.Popen"]
    and n.arg(1) matches Literal { lit_kind: "Bool" }

rule "cwe-78-python-command-injection" {
    severity: critical
    languages: [python]
    message: "OS command injection: user input reaches shell execution"
    tags: ["command-injection", "cwe-78"]
    taint {
        sources: ["py_user_input"]
        sinks:   ["py_exec_sinks"]
        sanitizers: ["py_shell_false"]
        require_interprocedural: true
        max_call_depth: 5
    }
}
```

---

## Endpoint Definitions

Define reusable taint endpoints with search queries.

### Source

```wql
source <name> = find <bindings> where <expr>

// Shorthand attribute block:
source <name> { kind: Call, name: "input" }

// Alternatives (OR):
source <name> =
    find n: Call where n.callee_name() == "read"
    or find n: Call where n.callee_name() == "recv"
```

### Sink

```wql
sink <name> = find <bindings> where <expr>
sink <name> { kind: Call, name: "system" }
```

### Sanitizer

```wql
sanitizer <name> = find <bindings> where <expr>
```

Sanitizers use `=` syntax only (no attribute-block shorthand).

### Propagator

Propagators declare custom taint edges between sub-expressions of a matched pattern:

```wql
propagator memcpy_flow(c: Call) = pattern:
    c.callee_name() == "memcpy"
    from: src
    to: dst
```

- `pattern` — Expression that must match (the `from`/`to` bindings must appear in this expression).
- `from` / `to` — Binding names that define the taint edge direction.

> **Note:** User-defined `propagator` blocks are parsed and type-checked, but are not yet registered at evaluation time. For production rules, rely on built-in propagators from `security_patterns` (e.g. `memcpy`, `strcpy`) which are applied automatically in the DFG layer.

---

## Built-in Security Endpoints

`web_ql::builtin_endpoint_registry()` pre-registers thousands of stdlib sources, sinks, and sanitizers from `web_ql::security_patterns`, keyed as `"<language>.<set>"`:

```wql
taint {
    sources: ["c.io_sources"]
    sinks:   ["c.exec_ops"]
    sanitizers: ["c.command_sanitizers"]
}
```

### C / POSIX / Windows Sets

| Endpoint | Role |
|---|---|
| `c.io_sources` | `read`, `fgets`, `recv`, `getenv`, … |
| `c.exec_ops` | `system`, `popen`, `execve`, … |
| `c.file_ops` | File open/write operations |
| `c.alloc_ops` | `malloc`, `calloc`, … |
| `c.string_copy_ops` | `strcpy`, `strcat`, `sprintf`, … |
| `c.command_sanitizers` | Command-injection sanitizers |
| `c.path_sanitizers` | Path-traversal sanitizers |
| `c.free_functions` | `free`, `delete`, … |
| `c.dealloc_or_assert` | Deallocation and assertion calls |

Similar sets exist for `cpp.*`, `java.*`, `go.*`, `python.*`, `javascript.*`, `typescript.*`, and `rust.*`. See `web-ql/src/security_patterns/` for the full tables.

Short aliases (e.g. `io_sources` → `c.io_sources`) are registered for common cross-language names.

---

## Evaluation Model

### Search Evaluation

1. **Seed** — For each root binding, enumerate candidate nodes matching the binding type (with optional seed hints for performance).
2. **Filter** — Evaluate the `where` expression for each binding environment.
3. **Report** — On match, emit a `Finding` with all root binding nodes.

Rules with multiple `find` clauses produce findings from each clause independently.

### Three-Phase Optimization

The engine uses seed hints derived at compile time to avoid scanning every node:

| Hint | Effect |
|---|---|
| `Kind(Call)` | Only `Call` nodes |
| `CalleeMatch("exec")` | Calls whose callee matches |
| `MethodNameMatch("main")` | `MethodDef` nodes by name |
| `AllNodes` | Full scan (fallback) |

### Parallelism

- Rules are evaluated in parallel across a CPG (`rayon`).
- Files in a `Workspace` are scanned in parallel.
- CFG construction per function is parallelized during indexing.

---

## Workspace Scanning

`Workspace` manages multi-file analysis with incremental caching.

```rust
use web_ql::{Workspace, compile_rules, builtin_endpoint_registry, loader::file_hash};
use web_sitter::{CpgGenerator, GraphBuildOptions, language_from_path};

let rule_set = compile_rules(&std::fs::read_to_string("rules.wql")?)?;
let mut ws = Workspace::new(builtin_endpoint_registry());

let path = "src/main.py";
let lang = language_from_path(path);
let cpg = CpgGenerator::new_for_language(lang)?
    .generate_from_file_with_options(path, GraphBuildOptions::default())?;
let hash = file_hash(std::path::Path::new(path))?;
ws.upsert_file(path.into(), cpg, hash);

ws.build_cross_file_edges();
let findings = ws.scan(&rule_set);
```

| Method | Purpose |
|---|---|
| `upsert_file` | Add or update a file's CPG (skips if content hash unchanged) |
| `remove_file` | Remove a deleted file from the index |
| `build_cross_file_edges` | Resolve cross-file call edges for interprocedural taint |
| `scan` | Run all rules over all indexed files |
| `scan_incremental` | Re-scan only dirty files, reusing taint cache |

---

## Findings

```rust
pub struct Finding {
    pub rule_id: String,
    pub severity: Option<Severity>,
    pub message: String,
    pub tags: Vec<String>,
    pub location: FindingLocation,  // file, line, column
    pub matched_nodes: Vec<NodeId>, // primary nodes + taint path
}
```

Search findings locate the primary matched node. Taint findings include the full source→sink path in `matched_nodes`.

---

## CLI: web-scan

The `web-scan` binary scans a repository with compiled `.wql` rules:

```sh
# Scan with all rules in a directory
web-scan scan web-ql-queries/python --repo ./my-project

# Multiple query paths, JSON output to file
web-scan scan rules/custom.wql web-ql-queries/c \
    --repo ./my-project \
    --format json \
    --output findings.json

# HTML report, exit code 1 when findings exist
web-scan scan web-ql-queries/ --repo . --format html -o report.html --exit-code
```

| Flag | Description |
|---|---|
| `--repo PATH` | Repository root (default: `.`) |
| `-o, --output PATH` | Output file (default: stdout) |
| `-f, --format FORMAT` | `json`, `sarif`, `text`, or `html` |
| `--exclude PATTERN` | Skip paths containing substring (repeatable) |
| `--no-cache` | Force re-parse of all files |
| `--exit-code` | Exit 1 if findings exist, 2 on error |
| `--profile` | Print timing breakdown |

---

## Best Practices

1. **Scope with `languages`** — Avoid false positives by restricting rules to relevant languages.
2. **Prefer `callee_name()` over `name()`** for calls — `callee_name()` uses call-graph resolution; `name()` is the raw AST name.
3. **Define shared endpoints** — Factor sources/sinks into named `source`/`sink` blocks reused across rules.
4. **Use builtins for stdlib** — Reference `c.io_sources`, `java.*`, etc. instead of hand-maintaining function lists where possible.
5. **Combine structural + taint** — Use `find` for simple syntactic checks; use `taint` when data must flow between points.
6. **Call `build_cross_file_edges`** — Required before scanning for accurate cross-file taint.
7. **Tag with CWE IDs** — Use `tags: ["cwe-89"]` for downstream SARIF and compliance tooling.
8. **Test rules** — Place rules in `web-ql-queries/`; the test suite compiles all `.wql` files automatically.

---

## Grammar Summary

```ebnf
(* Top level *)
file          ::= item*
item          ::= rule | pred | source | sink | sanitizer | propagator

rule          ::= "rule" STRING "{" rule_body "}"
rule_body     ::= (metadata | clause)*
metadata      ::= "severity" ":" severity
                |  "languages" ":" "[" lang ("," lang)* "]"
                |  "tags" ":" string_list
                |  "message" ":" STRING
clause        ::= search | taint

search        ::= "find" bindings "where" expr
taint         ::= "taint" "{" taint_body "}"
taint_body    ::= ("sources" | "sinks" | "sanitizers" | "propagators") ":" endpoint_list
                |  taint_option*

bindings      ::= binding ("," binding)*
binding       ::= IDENT ":" type_expr

pred          ::= "pred" IDENT params ("{" expr "}" | "=" expr)
source        ::= "source" IDENT ("=" find_alt | "{" attr_block "}")
sink          ::= "sink" IDENT ("=" find_alt | "{" attr_block "}")
sanitizer     ::= "sanitizer" IDENT params? "=" find_alt
propagator    ::= "propagator" IDENT params "=" prop_body
prop_body     ::= "pattern" ":" expr "from" ":" IDENT "to" ":" IDENT

find_alt      ::= find_expr ("or" find_expr)*
find_expr     ::= "find" bindings "where" expr

expr          ::= or_expr
or_expr       ::= and_expr ("or" and_expr)*
and_expr      ::= not_expr ("and" not_expr)*
not_expr      ::= "not" not_expr | let_expr | compare_expr
let_expr      ::= "let" IDENT "=" call_expr "in" expr
compare_expr  ::= call_expr (cmp_op call_expr | "matches" pattern)?
call_expr     ::= primary ("." IDENT ("(" expr_list? ")")?)*
primary       ::= literal | IDENT | "(" expr ")"
                |  "exists" "(" IDENT ":" type_expr "|" expr ")"
                |  "forall" "(" IDENT ":" type_expr "|" expr ")"
                |  IDENT "(" expr_list? ")"

type_expr     ::= "Node" | "Expr" | "Stmt" | "Decl"
                |  "Call" | "MethodDef" | …
                |  "NodeType" "(" STRING ")"
                |  IDENT
```

---

## Related Documentation

| Document | Contents |
|---|---|
| [ir.md](ir.md) | CPG IR node taxonomy queried by web-ql types |
| [graph_schema.md](graph_schema.md) | Full `Cpg` schema (CFG, DFG, call graph) |
| [language_support.md](language_support.md) | Per-language lifter and metadata details |
| [`web-ql-queries/`](../web-ql-queries/) | Production CWE rule library (54 rules) |
