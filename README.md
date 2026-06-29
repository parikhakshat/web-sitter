# web-sitter

**Multi-language Code Property Graph generation and query stack for Rust, powered by tree-sitter.**

This workspace provides an end-to-end static analysis pipeline:

| Crate | Role |
|---|---|
| [**web-sitter**](#quick-start) | Parse source into a unified [Code Property Graph (CPG)](https://cpg.joern.io/) — AST, CFG, DFG, and call graph in one structure |
| [**web-ql**](docs/web-ql.md) | Declarative query language (`.wql`) for structural search, CFG/DFG predicates, and interprocedural taint analysis over the CPG |
| [**web-scan**](#scanning-with-web-scan) | CLI that scans a repository with web-ql rules and emits JSON, SARIF, text, or HTML findings |
| **web-profiler** | Lightweight profiling hooks used by the query engine |

web-sitter parses source code; web-ql queries it. Downstream tools get one graph and one rule language instead of stitching together separate parsers, IRs, and analysis passes.

Built for security tooling, IDE integrations, and static analysis pipelines that need fast, language-agnostic program structure with enough semantic detail for taint tracking, call resolution, and incremental re-analysis on every keystroke.

---

## Why web-sitter?

| Capability | What you get |
|---|---|
| **One IR, eight languages** | tree-sitter parse trees are lifted into a shared `IrNodeKind` taxonomy; CFG/DFG/call-graph builders never touch raw grammar strings |
| **Production graph layers** | AST, basic blocks, data-flow defs/uses/edges, call graph, cross-file call edges, function summaries |
| **Incremental rebuilds** | Edit-aware CPG updates with structural key reuse, targeted CFG/DFG refresh, and persistent state (bincode) |
| **Security-ready metadata** | Built-in taint source/sink/propagator specs for C/POSIX/Windows stdlib; per-language type inference and class hierarchy |
| **Serde throughout** | `Cpg` and all graph layers serialize for caching, RPC, or offline analysis |
| **web-ql rule language** | Datalog-inspired `.wql` queries with taint tracking, CFG/DFG reachability, and a 54-rule CWE library |
| **Repository scanner** | `web-scan` indexes a codebase, runs rules in parallel, and outputs SARIF-ready findings |

---

## Supported Languages

| Language | Lifter | Grammar | `SourceLanguage` |
|---|---|---|---|
| C | `CLifter` | `tree-sitter-c` | `SourceLanguage::C` |
| C++ | `CppLifter` | `tree-sitter-cpp` | `SourceLanguage::Cpp` |
| Python | `PythonLifter` | `tree-sitter-python` | `SourceLanguage::Python` |
| Go | `GoLifter` | `tree-sitter-go` | `SourceLanguage::Go` |
| Java | `JavaLifter` | `tree-sitter-java` | `SourceLanguage::Java` |
| JavaScript | `JsLifter` | `tree-sitter-javascript` | `SourceLanguage::JavaScript` |
| TypeScript | `TsLifter` | `tree-sitter-typescript` | `SourceLanguage::TypeScript` |
| Rust | `RustLifter` | `tree-sitter-rust` | `SourceLanguage::Rust` |

Language detection from file paths is available via `language_from_path("main.go")`.

---

## Requirements

- **Rust** stable (2024 edition)
- **Linux / macOS / WSL** — C/C++ macro extraction invokes `gcc -E` when parsing files from disk

---

## Installation

Add web-sitter as a path or git dependency in your `Cargo.toml`:

```toml
[dependencies]
web-sitter = { path = "web-sitter" }
# or
# web-sitter = { git = "https://github.com/<org>/cpg" }
```

Then build from the workspace root:

```sh
cargo build --workspace
```

Add web-ql for querying CPGs:

```toml
[dependencies]
web-sitter = { path = "web-sitter" }
web-ql = { path = "web-ql" }
```

---

## Quick Start

### Generate a CPG from source

The simplest entry point defaults to C:

```rust
use web_sitter::generate_cpg_from_code;

let code = "int main() { return 0; }";
let cpg = generate_cpg_from_code(code)?;

for (id, node) in cpg.ast.iter() {
    println!("{id}: {:?} — {:?}", node.kind, node.name);
}
```

### Pick a language explicitly

```rust
use web_sitter::{CpgGenerator, GraphBuildOptions, SourceLanguage};

let src = "def greet(name: str) -> str:\n    return f'hello {name}'\n";

let cpg = CpgGenerator::new_for_language(SourceLanguage::Python)?
    .generate_from_source_with_options(src.as_bytes(), GraphBuildOptions::default())?;
```

### Detect language from a file path

```rust
use web_sitter::{language_from_path, CpgGenerator, GraphBuildOptions};

let lang = language_from_path("cmd/server/main.go");
let cpg = CpgGenerator::new_for_language(lang)?
    .generate_from_file_with_options("cmd/server/main.go", GraphBuildOptions::default())?;
```

### Walk the call graph

```rust
for (fn_id, entry) in cpg.call_graph.iter() {
    for call in &entry.calls {
        println!("{} calls {} at node {}", entry.name, call.callee, call.node_id);
    }
}
```

---

## Querying with web-ql

web-ql rules live in `.wql` files. A structural rule matches dangerous calls; a taint rule tracks data flow from sources to sinks.

```wql
rule "dangerous-eval" {
    severity: high
    languages: [javascript, python]
    message: "Use of eval()"
    find n: Call where n.callee_name() == "eval"
}
```

```rust
use web_ql::{compile_rules, Workspace, builtin_endpoint_registry};

let rule_set = compile_rules(include_str!("rules.wql"))?;
let mut ws = Workspace::new(builtin_endpoint_registry());
// ws.upsert_file(path, cpg, content_hash);
ws.build_cross_file_edges();
let findings = ws.scan(&rule_set);
```

See [`docs/web-ql.md`](docs/web-ql.md) for the full language reference (types, methods, CFG/DFG predicates, taint, endpoints). Production CWE rules are in [`web-ql-queries/`](web-ql-queries/).

---

## Scanning with web-scan

Scan a repository with the built-in rule library:

```sh
cargo run -p web-scan -- scan web-ql-queries/python --repo /path/to/project

# JSON output, exit non-zero when findings exist
cargo run -p web-scan -- scan web-ql-queries/ --repo . \
    --format json --output findings.json --exit-code
```

Supported output formats: `json`, `sarif`, `text`, `html`.

---

## What You Get: The `Cpg` Struct

Every generation path produces a `Cpg` value containing:

```
Cpg
├── ast              BTreeMap<NodeId, IrNode>       — language-agnostic IR tree
├── basic_blocks     BTreeMap<String, BasicBlock>   — CFG (entry, exit, successors)
├── dataflow         DataflowGraph                  — defs, uses, taint-relevant edges
├── call_graph       BTreeMap<NodeId, CallGraphEntry>
├── cross_file_calls Vec<CrossFileCallEdge>
├── function_summaries BTreeMap<NodeId, FunctionSummary>
├── class_hierarchy  BTreeMap<String, Vec<String>>
├── comments         Vec<SourceComment>
└── *_metadata       Per-language side-tables (cpp, go, python, java, js, ts, rust)
```

C/C++ files additionally carry preprocessor data (`macro_aliases`, `macro_bodies`, `custom_allocators`) extracted via `gcc -E`.

See [`docs/graph_schema.md`](docs/graph_schema.md) for the full schema and accessor methods.

---

## Architecture

```
Source bytes
    │
    ▼
tree-sitter parser  ←  LanguageLifter (lift_kind, loop_kind, lit_kind, …)
    │
    ▼
CpgGenerator  ──→  IrNode AST  (cpg.ast)
    │
    ├──→  CFG builder       ──→  basic_blocks
    ├──→  DFG builder       ──→  dataflow + call_graph
    ├──→  Type inference    ──→  per-node inferred types
    ├──→  Call analysis     ──→  cross_file_calls, function_summaries
    └──→  Language metadata ──→  python_metadata, go_metadata, …
```

Each `LanguageLifter` maps tree-sitter node kind strings to `IrNodeKind` variants. All downstream algorithms dispatch on `IrNodeKind` — they never inspect raw grammar strings directly. The original tree-sitter kind is preserved in `IrNode::node_type` as an escape hatch.

See [`docs/ir.md`](docs/ir.md) for the full IR taxonomy.

---

## Configuration: `GraphBuildOptions`

```rust
use web_sitter::GraphBuildOptions;

let options = GraphBuildOptions {
    include_cfg: true,           // build control-flow basic blocks
    include_dfg: true,           // build data-flow graph and call graph
    remove_identifiers: false,   // strip identifier text (privacy / dedup)
    skip_preproc_nodes: false,   // omit C preprocessor directive nodes
    minimal_text: true,          // store only essential source text on nodes
    macro_aliases: None,         // override macro alias map (auto-filled for files)
};
```

Pass options to `CpgGenerator::generate_from_source_with_options` or `IncrementalCpgGenerator::new`.

---

## Incremental Rebuilds

For editor integrations and long-running analysis sessions, `IncrementalCpgGenerator` reuses structural keys and refreshes only the CFG/DFG regions affected by an edit:

```rust
use web_sitter::{IncrementalCpgGenerator, compute_edit, GraphBuildOptions};

let src_v1 = "void f() { int x = 5; }";
let src_v2 = "void f() { int x = 10; }";

let mut gen = IncrementalCpgGenerator::new(GraphBuildOptions::default())?;
gen.parse_initial(src_v1.as_bytes())?;

let edit = compute_edit(src_v1.as_bytes(), src_v2.as_bytes())
    .expect("sources differ");
let cpg = gen.apply_edit(&edit, src_v2.as_bytes())?;
```

Additional capabilities:

- **`parse_incremental`** — apply a batch of `TextEdit`s in one pass
- **`parse_lightweight`** — build a symbol index without full CFG/DFG
- **`generate_function_cpg`** — rebuild specific functions by `NodeId`
- **`save_state` / `load_state`** — persist incremental state to disk (bincode)

Incremental rebuilds are verified against full parses in `web-sitter/tests/incremental.rs`.

---

## Security Analysis

### Built-in taint specs

The `security_patterns` module is the single source of truth for stdlib taint sources, sinks, propagators, and allocators across C/POSIX/Windows:

```rust
use web_sitter::security_patterns as sp;

if let Some(spec) = sp::get_sink("system") {
    // spec.sink_args lists taint-sensitive parameter indices
}

let sources: Vec<&str> = sp::STDLIB_TAINT_SOURCES.iter().map(|(n, _)| *n).collect();
```

### Function summaries

`FunctionSummary` captures per-function effects (sink params, taint propagation, frees) used by interprocedural analysis:

```rust
use web_sitter::FunctionSummary;

if let Some(summary) = cpg.function_summaries.get(&fn_id) {
    for effect in &summary.param_effects {
        // ParamEffect::Sink, TaintOut, TaintReturn, Frees
    }
}
```

### Symbol anonymization

Strip user-defined variable names while preserving function names, stdlib identifiers, and type names — useful before sending CPGs to external models:

```rust
use web_sitter::SymbolAnonymizer;

let mut anonymizer = SymbolAnonymizer::new();
let AnonymizedCpg { cpg, symbol_table } = anonymizer.anonymize(&cpg);
```

---

## Documentation

| Document | Contents |
|---|---|
| [`docs/web-ql.md`](docs/web-ql.md) | **web-ql language reference** — syntax, types, methods, taint, scanning |
| [`docs/ir.md`](docs/ir.md) | IR node taxonomy: `IrNodeKind`, sub-kinds, `IrNode` fields |
| [`docs/graph_schema.md`](docs/graph_schema.md) | Full `Cpg` schema: AST, CFG, DFG, call graph, metadata tables |
| [`docs/language_support.md`](docs/language_support.md) | Per-language lifter details, metadata structs, unique analysis features |
| [`web-ql-queries/`](web-ql-queries/) | Production CWE security rules (`.wql`) for all supported languages |
| [`plans/`](plans/) | Per-language implementation design documents |

---

## Development

### Run tests

```sh
cargo test --workspace
```

Tests live in `web-sitter/tests/`:

- `*_grammar_coverage.rs` — one test per significant tree-sitter node type, per language
- `cpg_comprehensive.rs` — end-to-end CFG/DFG correctness
- `incremental.rs` — incremental vs. full-parse parity
- `symbol_anonymizer.rs` — anonymization invariants

CI runs on every push and pull request to `main` (build + full test suite).

### Project layout

```
web-sitter/             — CPG generation (tree-sitter → IR → CFG/DFG/call graph)
  src/                  — Lifters, generators, incremental rebuild, security patterns
  tests/                — Grammar coverage, CFG/DFG correctness, incremental parity
web-ql/                 — ScuzzQL query language and evaluation engine
  src/                  — Lexer, parser, planner, engine, taint, workspace
  tests/                — Parser, engine, CFG/DFG, workspace integration tests
web-scan/               — CLI repository scanner (web-ql + web-sitter)
web-ql-queries/         — Production CWE rule library (.wql, per language)
web-profiler/           — Profiling hooks for query evaluation
grammars/               — Vendored grammar.json / node-types.json per language
docs/                   — IR, schema, language support, and web-ql reference
plans/                  — Per-language implementation design documents
```

---

## License

MIT
