# CPG — Code Property Graph Pipeline

A multi-language static analysis library that builds Code Property Graphs (CPGs) from source code using tree-sitter grammars. CPGs unify the AST, control-flow graph (CFG), and data-flow graph (DFG) into a single queryable structure for security analysis and program understanding.

## Supported Languages

| Language | Lifter | Grammar |
|---|---|---|
| C | `CLifter` | `tree-sitter-c` |
| C++ | `CppLifter` | `tree-sitter-cpp` |
| Python | `PythonLifter` | `tree-sitter-python` |
| Go | `GoLifter` | `tree-sitter-go` |
| Java | `JavaLifter` | `tree-sitter-java` |
| JavaScript | `JsLifter` | `tree-sitter-javascript` |
| TypeScript | `TsLifter` | `tree-sitter-typescript` |
| Rust | `RustLifter` | `tree-sitter-rust` |

## Quick Start

```rust
use web_sitter::{generate_cpg_from_code, GraphBuildOptions};

let code = b"int main() { return 0; }";
let cpg = generate_cpg_from_code(code, GraphBuildOptions::default())
    .expect("CPG generation failed");

// Walk the AST
for (id, node) in cpg.ast.iter() {
    println!("{id}: {:?} — {:?}", node.kind, node.name);
}

// Query the call graph
for (fn_id, entry) in cpg.call_graph.iter() {
    for call in &entry.calls {
        println!("{} calls {}", entry.name, call.callee);
    }
}
```

For non-C languages, use `CpgGenerator`:

```rust
use web_sitter::{CpgGenerator, GraphBuildOptions, SourceLanguage};

let cpg = CpgGenerator::new_for_language(SourceLanguage::Python)
    .expect("parser init")
    .generate_from_source_with_options(src.as_bytes(), GraphBuildOptions::default())
    .expect("CPG generation failed");
```

Or use the language-agnostic helper:

```rust
use web_sitter::{language_from_path, CpgGenerator, GraphBuildOptions};

let lang = language_from_path("main.go");
let cpg = CpgGenerator::new_for_language(lang)
    .unwrap()
    .generate_from_source_with_options(src.as_bytes(), GraphBuildOptions::default())
    .unwrap();
```

## Incremental Rebuilds

```rust
use web_sitter::{IncrementalCpgGenerator, compute_edit, GraphBuildOptions};

let mut gen = IncrementalCpgGenerator::new(src_v1.as_bytes(), GraphBuildOptions::default())
    .expect("init");

let edits = compute_edit(src_v1.as_bytes(), src_v2.as_bytes());
let cpg = gen.rebuild(src_v2.as_bytes(), &edits).expect("rebuild");
```

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
    ├──→  CFG builder  ──→  BasicBlock graph  (cpg.basic_blocks)
    │
    ├──→  DFG builder  ──→  DataflowGraph  (cpg.dataflow)
    │                       call_graph  (cpg.call_graph)
    │
    └──→  Language metadata  (cpg.python_metadata, cpg.go_metadata, …)
```

Each `LanguageLifter` translates tree-sitter node kind strings into the language-agnostic `IrNodeKind` enum. All algorithms (CFG, DFG, call graph, incremental rebuild) operate on `IrNodeKind` and never inspect the raw grammar strings directly.

## Project Layout

```
web-sitter/
  src/
    lib.rs              — IrNode, Cpg, all metadata structs, type enums
    lifter.rs           — LanguageLifter trait + all 8 lifter impls
    cpg_generator.rs    — CpgGenerator, GraphBuildOptions, SourceLanguage
    cfg.rs              — Control-flow graph builder
    dfg.rs              — Data-flow graph + call graph builder
    incremental.rs      — Incremental CPG rebuild machinery
    type_inference.rs   — Language-specific type inference passes
    call_analysis.rs    — Cross-file call edge resolution helpers
    function_summary.rs — Interprocedural function summaries
    security_patterns.rs — Built-in taint sources/sinks
    symbol_anonymizer.rs — CPG symbol anonymization
  tests/                — Integration tests (one file per language + topic)
grammars/               — Vendored grammar.json / node-types.json per language
plans/                  — Per-language implementation design documents
```

## Docs

- [`docs/ir.md`](docs/ir.md) — IR node taxonomy: `IrNodeKind`, sub-kinds, `IrNode` fields
- [`docs/graph_schema.md`](docs/graph_schema.md) — Full `Cpg` struct schema: AST, CFG, DFG, call graph, metadata tables
- [`docs/language_support.md`](docs/language_support.md) — Per-language lifter details, metadata structs, unique analysis features

## Running Tests

```sh
cargo test
```

All tests live in `web-sitter/tests/`. Each language has a `*_grammar_coverage.rs` file with one test per significant tree-sitter node type. Additional files cover CFG/DFG correctness, incremental rebuild parity, and security pattern detection.
