# CPG Graph Schema

The `Cpg` struct is the top-level output of the pipeline. It contains all graph layers (AST, CFG, DFG, call graph) plus per-language metadata side-tables, cross-file call edges, and source-level annotations.

---

## `Cpg` Struct

```rust
pub struct Cpg {
    // ── Core graph layers ───────────────────────────────────────────────────
    pub ast:            BTreeMap<NodeId, IrNode>,
    pub basic_blocks:   BTreeMap<String, BasicBlock>,
    pub call_graph:     BTreeMap<NodeId, CallGraphEntry>,
    pub dataflow:       DataflowGraph,

    // ── Source metadata ─────────────────────────────────────────────────────
    pub source_file:    Option<String>,
    pub language:       String,
    pub comments:       Vec<SourceComment>,

    // ── C/C++ preprocessor data ─────────────────────────────────────────────
    pub macro_aliases:  BTreeMap<String, String>,
    pub macro_bodies:   BTreeMap<String, MacroBody>,
    pub custom_allocators: BTreeMap<String, i32>,

    // ── Cross-file analysis ─────────────────────────────────────────────────
    pub cross_file_calls: Vec<CrossFileCallEdge>,
    pub class_hierarchy:  BTreeMap<String, Vec<String>>,
    pub function_summaries: BTreeMap<NodeId, FunctionSummary>,

    // ── Per-language metadata side-tables ───────────────────────────────────
    pub cpp_metadata:    BTreeMap<NodeId, CppNodeMetadata>,
    pub go_metadata:     BTreeMap<NodeId, GoNodeMetadata>,
    pub python_metadata: BTreeMap<NodeId, PythonNodeMetadata>,
    pub java_metadata:   BTreeMap<NodeId, JavaNodeMetadata>,
    pub js_metadata:     BTreeMap<NodeId, JsNodeMetadata>,
    pub ts_metadata:     BTreeMap<NodeId, TsNodeMetadata>,
    pub rust_metadata:   BTreeMap<NodeId, RustNodeMetadata>,
}
```

`NodeId` is a `u32`. All `BTreeMap` fields default to empty so CPGs serialized by older versions can be deserialized into newer structs.

### Accessor methods on `Cpg`

```rust
cpg.get_node(id)          -> Option<&IrNode>
cpg.iter_nodes()          -> impl Iterator<Item = (&NodeId, &IrNode)>
cpg.cpp_meta(id)          -> Option<&CppNodeMetadata>
cpg.cpp_meta_mut(id)      -> &mut CppNodeMetadata
cpg.go_meta(id)           -> Option<&GoNodeMetadata>
cpg.go_meta_mut(id)       -> &mut GoNodeMetadata
cpg.python_meta(id)       -> Option<&PythonNodeMetadata>
cpg.python_meta_mut(id)   -> &mut PythonNodeMetadata
cpg.java_meta(id)         -> Option<&JavaNodeMetadata>
cpg.java_meta_mut(id)     -> &mut JavaNodeMetadata
cpg.js_meta(id)           -> Option<&JsNodeMetadata>
cpg.js_meta_mut(id)       -> &mut JsNodeMetadata
cpg.ts_meta(id)           -> Option<&TsNodeMetadata>
cpg.ts_meta_mut(id)       -> &mut TsNodeMetadata
cpg.rust_meta(id)         -> Option<&RustNodeMetadata>
cpg.rust_meta_mut(id)     -> &mut RustNodeMetadata
cpg.function_kind(id)     -> FunctionKind
```

---

## AST Layer (`cpg.ast`)

Each `IrNode` (see [`ir.md`](ir.md)) is keyed by its `NodeId`. The root `File` node has `parent_id = None`. Every node inside a function body carries `function_id = Some(method_def_node_id)`. Nodes inside comprehensions (Python) carry the comprehension's own `function_id`.

---

## CFG Layer (`cpg.basic_blocks`)

Basic blocks are keyed by a string id (e.g. `"42_entry"`, `"42_bb1"`). The string encodes the enclosing function's `NodeId` as a prefix.

```rust
pub struct BasicBlock {
    pub block_type:           String,          // "entry", "exit", "branch", "merge", "body", …
    pub nodes:                Vec<NodeId>,     // ordered list of IrNode ids in this BB
    pub successors:           Vec<String>,     // normal successor BB ids
    pub exception_successors: Vec<String>,     // exception-path successor BB ids (C++/Java/Python)
    pub function:             NodeId,          // enclosing MethodDef node id
    pub is_setjmp_target:     bool,            // C: BB contains a setjmp call
}
```

Edges between basic blocks are encoded as `successors` / `exception_successors` lists on each block. There is no separate edge collection. To traverse the CFG:

```rust
let entry_id = format!("{fn_id}_entry");
let mut worklist = vec![entry_id];
while let Some(bb_id) = worklist.pop() {
    let bb = &cpg.basic_blocks[&bb_id];
    for succ in &bb.successors {
        worklist.push(succ.clone());
    }
}
```

---

## DFG Layer (`cpg.dataflow`)

```rust
pub struct DataflowGraph {
    pub definitions: Vec<DataflowDef>,
    pub uses:        Vec<DataflowUse>,
    pub edges:       Vec<DataflowEdge>,
}

pub struct DataflowDef {
    pub node_id:     NodeId,          // IrNode where the definition occurs
    pub variable:    String,          // variable name
    pub function_id: Option<NodeId>,  // enclosing function scope
}

pub struct DataflowUse {
    pub node_id:     NodeId,
    pub variable:    String,
    pub function_id: Option<NodeId>,
}

pub struct DataflowEdge {
    pub source:      NodeId,          // definition node
    pub destination: NodeId,          // use node
    pub variable:    String,
    pub edge_type:   String,          // "DATA_FLOW", "CLOSURE_FLOW", etc.
    pub field_path:  Vec<String>,     // field-sensitive path, e.g. ["buf"] for ctx.buf
}
```

---

## Call Graph (`cpg.call_graph`)

Keyed by the `MethodDef` `NodeId` of the caller.

```rust
pub struct CallGraphEntry {
    pub name:     String,         // function name
    pub calls:    Vec<CallSite>,  // outgoing calls
    pub called_by: Vec<NodeId>,   // callee NodeIds of functions that call this one
}

pub struct CallSite {
    pub callee:          String,              // simple callee name
    pub callee_id:       Option<NodeId>,      // MethodDef NodeId if resolved in this CPG
    pub call_site:       Option<u32>,         // NodeId of the Call IrNode
    pub qualified_callee: Option<String>,     // fully-qualified name (C++/Java/Go)
    pub callee_kind:     FunctionKind,        // Internal / WorkspaceLocal / ExternalDecl / LibrarySymbol
}
```

### `FunctionKind`

| Value | Meaning |
|---|---|
| `Internal` | Definition present in this CPG |
| `WorkspaceLocal` | Definition in another file in the same workspace |
| `ExternalDecl` | Only a declaration found; body in a library |
| `LibrarySymbol` | Known only from taint config / symbol DB; no source |

---

## Cross-File Call Edges (`cpg.cross_file_calls`)

Populated during per-file CPG construction; resolved by the workspace layer.

```rust
pub struct CrossFileCallEdge {
    pub call_node:        NodeId,         // Call IrNode in this file
    pub caller_fn:        NodeId,         // enclosing MethodDef NodeId
    pub callee_name:      String,         // unqualified callee name
    pub qualified_callee: Option<String>, // fully-qualified name if available
    pub arg_positions:    Vec<usize>,     // 0-based argument indices passed
}
```

---

## Class Hierarchy (`cpg.class_hierarchy`)

Maps a type name to its declared direct supertypes (extends + implements). Populated after lifting.

```
"Cat" → ["Animal", "Mammal"]
"Dog" → ["Animal"]
```

---

## Source Comments (`cpg.comments`)

```rust
pub struct SourceComment {
    pub line: u32,
    pub text: String,
}
```

Used for suppression directives (e.g. `// scuzz-ignore`) without polluting the IR.

---

## Serialization

The `Cpg` struct derives `serde::Serialize / Deserialize`. No field uses `skip_serializing_if` — bincode requires every field to be written in declaration order. Adding new fields must be done by appending to the end of each struct, and `CACHE_FORMAT_VERSION` in `incremental.rs` must be bumped whenever `IrNodeKind`, `Cpg`, or any language metadata struct changes its binary layout.

JSON serialization (via `sonic-rs`) works for tooling integration; bincode is used for the incremental cache.

---

## Per-Language Metadata Side-Tables

Each side-table is a `BTreeMap<NodeId, XxxNodeMetadata>` appended to `Cpg`. Only nodes that carry language-specific properties have entries; most nodes have no entry. Use `cpg.xxx_meta(id)` to look up (returns `Option`); `cpg.xxx_meta_mut(id)` to insert-or-update.

See [`language_support.md`](language_support.md) for the full field listing of each metadata struct.

---

## Function Summaries (`cpg.function_summaries`)

Keyed by `MethodDef` NodeId.

```rust
pub struct FunctionSummary {
    // which parameters flow to which return-value positions
    // used by interprocedural DFG propagation
}
```

Populated by the function summary pass after DFG construction. Consumed by the workspace layer to propagate taint across call boundaries without re-analyzing callees.

---

## C/C++ Preprocessor Data

| Field | Type | Meaning |
|---|---|---|
| `macro_aliases` | `BTreeMap<String, String>` | `MALLOC → malloc` — macro wrapping a function |
| `macro_bodies` | `BTreeMap<String, MacroBody>` | Macro params + body text for expansion |
| `custom_allocators` | `BTreeMap<String, i32>` | Function name → size-arg index (`-1` = implicit like `strdup`) |

```rust
pub struct MacroBody {
    pub params: Vec<String>,  // empty for object-like macros
    pub body:   String,
}
```
