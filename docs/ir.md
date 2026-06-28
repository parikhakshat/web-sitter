# IR Node Taxonomy

The CPG pipeline translates tree-sitter parse trees into a language-agnostic intermediate representation. Every node in `cpg.ast` is an `IrNode` whose `kind` field is an `IrNodeKind` variant. Analysis algorithms dispatch on `kind`; the raw tree-sitter kind string is preserved in `node_type` as an escape hatch.

---

## `IrNodeKind` Variants

### Structural

| Variant | Meaning |
|---|---|
| `File` | Source file root (C `translation_unit`, Python `module`, Go `source_file`, etc.) |
| `Namespace` | C++ namespace, Java package scope |
| `ClassDef` | Class, struct, union, interface, record type definition |
| `MethodDef` | Function, method, or lambda definition (any callable with a body) |

### Declarations

| Variant | Meaning |
|---|---|
| `ParamDef` | Function parameter |
| `LocalDef` | Local variable declaration |
| `FieldDef` | Class / struct field |
| `TypeAlias` | `typedef`, `type X = Y`, `using X = Y` |

### Statements

| Variant | Meaning |
|---|---|
| `Block` | Compound statement / indented block |
| `Return` | Return statement |
| `Loop` | Any loop; discriminated by `loop_kind` (For / While / DoWhile / ForEach) |
| `Conditional` | `if` / `elif` branch |
| `Switch` | Switch/match on a value |
| `Case` | One arm of a switch/match |
| `SwitchDefault` | Default arm of a switch |
| `Break` | Break statement |
| `Continue` | Continue statement |
| `Goto` | Goto statement |
| `Label` | Label target |
| `Throw` | Throw / raise exception |
| `Try` | Try block; discriminated by `try_kind` (Standard / Seh / WithResources) |
| `Catch` | Catch / except clause |
| `ExprStmt` | Bare expression used as a statement |

### Expressions

| Variant | Meaning |
|---|---|
| `Call` | Free-function or method call |
| `Assign` | Assignment expression |
| `BinaryOp` | Binary operator; operator text in `IrNode::operator` |
| `UnaryOp` | Unary operator; operator text in `IrNode::operator` |
| `TernaryOp` | Ternary / conditional expression |
| `Cast` | Type cast |
| `Subscript` | Index / subscript expression `a[i]` |
| `MemberAccess` | Field/property access `a.b` (non-call) |
| `LambdaDef` | Anonymous function / closure expression |
| `NewExpr` | C++ / Java `new` heap allocation |
| `DeleteExpr` | C++ `delete` / JS `delete` |
| `SizeofExpr` | `sizeof` expression |

### Leaves

| Variant | Meaning |
|---|---|
| `Identifier` | Variable or name reference |
| `Literal` | Constant value; discriminated by `lit_kind` |
| `TypeRef` | Reference to a type name |

### Escape Hatch

| Variant | Meaning |
|---|---|
| `Unknown` | No mapping defined; `node_type` retains the raw tree-sitter kind |

---

## Python-Specific Variants

| Variant | Meaning |
|---|---|
| `Import` | `import` / `from … import` / `from __future__ import` |
| `Yield` | Generator `yield` / `yield from` suspension point |
| `Await` | `await expr` async suspension point |
| `Comprehension` | List / set / dict comprehension or generator expression (own scope) |
| `With` | Context manager `with` statement |
| `Assert` | `assert condition, message` |
| `Delete` | `del target` — kills a variable binding in the DFG |
| `Global` | `global` / `nonlocal` declaration; discriminated by `GlobalKind` |
| `Decorator` | Decorator expression applied to a function or class |
| `NamedExpr` | Walrus operator `:=` |
| `CollectionExpr` | List / tuple / set / dict literal; discriminated by `CollectionKind` |

---

## Go-Specific Variants

| Variant | Meaning |
|---|---|
| `GoStmt` | `go expr` goroutine launch |
| `DeferStmt` | `defer expr` deferred call |
| `SelectStmt` | Multi-way channel `select` |
| `CommCase` | One arm of a `select` |
| `SendStmt` | Channel send `ch <- v` |
| `ReceiveExpr` | Channel receive `<-ch` |
| `ShortVarDecl` | Short variable declaration `:=` |
| `IncDecStmt` | `x++` / `x--` statement |
| `TypeAssertion` | Type assertion `i.(T)` |
| `TypeSwitch` | Type switch `switch v := i.(type)` |
| `TypeCase` | One arm of a type switch |
| `CompositeLit` | Composite literal `T{…}` |
| `Fallthrough` | `fallthrough` statement |

---

## Java-Specific Variants

| Variant | Meaning |
|---|---|
| `EnumDef` | `enum` declaration |
| `EnumConstant` | Named constant inside an enum |
| `SwitchExpr` | Value-producing `switch` expression (Java 14+) |
| `SwitchRule` | Arrow arm `case X -> expr` |
| `Yield` | `yield expr` inside a switch expression arm |
| `Finally` | `finally` clause |
| `Synchronized` | `synchronized (obj) { }` block |
| `Assert` | `assert condition : message` |
| `InstanceofExpr` | `x instanceof T` / pattern form |
| `MethodRef` | `Class::method` method reference |
| `NewArray` | `new T[n]` array allocation |
| `ArrayInit` | `{1, 2, 3}` array initializer |
| `Import` | `import` declaration |
| `ModuleDecl` | `module com.example { }` (Java 9+) |
| `StringTemplate` | `STR."…"` template expression (Java 21+) |
| `ClassLiteral` | `Foo.class` expression |
| `ThisExpr` | `this` or `super` as a standalone expression |

---

## JavaScript / TypeScript-Specific Variants

| Variant | Meaning |
|---|---|
| `AwaitExpr` | `await expr` |
| `YieldExpr` | `yield expr` / `yield* expr` |
| `TemplateStr` | Backtick template literal |
| `SpreadExpr` | `...expr` in calls or array/object literals |
| `OptionalChain` | `?.` optional chaining |
| `JsxElement` | JSX element |
| `Export` | ESM `export` statement |
| `Import` | ESM `import` statement |
| `SequenceExpr` | `(a, b, c)` comma expression |
| `InterfaceDecl` | TypeScript interface declaration |
| `EnumDecl` | TypeScript `enum` declaration |
| `AsExpr` | `expr as T` type assertion |
| `NonNullExpr` | `x!` non-null assertion |
| `SatisfiesExpr` | `expr satisfies T` |
| `AmbientDecl` | `declare …` ambient declaration |
| `TypePredicate` | `x is T` return type predicate |

---

## Rust-Specific Variants

| Variant | Meaning |
|---|---|
| `MatchExpr` | `match expr { … }` (value-returning) |
| `MatchArm` | One arm of a `match` |
| `ImplBlock` | `impl Type` or `impl Trait for Type` |
| `TraitDef` | `trait` definition |
| `UnsafeBlock` | `unsafe { … }` block |
| `ClosureExpr` | Closure `\|x\| expr` with capture semantics |
| `MacroInvocation` | `macro!(…)` invocation |
| `TryExpr` | `expr?` try operator (desugars to early-return) |
| `LoopExpr` | `loop { }` infinite loop expression (value-returning via `break`) |
| `RangeExpr` | `a..b`, `a..=b`, `..` range expression |
| `StructExpr` | Struct literal `Foo { a: x, b: y }` |
| `ModDef` | `mod` module definition |
| `BreakExpr` | `break value` (Rust break carries a value) |
| `LifetimeRef` | Lifetime annotation `'a` |
| `UseDecl` | `use` declaration |

---

## C / C++-Specific Variants

| Variant | Meaning |
|---|---|
| `SehLeave` | MSVC `__leave` statement inside a SEH `__try` block |

---

## Sub-Kind Enums

### `LoopKind` — discriminates `IrNodeKind::Loop`

| Value | Meaning |
|---|---|
| `While` | `while (cond)` loop |
| `For` | `for (init; cond; step)` loop |
| `DoWhile` | `do { } while (cond)` loop |
| `ForEach` | Range-based / iterator for loop |

### `TryKind` — discriminates `IrNodeKind::Try`

| Value | Meaning |
|---|---|
| `Standard` | Normal try/catch |
| `Seh` | MSVC structured exception handling `__try` / `__except` |
| `WithResources` | Java try-with-resources |

### `LiteralKind` — discriminates `IrNodeKind::Literal`

| Value | Meaning |
|---|---|
| `Integer` | Integer constant |
| `Float` | Floating-point constant |
| `String` | String constant |
| `Char` | Character constant |
| `Bool` | Boolean `true` / `false` |
| `Null` | `null` / `nil` / `None` |
| `Bytes` | Python `b"…"` byte string |
| `Ellipsis` | Python `…` ellipsis literal |
| `Regex` | JavaScript `/pattern/flags` regex literal |
| `Template` | JavaScript template literal (no substitutions) |
| `BigInt` | JavaScript `42n` big integer |

### Python Sub-Kinds

| Enum | Values |
|---|---|
| `GlobalKind` | `Global`, `Nonlocal` |
| `ImportKind` | `Regular`, `From`, `Future` |
| `ComprehensionKind` | `List`, `Set`, `Dict`, `Generator` |
| `CollectionKind` | `List`, `Tuple`, `Set`, `Dict` |

### Go Sub-Kinds

| Enum | Values |
|---|---|
| `ChannelDirection` | `Send` (`chan<- T`), `Recv` (`<-chan T`), `Bidi` (`chan T`) |

---

## `IrNode` Fields

```rust
pub struct IrNode {
    // IR classification
    pub kind:           IrNodeKind,
    pub loop_kind:      Option<LoopKind>,
    pub try_kind:       Option<TryKind>,
    pub lit_kind:       Option<LiteralKind>,

    // Raw tree-sitter escape hatch
    pub node_type:      String,     // e.g. "function_definition"

    // Declared name / signature
    pub name:           Option<String>,
    pub signature:      Option<String>,

    // Source text
    pub text:           Option<String>,

    // Graph structure
    pub children:       Vec<NodeId>,
    pub field_names:    Vec<Option<String>>,
    pub parent_id:      Option<NodeId>,
    pub function_id:    Option<NodeId>,   // enclosing function scope
    pub basic_block:    Option<String>,   // BB id if inside a BB

    // Source position
    pub line:           u32,
    pub column:         u32,
    pub end_line:       u32,
    pub end_column:     u32,
    pub start_byte:     Option<u32>,
    pub end_byte:       Option<u32>,

    // Semantic annotations
    pub string_length:  Option<u32>,
    pub array_size:     Option<i64>,
    pub array_size_expr: Option<String>,
    pub operator:       Option<String>,   // for BinaryOp / UnaryOp / Assign
    pub argument_count: Option<u32>,      // for Call nodes

    // OOP / cross-language metadata on the node itself
    pub class_context:  Option<String>,
    pub namespace:      Option<String>,
    pub visibility:     Option<String>,
    pub is_constructor: Option<bool>,
    pub is_destructor:  Option<bool>,
    pub is_virtual:     Option<bool>,
    pub template_params: Option<Vec<String>>,
    pub qualified_name: Option<String>,
    pub base_classes:   Option<Vec<String>>,
}
```

`AstNode` is a backward-compatible type alias for `IrNode`.

---

## Unknown Node Policy

Every node — including those with `kind == Unknown` — retains its raw tree-sitter kind in `node_type`. The AST walker always descends into `Unknown` nodes; they are never pruned. Analysis passes that need to inspect a specific `Unknown`-mapped construct should:

1. Prefer the language metadata side-table (`cpg.python_metadata`, `cpg.go_metadata`, etc.) where the CPG generator has already extracted the relevant fields.
2. Fall back to `dfg::build_preprocessing_maps`'s `type_index: BTreeMap<String, Vec<NodeId>>` which indexes every node by its raw `node_type` string.

When to add a new `IrNodeKind` variant vs. leave a construct as `Unknown`:

| Situation | Decision |
|---|---|
| Construct creates new CFG branches | Add variant |
| Construct is a DFG source, sink, or kill | Add variant or extract to metadata |
| Transparent container or grouping node | `Unknown` |
| Leaf token or punctuation | `Unknown` |
| Metadata for the parent node only | `Unknown` + extract to language metadata |
