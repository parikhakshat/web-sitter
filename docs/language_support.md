# Language Support

Each language is implemented as a `LanguageLifter` that translates tree-sitter node kinds into `IrNodeKind` values. The CFG, DFG, and call-graph builders then operate uniformly on those IR kinds. Language-specific information that has no IR analog is stored in a per-node metadata side-table appended to `Cpg`.

---

## C

**Lifter:** `CLifter`  
**Grammar:** `tree-sitter-c`  
**Language string:** `"c"`  
**Root node:** `translation_unit` → `File`

C is the base language. All core IR variants were designed around C semantics. The `CLifter` implements the full C grammar mapping with no side-table (C-specific data is embedded directly in `IrNode` fields where possible, or carried in `cpp_metadata` for the fields shared with C++).

Key mappings:
- `function_definition` → `MethodDef`
- `compound_statement` → `Block`
- `declaration` → `LocalDef`
- `if_statement` → `Conditional`
- `while_statement` / `for_statement` / `do_statement` → `Loop` (While / For / DoWhile)
- `call_expression` → `Call`
- `pointer_expression` `*` / `&` → `UnaryOp`

Preprocessor data (`macro_aliases`, `macro_bodies`, `custom_allocators`) is extracted separately via `extract_macros` and merged into `Cpg`.

MSVC structured exception handling: `__try` / `__except` → `Try` (`TryKind::Seh`); `__leave` → `SehLeave`.

---

## C++

**Lifter:** `CppLifter`  
**Grammar:** `tree-sitter-cpp`  
**Language string:** `"cpp"`  
**Root node:** `translation_unit` → `File`

`CppLifter` extends C with class semantics, templates, exceptions, and lambdas. Language-specific data goes into `CppNodeMetadata`.

### `CppNodeMetadata`

| Field | Type | Meaning |
|---|---|---|
| `class_context` | `Option<String>` | Enclosing class name |
| `namespace` | `Option<String>` | Enclosing namespace |
| `visibility` | `Option<String>` | `"public"` / `"protected"` / `"private"` |
| `is_constructor` | `Option<bool>` | Constructor definition |
| `is_destructor` | `Option<bool>` | Destructor definition |
| `is_virtual` | `Option<bool>` | Virtual method declaration |
| `template_params` | `Option<Vec<String>>` | Template parameter names |
| `qualified_name` | `Option<String>` | Fully-qualified name, e.g. `"std::string::append"` |
| `base_classes` | `Option<Vec<String>>` | Base class names for `ClassDef` nodes |
| `template_origin` | `Option<NodeId>` | NodeId of the template this was instantiated from |
| `function_kind` | `FunctionKind` | Internal / ExternalDecl / etc. |
| `inferred_type` | `Option<CType>` | Inferred C/C++ type (literal-level) |
| `is_virtual_dispatch` | `bool` | Call site is a virtual dispatch candidate |

C++ lambdas use `LambdaDef`; they do not create a new `function_id` scope (they share the enclosing function's scope in the C++ model). C++ exceptions use `Try` / `Catch` / `Throw` with `exception_successors` edges in the CFG.

---

## Python

**Lifter:** `PythonLifter`  
**Grammar:** `tree-sitter-python`  
**Language string:** `"python"`  
**Root node:** `module` → `File`

Python has several features that required new `IrNodeKind` variants: generators (`Yield`), async coroutines (`Await`), comprehensions (`Comprehension`), context managers (`With`), walrus operator (`NamedExpr`), collection literals (`CollectionExpr`), import system (`Import`), and binding-scope declarations (`Global`, `Delete`). See [`ir.md`](ir.md) for the full list.

### Scope rules

- `function_definition`, `lambda`, `list_comprehension`, `set_comprehension`, `dictionary_comprehension`, `generator_expression` all introduce a new function scope (`is_function_scope = true`). Comprehensions get their own `function_id`.
- The walrus operator (`:=`) defines the variable in the **innermost non-comprehension scope**, even when written inside a comprehension.
- `global x` and `nonlocal x` redirect DFG defs/uses to the module-level or enclosing-function scope respectively.

### `PythonNodeMetadata`

Selected fields (full list in `lib.rs`):

| Field | Type | Applies to |
|---|---|---|
| `is_async` | `bool` | `MethodDef`, `Loop` (async for), `With` (async with) |
| `is_generator` | `bool` | `MethodDef` containing `yield` |
| `is_staticmethod` / `is_classmethod` / `is_property` / `is_abstract` | `bool` | `MethodDef` |
| `decorators` | `Vec<String>` | `MethodDef`, `ClassDef` |
| `return_annotation` | `Option<String>` | `MethodDef` |
| `closure_vars` | `Vec<String>` | Nested `MethodDef` / `LambdaDef` |
| `annotation` | `Option<String>` | `ParamDef`, `Assign` (annotated) |
| `has_default` | `bool` | `ParamDef` |
| `is_star_param` / `is_double_star_param` | `bool` | `ParamDef` (`*args`, `**kwargs`) |
| `is_keyword_only` / `is_positional_only` | `bool` | `ParamDef` |
| `metaclass` | `Option<String>` | `ClassDef` |
| `is_augmented` | `bool` | `Assign` (`+=`, `-=`, etc.) |
| `is_multi_target` | `bool` | `Assign` (`a = b = c`) |
| `is_tuple_unpack` | `bool` | `Assign` (`a, b = …`) |
| `has_loop_else` | `bool` | `Loop` |
| `has_try_else` / `has_finally` | `bool` | `Try` |
| `exception_type` / `exception_alias` | `Option<String>` | `Catch` |
| `with_alias` | `Option<String>` | `With` item |
| `import_kind` | `ImportKind` | `Import` (Regular / From / Future) |
| `import_module` / `import_names` / `import_aliases` | various | `Import` |
| `import_is_wildcard` / `import_relative_dots` | various | `Import` |
| `global_names` / `global_kind` | various | `Global` (Global / Nonlocal) |
| `comprehension_kind` | `ComprehensionKind` | `Comprehension` (List / Set / Dict / Generator) |
| `collection_kind` | `CollectionKind` | `CollectionExpr` (List / Tuple / Set / Dict) |
| `guard_expr` / `pattern_bindings` / `pattern_is_union` | various | `Case` (match arms) |
| `is_constructor_call` / `is_super_call` / `is_decorator_call` | `bool` | `Call` |
| `is_generator_send` / `is_dunder_call` | `bool` | `Call` |
| `has_star_args` / `has_double_star_args` | `bool` | `Call` |
| `call_receiver_text` | `Option<String>` | `Call` (attribute chain before method) |
| `is_yield_from` | `bool` | `Yield` |
| `is_chained_comparison` | `bool` | `BinaryOp` (`a < b < c`) |
| `resolved_type` | `Option<String>` | Any node (type inference result) |
| `function_kind` | `FunctionKind` | `MethodDef` / `LambdaDef` |

---

## Go

**Lifter:** `GoLifter`  
**Grammar:** `tree-sitter-go`  
**Language string:** `"go"`  
**Root node:** `source_file` → `File`

Go required new variants for goroutines (`GoStmt`), deferred calls (`DeferStmt`), channel operations (`SelectStmt`, `CommCase`, `SendStmt`, `ReceiveExpr`), short variable declarations (`ShortVarDecl`), type assertions (`TypeAssertion`, `TypeSwitch`, `TypeCase`), composite literals (`CompositeLit`), and `fallthrough`.

Key analysis notes:
- Each goroutine launch (`GoStmt`) creates a conceptual new CFG root. The workspace-level analysis must consider concurrent access to shared state.
- `DeferStmt` calls are executed in LIFO order at function exit. The CFG models these as a synthetic call chain before the function exit BB.
- `SelectStmt` is non-deterministic: all `CommCase` arms that are ready can be chosen. The CFG adds a successor edge from the `SelectStmt` to each `CommCase`.
- `ShortVarDecl` (`:=`) defines variables; `Assign` (`=`) does not. Use `ShortVarDecl` to find all binding sites.

### `GoNodeMetadata`

| Field | Type | Applies to |
|---|---|---|
| `package_name` | `Option<String>` | `File` |
| `receiver_type` | `Option<String>` | `MethodDef` (method declaration) |
| `receiver_name` | `Option<String>` | `MethodDef` |
| `is_exported` | `bool` | `MethodDef`, `FieldDef`, `ClassDef` (uppercase first char) |
| `is_variadic` | `bool` | `ParamDef` (`...T`) |
| `channel_direction` | `Option<ChannelDirection>` | `TypeRef` for channel types |
| `is_interface` | `bool` | `ClassDef` (interface type) |
| `is_alias` | `bool` | `TypeAlias` (`type X = Y`) |
| `is_const` | `bool` | `LocalDef` from `const_spec` |
| `is_closure` | `bool` | `LambdaDef` (`func` literal) |
| `is_goroutine` | `bool` | Call inside `GoStmt` |
| `is_deferred` | `bool` | Call inside `DeferStmt` |
| `is_init` | `bool` | `MethodDef` for `init()` functions |
| `generic_type_params` | `Option<Vec<String>>` | Generic type parameters |
| `embedded_interfaces` | `Option<Vec<String>>` | Embedded interface names in `ClassDef` |
| `qualified_name` | `Option<String>` | `"package.Function"` or `"package.Receiver.Method"` |
| `is_imaginary` | `bool` | `Literal` for complex imaginary part |
| `function_kind` | `FunctionKind` | `MethodDef` |
| `inferred_type` | `Option<GoType>` | Any node (Go type inference) |

---

## Java

**Lifter:** `JavaLifter`  
**Grammar:** `tree-sitter-java`  
**Language string:** `"java"`  
**Root node:** `program` → `File`

Java introduced `EnumDef`, `EnumConstant`, `SwitchExpr`, `SwitchRule`, `Finally`, `Synchronized`, `Assert`, `InstanceofExpr`, `MethodRef`, `NewArray`, `ArrayInit`, `Import`, `ModuleDecl`, `StringTemplate`, `ClassLiteral`, `ThisExpr`, and the `TryKind::WithResources` sub-kind.

Key analysis notes:
- `SwitchExpr` produces a value; `Switch` does not. Treat `SwitchExpr` as an expression node in DFG.
- `Yield` inside a `SwitchExpr` arm is a value return from the switch arm, not a generator yield.
- `try-with-resources`: the resource variable is automatically closed at block exit; model a synthetic `Call` to `close()` on the resource at normal and exception exits.
- `InstanceofExpr` with a pattern form (`x instanceof T name`) introduces a variable binding — create a `DataflowDef` for `name`.
- Lambda expressions (`LambdaDef`) use inferred functional interface types; call-graph edges to lambdas must track the functional interface implementation.

### `JavaNodeMetadata`

| Field | Type | Applies to |
|---|---|---|
| `package_name` | `Option<String>` | `File`, `ClassDef` |
| `fully_qualified_class` | `Option<String>` | `ClassDef` |
| `enclosing_class` | `Option<String>` | Nested `ClassDef`, `MethodDef` |
| `is_interface` / `is_enum` / `is_record` / `is_annotation_type` | `bool` | `ClassDef` / `EnumDef` |
| `is_abstract` / `is_final` / `is_sealed` | `bool` | `ClassDef`, `MethodDef` |
| `is_anonymous` / `is_local_class` | `bool` | `ClassDef` |
| `extends_type` | `Option<String>` | `ClassDef` |
| `implements_types` | `Vec<String>` | `ClassDef` |
| `permitted_subtypes` | `Vec<String>` | Sealed `ClassDef` |
| `generic_type_params` | `Vec<String>` | `ClassDef`, `MethodDef` |
| `access_modifiers` | `Vec<String>` | `ClassDef`, `MethodDef`, `FieldDef` |
| `is_static` / `is_synchronized` / `is_native` | `bool` | `MethodDef` |
| `is_default_method` | `bool` | Interface `MethodDef` |
| `is_static_initializer` / `is_instance_initializer` | `bool` | `MethodDef` |
| `throws_types` | `Vec<String>` | `MethodDef` |
| `has_finally` | `bool` | `Try` |
| `annotations` | `Vec<String>` | `ClassDef`, `MethodDef`, `FieldDef` |
| `is_this_call` / `is_super_call` | `bool` | `Call` |
| `is_virtual_dispatch` | `bool` | `Call` |
| `is_static_import` | `bool` | `Import` |
| `catch_types` | `Vec<String>` | `Catch` (multi-catch) |
| `label_target` | `Option<String>` | `Break`, `Continue` |
| `is_varargs` / `is_postfix` | `bool` | `ParamDef`, `UnaryOp` |
| `function_kind` | `FunctionKind` | `MethodDef` |
| `inferred_type` | `Option<JavaType>` | Any node |

---

## JavaScript

**Lifter:** `JsLifter`  
**Grammar:** `tree-sitter-javascript`  
**Language string:** `"javascript"`  
**Root node:** `program` → `File`

New IR variants: `AwaitExpr`, `YieldExpr`, `TemplateStr`, `SpreadExpr`, `OptionalChain`, `JsxElement`, `Import`, `Export`, `SequenceExpr`. New `LiteralKind` values: `Regex`, `Template`, `BigInt`.

The `JsLifter` exposes a public free function `lift_js_kind(ts_kind: &str) -> IrNodeKind` that the `TsLifter` delegates to for shared constructs.

Key analysis notes:
- Arrow functions are `MethodDef` with `js_metadata.is_arrow = true`.
- Generator functions have `js_metadata.is_generator = true`; `YieldExpr` nodes are suspension points.
- `TemplateStr` with interpolations — each `${expr}` child is a DFG use.
- `OptionalChain` (`?.`) marks that the member access / call / subscript may short-circuit on null; add a conditional branch edge in the CFG.
- ESM `import` / `export` → `Import` / `Export`; CommonJS `require()` / `module.exports` map to `Call` / `Assign` with no dedicated IR kind.

### `JsNodeMetadata`

| Field | Type | Applies to |
|---|---|---|
| `is_async` | `bool` | `MethodDef` |
| `is_generator` | `bool` | `MethodDef` |
| `is_arrow` | `bool` | `MethodDef` (arrow function) |
| `is_constructor` | `bool` | `MethodDef` class constructor |
| `is_getter` / `is_setter` | `bool` | `MethodDef` accessor |
| `is_static` | `bool` | `MethodDef`, `FieldDef` |
| `is_private` | `bool` | `MethodDef`, `FieldDef` (`#name`) |
| `is_delegate` | `bool` | `YieldExpr` (`yield*`) |
| `module_kind` | `Option<String>` | `File` (`"esm"` / `"commonjs"`) |
| `scope_kind` | `Option<String>` | Variable declarations (`"let"` / `"const"` / `"var"`) |
| `class_context` | `Option<String>` | `MethodDef` inside a class |
| `decorator_names` | `Vec<String>` | `MethodDef`, `ClassDef` (TC39 decorators) |
| `export_kind` | `Option<String>` | `Export` (`"named"` / `"default"` / `"namespace"`) |
| `import_source` | `Option<String>` | `Import` (module specifier string) |
| `is_for_of` | `bool` | `Loop` (`for … of`) |
| `inferred_type` | `Option<JsType>` | Any node |

---

## TypeScript

**Lifter:** `TsLifter`  
**Grammar:** `tree-sitter-typescript`  
**Language string:** `"typescript"`  
**Root node:** `program` → `File`

`TsLifter` delegates all shared JavaScript constructs to the `lift_js_kind` free function and handles TypeScript-specific node types on top. New IR variants: `InterfaceDecl`, `EnumDecl`, `AsExpr`, `NonNullExpr`, `SatisfiesExpr`, `AmbientDecl`, `TypePredicate`.

Key analysis notes:
- TypeScript `interface` → `InterfaceDecl` (not `ClassDef`), because interfaces have no runtime representation and are erased.
- TypeScript `enum` → `EnumDecl`; members are `EnumConstant` (shared Java variant).
- `as` expressions (`AsExpr`) have no runtime effect but affect type inference.
- `declare` blocks (`AmbientDecl`) are type-only and should not generate DFG/CFG edges.
- Generic type parameters are collected in `TsNodeMetadata.generic_constraints`.

### `TsNodeMetadata`

| Field | Type | Applies to |
|---|---|---|
| `is_async` | `bool` | `MethodDef` |
| `is_abstract` | `bool` | `ClassDef`, `MethodDef` |
| `is_readonly` | `bool` | `FieldDef`, `ParamDef` |
| `is_optional` | `bool` | `FieldDef`, `ParamDef` |
| `is_definite_assignment` | `bool` | `FieldDef` (`x!: T`) |
| `is_ambient` / `is_declare` | `bool` | `AmbientDecl` |
| `is_override` | `bool` | `MethodDef` |
| `is_using` | `bool` | `LocalDef` (`using` / `await using`) |
| `enum_is_const` | `bool` | `EnumDecl` |
| `module_is_namespace` | `bool` | `Namespace` (`namespace` vs `module`) |
| `access_modifier` | `Option<String>` | `MethodDef`, `FieldDef`, `ParamDef` |
| `type_annotation` | `Option<String>` | Any typed node |
| `generic_constraints` | `Vec<(String, Option<String>)>` | `ClassDef`, `MethodDef` type params |
| `implements_types` | `Vec<String>` | `ClassDef` |
| `extends_type` | `Option<String>` | `ClassDef`, `InterfaceDecl` |
| `satisfies_type` | `Option<String>` | `SatisfiesExpr` |
| `type_arguments` | `Vec<String>` | `Call`, `NewExpr` with type args |
| `decorator_names` | `Vec<String>` | `ClassDef`, `MethodDef` |
| `resolved_type` | `Option<TsType>` | Any node (type inference) |

---

## Rust

**Lifter:** `RustLifter`  
**Grammar:** `tree-sitter-rust`  
**Language string:** `"rust"`  
**Root node:** `source_file` → `File`

Rust required new variants for its distinct constructs: `MatchExpr`, `MatchArm`, `ImplBlock`, `TraitDef`, `UnsafeBlock`, `ClosureExpr`, `MacroInvocation`, `TryExpr`, `LoopExpr`, `RangeExpr`, `StructExpr`, `ModDef`, `BreakExpr`, `LifetimeRef`, `UseDecl`.

Key analysis notes:
- `TryExpr` (`expr?`) desugars to an early-return `if is_err { return Err(…) }`. The CFG must add two successor edges from every `TryExpr`: a normal-path edge and an early-return edge to the function exit BB.
- `ClosureExpr` captures: if `move` is present (`is_move_closure = true`), all captured bindings are moved; otherwise they may be borrowed. The DFG ownership pass tracks `OwnershipState` transitions.
- `UnsafeBlock` nodes are annotated so security analysis can flag unsafe regions without false positives on safe Rust code.
- `MacroInvocation` generates synthetic call-graph edges for well-known macros (`vec!`, `println!`, etc.) and otherwise is treated as an opaque call.
- `LoopExpr` is an expression that returns a value via `break value`. The CFG has a back-edge from the loop body to the loop header, and `BreakExpr` nodes jump to the loop's exit BB carrying a value.

### `RustNodeMetadata`

| Field | Type | Applies to |
|---|---|---|
| `visibility` | `Option<String>` | `MethodDef`, `ClassDef`, `FieldDef`, `ModDef` |
| `is_async` | `bool` | `MethodDef`, `ClosureExpr` |
| `is_unsafe` | `bool` | `MethodDef`, `ImplBlock`, `UnsafeBlock` |
| `is_const` | `bool` | `MethodDef`, `LocalDef` |
| `is_extern` | `bool` | `MethodDef` (`extern fn`) |
| `abi` | `Option<String>` | `MethodDef` (e.g. `"C"`) |
| `is_mut` | `bool` | `LocalDef`, `ParamDef`, `FieldDef` |
| `lifetimes` | `Vec<String>` | `MethodDef`, `ImplBlock`, `ClassDef` |
| `generic_params` | `Vec<String>` | `MethodDef`, `ClassDef`, `ImplBlock` |
| `where_clauses` | `Vec<String>` | `MethodDef`, `ClassDef` |
| `trait_bounds` | `Vec<String>` | Generic params |
| `self_type` | `Option<String>` | `ImplBlock` |
| `trait_type` | `Option<String>` | `ImplBlock` (`impl Trait for Type`) |
| `is_move_closure` | `bool` | `ClosureExpr` |
| `derive_macros` | `Vec<String>` | `ClassDef` (from `#[derive(…)]`) |
| `is_unsafe_context` | `bool` | Any node inside an `UnsafeBlock` |
| `ownership_state` | `Option<OwnershipState>` | Any node (ownership pass) |
| `inferred_type` | `Option<RustType>` | Any node |
| `is_no_std` | `bool` | `File` |
| `use_after_move` | `bool` | `Identifier` flagged by ownership pass |

`OwnershipState` values: `Owned`, `Moved`, `Borrowed`, `BorrowedMut`, `Dropped`.

---

## Type Inference

Each language defines a type enum used by its type inference pass:

| Language | Enum | Notable variants |
|---|---|---|
| C / C++ | `CType` | `Void`, `Int`, `Pointer(Box<CType>)`, `Array { elem, len }`, `Named(String)` |
| Python | `PyType` | `Int`, `Str`, `List(Option<Box<PyType>>)`, `Dict { key, value }`, `Union(Vec<PyType>)`, `Class(String)` |
| Go | `GoType` | `Named(String)`, `Pointer(Box<GoType>)`, `Slice`, `Map`, `Chan { dir, elem }`, `Func`, `Interface` |
| Java | `JavaType` | `Primitive(String)`, `Object(String)`, `Array(Box<JavaType>)`, `Generic { base, args }` |
| JavaScript | `JsType` | `Boolean`, `Number`, `Str`, `Object`, `Array(Option<Box<JsType>>)`, `Function` |
| TypeScript | `TsType` | `Boolean`, `Number`, `Str`, `Union(Vec<TsType>)`, `Tuple`, `Named(String)`, `Generic { name, args }` |
| Rust | `RustType` | `Prim(PrimKind)`, `Ref(Box<RustType>)`, `MutRef`, `Slice`, `Named(String)`, `Trait(String)` |

Inferred types are stored in `XxxNodeMetadata::inferred_type` (typed enum) or `XxxNodeMetadata::resolved_type` (serialized string for Python's interprocedural case). Type inference passes run after `build_dataflow` and are gated by `GraphBuildOptions`.

---

## Adding a New Language

1. Implement `LanguageLifter` for the new language in `lifter.rs`.
2. Add the language to `SourceLanguage` in `cpg_generator.rs` and wire it into `CpgGenerator::new_for_language`.
3. Add any new `IrNodeKind` variants to the end of the enum in `lib.rs` (never insert between existing variants — bincode discriminants are positional).
4. Add a `XxxNodeMetadata` struct and a corresponding `BTreeMap<NodeId, XxxNodeMetadata>` field at the end of `Cpg`. Add `xxx_meta` / `xxx_meta_mut` accessor methods.
5. Bump `CACHE_FORMAT_VERSION` in `incremental.rs`.
6. Add integration tests in `tests/xxx_grammar_coverage.rs`.
