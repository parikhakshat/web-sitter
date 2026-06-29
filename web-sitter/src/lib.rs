use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

pub mod function_summary;
pub mod security_patterns;

pub use function_summary::{FunctionSummary, ParamEffect};

pub type NodeId = u32;

// ── IR node kind taxonomy ──────────────────────────────────────────────────────

/// Primary IR node classification, independent of tree-sitter node kind strings.
/// Algorithms dispatch on this enum; `IrNode::node_type` retains the raw
/// tree-sitter kind as a debug/escape-hatch field.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IrNodeKind {
    // ── Structural ─────────────────────────────────────────────────────────
    File,
    Namespace,
    ClassDef,   // class / struct / union / interface type definition
    MethodDef,  // function / method / lambda definition
    // ── Declarations ───────────────────────────────────────────────────────
    ParamDef,
    LocalDef,  // local variable declaration
    FieldDef,
    TypeAlias, // typedef / type alias / using
    // ── Statements ─────────────────────────────────────────────────────────
    Block,       // compound statement / block
    Return,
    Loop,        // discriminated by `loop_kind` field
    Conditional, // if / else if
    Switch,
    Case,
    SwitchDefault,
    Break,
    Continue,
    Goto,
    Label,
    Throw,
    Try,      // discriminated by `try_kind` field
    Catch,
    ExprStmt, // bare expression-as-statement wrapper
    // ── Expressions ────────────────────────────────────────────────────────
    Call,        // free-function or method call
    Assign,
    BinaryOp,   // operator stored in `operator` field
    UnaryOp,
    TernaryOp,
    Cast,
    Subscript,    // a[i]
    MemberAccess, // a.b or a->b (non-call)
    LambdaDef,    // anonymous function expression
    NewExpr,      // C++ new / heap allocation
    DeleteExpr,   // C++ delete / deallocation
    SizeofExpr,
    // ── Leaves ─────────────────────────────────────────────────────────────
    Identifier,
    Literal, // discriminated by `lit_kind` field
    TypeRef, // reference to a type name
    // ── Escape hatch ───────────────────────────────────────────────────────
    #[default]
    Unknown, // unmapped tree-sitter node; `node_type` retains the raw kind

    // ── Python ─────────────────────────────────────────────────────────────
    Import,        // import / from-import / future-import (Python, Java, JS)
    Yield,         // generator yield (Python) or switch-expr yield (Java)
    Await,         // async suspension point (Python)
    Comprehension, // list/set/dict comprehension or generator expr (Python)
    With,          // context manager `with` statement (Python)
    Assert,        // assert statement (Python, Java)
    Delete,        // del statement (Python)
    Global,        // global / nonlocal declaration (Python)
    Decorator,     // decorator expression (Python)
    NamedExpr,     // walrus operator `:=` (Python)
    CollectionExpr, // list/tuple/set/dict literal (Python)

    // ── Go ─────────────────────────────────────────────────────────────────
    GoStmt,        // `go expr` goroutine launch
    DeferStmt,     // `defer expr`
    SelectStmt,    // multi-way channel `select`
    CommCase,      // one arm of a `select`
    SendStmt,      // `ch <- v`
    ReceiveExpr,   // `<-ch`
    ShortVarDecl,  // `:=` short variable declaration
    IncDecStmt,    // `x++` / `x--` statement
    TypeAssertion, // `i.(T)` type assertion
    TypeSwitch,    // `switch v := i.(type)`
    TypeCase,      // one arm of a type switch
    CompositeLit,  // `T{...}` composite literal
    Fallthrough,   // `fallthrough` statement

    // ── Java ───────────────────────────────────────────────────────────────
    EnumDef,       // enum declaration
    EnumConstant,  // named constant inside an enum
    SwitchExpr,    // value-producing switch expression (Java 14+)
    SwitchRule,    // arrow arm `case X -> expr` in switch
    Finally,       // finally clause
    Synchronized,  // synchronized block
    InstanceofExpr, // `x instanceof T` or pattern form
    MethodRef,     // `Class::method` method reference
    NewArray,      // `new T[n]`
    ArrayInit,     // `{1,2,3}` array initializer
    ModuleDecl,    // `module com.example { }`
    StringTemplate, // `STR."..."` template expression
    ClassLiteral,  // `Foo.class`
    ThisExpr,      // `this` or `super` as expression

    // ── JavaScript ─────────────────────────────────────────────────────────
    AwaitExpr,     // `await expr` (JS/Rust)
    YieldExpr,     // `yield expr` / `yield*` (JS)
    TemplateStr,   // backtick template literal
    SpreadExpr,    // `...expr`
    OptionalChain, // `?.` optional chain
    JsxElement,    // JSX element
    Export,        // ESM export statement
    SequenceExpr,  // `(a, b, c)` comma expression

    // ── TypeScript ─────────────────────────────────────────────────────────
    InterfaceDecl, // TypeScript interface
    EnumDecl,      // TypeScript enum
    AsExpr,        // `expr as T` type assertion
    NonNullExpr,   // `x!` non-null assertion
    SatisfiesExpr, // `expr satisfies T`
    AmbientDecl,   // `declare ...` ambient declaration
    TypePredicate, // `x is T` return type predicate

    // ── Rust ───────────────────────────────────────────────────────────────
    MatchExpr,      // `match expr { ... }`
    MatchArm,       // one arm of a match
    ImplBlock,      // `impl Type` or `impl Trait for Type`
    TraitDef,       // trait definition
    UnsafeBlock,    // `unsafe { ... }`
    ClosureExpr,    // closure `|x| expr`
    MacroInvocation, // `macro!(...)` invocation
    TryExpr,        // `expr?` try operator
    LoopExpr,       // `loop { }` infinite loop expression
    RangeExpr,      // `a..b`, `a..=b`, etc.
    StructExpr,     // struct literal `Foo { a: x }`
    ModDef,         // module definition
    BreakExpr,      // `break value` (Rust break carries a value)
    LifetimeRef,    // lifetime annotation `'a`
    UseDecl,        // `use` declaration

    // ── C/C++ SEH ──────────────────────────────────────────────────────────
    SehLeave,       // `__leave` statement inside a SEH __try block
}

impl IrNodeKind {
    pub fn is_statement(self) -> bool {
        matches!(
            self,
            Self::Block
                | Self::Return
                | Self::Loop
                | Self::Conditional
                | Self::Switch
                | Self::Case
                | Self::SwitchDefault
                | Self::Break
                | Self::Continue
                | Self::Goto
                | Self::Label
                | Self::Throw
                | Self::Try
                | Self::Catch
                | Self::ExprStmt
                // Python
                | Self::Import
                | Self::With
                | Self::Assert
                | Self::Delete
                | Self::Global
                // Go
                | Self::GoStmt
                | Self::DeferStmt
                | Self::SelectStmt
                | Self::SendStmt
                | Self::ShortVarDecl
                | Self::IncDecStmt
                | Self::Fallthrough
                | Self::TypeSwitch
                // Java
                | Self::Synchronized
                | Self::Finally
                // Rust
                | Self::UseDecl
                | Self::ModDef
                // C/C++ SEH
                | Self::SehLeave
        )
    }

    pub fn is_expression(self) -> bool {
        matches!(
            self,
            Self::Call
                | Self::Assign
                | Self::BinaryOp
                | Self::UnaryOp
                | Self::TernaryOp
                | Self::Cast
                | Self::Subscript
                | Self::MemberAccess
                | Self::LambdaDef
                | Self::NewExpr
                | Self::DeleteExpr
                | Self::SizeofExpr
                | Self::Identifier
                | Self::Literal
                | Self::TypeRef
                // Python
                | Self::Yield
                | Self::Await
                | Self::Comprehension
                | Self::NamedExpr
                | Self::CollectionExpr
                // Go
                | Self::ReceiveExpr
                | Self::TypeAssertion
                | Self::CompositeLit
                // Java
                | Self::SwitchExpr
                | Self::InstanceofExpr
                | Self::MethodRef
                | Self::NewArray
                | Self::ArrayInit
                | Self::ClassLiteral
                | Self::ThisExpr
                // JavaScript
                | Self::AwaitExpr
                | Self::YieldExpr
                | Self::TemplateStr
                | Self::SpreadExpr
                | Self::OptionalChain
                | Self::JsxElement
                | Self::SequenceExpr
                // TypeScript
                | Self::AsExpr
                | Self::NonNullExpr
                | Self::SatisfiesExpr
                // Rust
                | Self::MatchExpr
                | Self::ClosureExpr
                | Self::TryExpr
                | Self::LoopExpr
                | Self::RangeExpr
                | Self::StructExpr
                | Self::BreakExpr
        )
    }
}

/// Distinguishes loop variant for `IrNodeKind::Loop` nodes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoopKind {
    #[default]
    While,
    For,
    DoWhile,
    ForEach,
}

/// Distinguishes try-block variant for `IrNodeKind::Try` nodes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TryKind {
    #[default]
    Standard,
    Seh,          // MSVC __try / __except
    WithResources, // Java try-with-resources
}

/// Distinguishes literal variant for `IrNodeKind::Literal` nodes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiteralKind {
    #[default]
    Integer,
    Float,
    String,
    Char,
    Bool,
    Null,
    Bytes,    // Python b"..." byte string
    Ellipsis, // Python `...`
    Regex,    // JavaScript /pattern/flags
    Template, // JavaScript template literal (no substitutions)
    BigInt,   // JavaScript 42n
}

// ──────────────────────────────────────────────────────────────────────────────

/// Classifies whether a function's definition is known and where it lives.
/// Used in `CallSite.callee_kind` and `AstNode.function_kind` to make the
/// internal/external distinction explicit throughout the analysis pipeline.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FunctionKind {
    /// Definition is in this CPG (function_definition node present).
    #[default]
    Internal,
    /// Definition exists in another file in the same workspace; CPG may not be loaded yet.
    WorkspaceLocal,
    /// Only a function_declarator/declaration exists; body is in a library or not found.
    ExternalDecl,
    /// Known only from taint config or symbol DB; no source node at all.
    LibrarySymbol,
}

impl FunctionKind {
    /// True when the function body is available for analysis (either in this CPG or
    /// will be available from the workspace).
    pub fn is_analyzable(self) -> bool {
        matches!(self, Self::Internal | Self::WorkspaceLocal)
    }
    /// True when the function comes from a library and has no source body.
    pub fn is_external(self) -> bool {
        matches!(self, Self::ExternalDecl | Self::LibrarySymbol)
    }
}

// ── Python sub-kind enums ─────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GlobalKind {
    #[default]
    Global,
    Nonlocal,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportKind {
    #[default]
    Regular,
    From,
    Future,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComprehensionKind {
    #[default]
    List,
    Set,
    Dict,
    Generator,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionKind {
    #[default]
    List,
    Tuple,
    Set,
    Dict,
}

// ── Go sub-kind enums ─────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelDirection {
    Send,
    Recv,
    #[default]
    Bidi,
}

// ── Rust sub-kind enums / type representations ────────────────────────────────

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnershipState {
    #[default]
    Owned,
    Moved,
    Borrowed,
    BorrowedMut,
    Dropped,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrimKind {
    I8, I16, #[default] I32, I64, I128, Isize,
    U8, U16, U32, U64, U128, Usize,
    F32, F64,
    Bool, Char, Str,
}

// ── Go type system ────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoType {
    Named(String),
    Pointer(Box<GoType>),
    Slice(Box<GoType>),
    Array { len: Option<u64>, elem: Box<GoType> },
    Map { key: Box<GoType>, value: Box<GoType> },
    Chan { dir: ChannelDirection, elem: Box<GoType> },
    Func { params: Vec<GoType>, returns: Vec<GoType> },
    Interface(Vec<String>),
    Tuple(Vec<GoType>),
    Generic { name: String, args: Vec<GoType> },
    #[default]
    Unknown,
}

// ── Python type system ────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PyType {
    #[default]
    Unknown,
    None_,
    Bool,
    Int,
    Float,
    Complex,
    Str,
    Bytes,
    List(Option<Box<PyType>>),
    Dict { key: Option<Box<PyType>>, value: Option<Box<PyType>> },
    Set(Option<Box<PyType>>),
    Tuple(Vec<PyType>),
    Generator(Box<PyType>),
    Coroutine(Box<PyType>),
    Class(String),
    Function,
    Module(String),
    Optional(Box<PyType>),
    Union(Vec<PyType>),
}

// ── Java type system ──────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JavaType {
    Primitive(String),
    Object(String),
    Array(Box<JavaType>),
    Generic { base: String, args: Vec<JavaType> },
    Void,
    Null,
    #[default]
    Unknown,
}

// ── JavaScript type system ────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JsType {
    Undefined,
    Null,
    Boolean,
    Number,
    BigInt,
    Str,
    Symbol,
    Object,
    Array(Option<Box<JsType>>),
    Function,
    Any,
    #[default]
    Unknown,
}

// ── TypeScript type system ────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TsType {
    Any,
    Unknown_,
    Never,
    Void,
    Undefined,
    Null,
    Boolean,
    Number,
    BigInt,
    Str,
    Symbol,
    Object,
    Array(Option<Box<TsType>>),
    Tuple(Vec<TsType>),
    Union(Vec<TsType>),
    Intersection(Vec<TsType>),
    Function { params: Vec<TsType>, ret: Box<TsType> },
    Literal(String),
    Conditional,
    Mapped,
    Named(String),
    Generic { name: String, args: Vec<TsType> },
    #[default]
    Inferred,
}

// ── Rust type system ──────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RustType {
    Prim(PrimKind),
    Ref(Box<RustType>),
    MutRef(Box<RustType>),
    Slice(Box<RustType>),
    Array { elem: Box<RustType>, len: Option<u64> },
    Str,
    Named(String),
    Generic { name: String, args: Vec<RustType> },
    Tuple(Vec<RustType>),
    Function { params: Vec<RustType>, ret: Box<RustType> },
    Trait(String),
    Opaque(String),
    #[default]
    Unknown,
}

// ── C / C++ type enum ─────────────────────────────────────────────────────────

/// Inferred type for a C or C++ AST node (literal-level precision only).
/// Pointer/array variants carry their element type for future-pass enrichment.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CType {
    Void,
    Bool,       // C99 _Bool / C++ bool
    Char,
    SChar,
    UChar,
    Short,
    UShort,
    Int,
    UInt,
    Long,
    ULong,
    LongLong,
    ULongLong,
    Float,
    Double,
    LongDouble,
    NullptrT,   // C++ nullptr
    Pointer(Box<CType>),
    Array { elem: Box<CType>, len: Option<u64> },
    Named(String), // struct / union / enum / typedef name
    #[default]
    Unknown,
}

/// A call to a function whose definition lives in a different source file.
/// Collected during per-file CPG construction; resolved by the workspace layer
/// into cross-file INTERPROCEDURAL_FLOW edges after all CPGs are built.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossFileCallEdge {
    /// NodeId of the call_expression in the caller's CPG.
    pub call_node: NodeId,
    /// NodeId of the enclosing function_definition in the caller's CPG.
    pub caller_fn: NodeId,
    /// Callee simple name (unqualified).
    pub callee_name: String,
    /// Fully-qualified callee name if available (C++).
    #[serde(default)]
    pub qualified_callee: Option<String>,
    /// Argument positions passed at this call site (0-based).
    #[serde(default)]
    pub arg_positions: Vec<usize>,
}

/// A unified IR node that represents one node in the Code Property Graph.
///
/// Every node carries both its raw tree-sitter kind (`node_type`) — preserved
/// as an escape hatch and for debugging — and a language-agnostic `kind`
/// classification set by the `LanguageLifter` during CPG construction.
/// Analysis algorithms should dispatch on `kind` (enum) rather than on the raw
/// `node_type` string; the lifter is responsible for populating `kind` correctly
/// for each supported language.
///
/// NOTE: No `skip_serializing_if` on any field — bincode requires every field
/// to be written in declaration order for a correct binary round-trip.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrNode {
    // ── IR classification (set by LanguageLifter) ─────────────────────────
    /// Language-agnostic IR kind. Algorithms dispatch on this.
    #[serde(default)]
    pub kind: IrNodeKind,
    /// Sub-kind for `Loop` nodes (For / While / DoWhile / ForEach).
    #[serde(default)]
    pub loop_kind: Option<LoopKind>,
    /// Sub-kind for `Try` nodes (Standard C++ try vs MSVC SEH __try).
    #[serde(default)]
    pub try_kind: Option<TryKind>,
    /// Sub-kind for `Literal` nodes.
    #[serde(default)]
    pub lit_kind: Option<LiteralKind>,
    // ── Raw tree-sitter kind (escape hatch / debug) ────────────────────────
    /// Original tree-sitter node kind string (e.g. "function_definition").
    /// Kept for legacy callers during migration and as a debug aid.
    /// New code should use `kind` instead.
    #[serde(rename = "type")]
    pub node_type: String,
    // ── Declared name / signature ──────────────────────────────────────────
    /// Canonical declared name for named nodes (MethodDef, ClassDef, LocalDef,
    /// ParamDef, FieldDef, Namespace). Not set for anonymous / expression nodes.
    #[serde(default)]
    pub name: Option<String>,
    /// Full signature string for MethodDef nodes (return type + params).
    #[serde(default)]
    pub signature: Option<String>,
    // ── Source text ────────────────────────────────────────────────────────
    pub text: Option<String>,
    // ── Graph structure ────────────────────────────────────────────────────
    pub children: Vec<NodeId>,
    pub field_names: Vec<Option<String>>,
    pub parent_id: Option<NodeId>,
    pub function_id: Option<NodeId>,
    pub basic_block: Option<String>,
    // ── Position ──────────────────────────────────────────────────────────
    pub line: u32,
    pub column: u32,
    pub end_line: u32,
    pub end_column: u32,
    #[serde(default)]
    pub start_byte: Option<u32>,
    #[serde(default)]
    pub end_byte: Option<u32>,
    // ── Semantic annotations ───────────────────────────────────────────────
    pub string_length: Option<u32>,
    pub array_size: Option<i64>,
    pub array_size_expr: Option<String>,
    pub operator: Option<String>,
    pub argument_count: Option<u32>,
    // ── OOP / language-specific metadata ──────────────────────────────────
    // All Optional so C analysis pays no per-node overhead.
    /// Enclosing class name for methods/nested types (C++, Java, etc.).
    #[serde(default)]
    pub class_context: Option<String>,
    /// Enclosing namespace for functions/types (C++, Java, etc.).
    #[serde(default)]
    pub namespace: Option<String>,
    /// Access specifier: "public" | "protected" | "private".
    #[serde(default)]
    pub visibility: Option<String>,
    /// True when this MethodDef is a constructor.
    #[serde(default)]
    pub is_constructor: Option<bool>,
    /// True when this MethodDef is a destructor.
    #[serde(default)]
    pub is_destructor: Option<bool>,
    /// True when this method is declared virtual.
    #[serde(default)]
    pub is_virtual: Option<bool>,
    /// Template parameter names, e.g. ["T", "Alloc"] (C++ only).
    #[serde(default)]
    pub template_params: Option<Vec<String>>,
    /// Fully-qualified name, e.g. "std::string::append".
    #[serde(default)]
    pub qualified_name: Option<String>,
    /// Base class names (for ClassDef nodes).
    #[serde(default)]
    pub base_classes: Option<Vec<String>>,
}

impl IrNode {
    // ── Convenience predicates (avoid `node_type` string comparisons) ──────

    pub fn is_method_def(&self) -> bool {
        self.kind == IrNodeKind::MethodDef
    }
    pub fn is_call(&self) -> bool {
        matches!(self.kind, IrNodeKind::Call | IrNodeKind::NewExpr | IrNodeKind::MacroInvocation)
    }
    pub fn is_assign(&self) -> bool {
        self.kind == IrNodeKind::Assign
    }
    pub fn is_identifier(&self) -> bool {
        self.kind == IrNodeKind::Identifier
    }
    pub fn is_literal(&self) -> bool {
        self.kind == IrNodeKind::Literal
    }
    pub fn is_loop(&self) -> bool {
        self.kind == IrNodeKind::Loop
    }
    pub fn is_conditional(&self) -> bool {
        self.kind == IrNodeKind::Conditional
    }
    pub fn is_switch(&self) -> bool {
        self.kind == IrNodeKind::Switch
    }
    pub fn is_block(&self) -> bool {
        self.kind == IrNodeKind::Block
    }
    pub fn is_return(&self) -> bool {
        self.kind == IrNodeKind::Return
    }
    pub fn is_class_def(&self) -> bool {
        self.kind == IrNodeKind::ClassDef
    }
    pub fn is_namespace(&self) -> bool {
        self.kind == IrNodeKind::Namespace
    }
    pub fn is_param_def(&self) -> bool {
        self.kind == IrNodeKind::ParamDef
    }
    pub fn is_local_def(&self) -> bool {
        self.kind == IrNodeKind::LocalDef
    }
    pub fn is_field_def(&self) -> bool {
        self.kind == IrNodeKind::FieldDef
    }
    pub fn is_type_alias(&self) -> bool {
        self.kind == IrNodeKind::TypeAlias
    }
    pub fn is_cast(&self) -> bool {
        self.kind == IrNodeKind::Cast
    }
    pub fn is_subscript(&self) -> bool {
        self.kind == IrNodeKind::Subscript
    }
    pub fn is_member_access(&self) -> bool {
        self.kind == IrNodeKind::MemberAccess
    }
    pub fn is_throw(&self) -> bool {
        self.kind == IrNodeKind::Throw
    }
    pub fn is_try(&self) -> bool {
        self.kind == IrNodeKind::Try
    }
    pub fn is_catch(&self) -> bool {
        self.kind == IrNodeKind::Catch
    }
    pub fn is_break(&self) -> bool {
        self.kind == IrNodeKind::Break
    }
    pub fn is_continue(&self) -> bool {
        self.kind == IrNodeKind::Continue
    }
    pub fn is_goto(&self) -> bool {
        self.kind == IrNodeKind::Goto
    }
    pub fn is_label(&self) -> bool {
        self.kind == IrNodeKind::Label
    }
    pub fn is_binary_op(&self) -> bool {
        self.kind == IrNodeKind::BinaryOp
    }
    pub fn is_unary_op(&self) -> bool {
        self.kind == IrNodeKind::UnaryOp
    }
    pub fn is_lambda_def(&self) -> bool {
        self.kind == IrNodeKind::LambdaDef
    }
    pub fn is_new_expr(&self) -> bool {
        self.kind == IrNodeKind::NewExpr
    }
    pub fn is_delete_expr(&self) -> bool {
        self.kind == IrNodeKind::DeleteExpr
    }
    pub fn is_sizeof_expr(&self) -> bool {
        self.kind == IrNodeKind::SizeofExpr
    }
    pub fn is_type_ref(&self) -> bool {
        self.kind == IrNodeKind::TypeRef
    }

    /// True if `kind` is still `Unknown` — the lifter has not classified this node.
    pub fn is_unknown(&self) -> bool {
        self.kind == IrNodeKind::Unknown
    }
    pub fn is_parenthesized(&self) -> bool {
        self.node_type == "parenthesized_expression"
    }
    pub fn is_seh_leave(&self) -> bool {
        self.kind == IrNodeKind::SehLeave
    }
}

/// Backward-compatible alias: existing code written against `AstNode` continues
/// to compile unchanged. Migrate call-sites to `IrNode` over time.
pub type AstNode = IrNode;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasicBlock {
    #[serde(rename = "type")]
    pub block_type: String,
    pub nodes: Vec<NodeId>,
    pub successors: Vec<String>,
    /// Successors reachable only via exception propagation (EXCEPTION_FLOW edges).
    /// These are catch-block landing-pad basic block IDs (C++ only).
    #[serde(default)]
    pub exception_successors: Vec<String>,
    pub function: NodeId,
    /// True when this block contains a `setjmp`/`sigsetjmp` call.  Used by the
    /// CFG builder to add non-local jump edges from `longjmp` call sites.
    #[serde(default)]
    pub is_setjmp_target: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallSite {
    pub callee: String,
    /// NodeId of the callee's function_definition in the current CPG, if present.
    pub callee_id: Option<NodeId>,
    pub call_site: Option<u32>,
    /// Fully-qualified callee name for C++ (e.g. "std::string::append").
    /// Same as `callee` for C code.
    #[serde(default)]
    pub qualified_callee: Option<String>,
    /// Where the callee's definition lives; determines analysis strategy.
    #[serde(default)]
    pub callee_kind: FunctionKind,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallGraphEntry {
    pub name: String,
    pub calls: Vec<CallSite>,
    pub called_by: Vec<NodeId>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataflowDef {
    pub node_id: NodeId,
    pub variable: String,
    pub function_id: Option<NodeId>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataflowUse {
    pub node_id: NodeId,
    pub variable: String,
    pub function_id: Option<NodeId>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataflowEdge {
    pub source: NodeId,
    pub destination: NodeId,
    pub variable: String,
    #[serde(rename = "type")]
    pub edge_type: String,
    /// Field path for field-sensitive tracking, e.g. ["buf"] for `ctx.buf`.
    /// Empty vec = field-insensitive (standard behavior).
    #[serde(default)]
    pub field_path: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataflowGraph {
    pub definitions: Vec<DataflowDef>,
    pub uses: Vec<DataflowUse>,
    pub edges: Vec<DataflowEdge>,
}

/// A comment line extracted from the source during CPG generation.
/// Stored separately from the AST so suppression logic can access them
/// without polluting the node graph.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceComment {
    pub line: u32,
    pub text: String,
}

/// Compact AST node representation for CPG subgraph visualization.
/// Field names are single characters to minimize JSON payload size.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpgNodeData {
    pub id: NodeId,
    /// Node type (e.g. "identifier", "call_expression").
    #[serde(rename = "t")]
    pub node_type: String,
    /// Source text of the node (truncated to 60 chars).
    #[serde(skip_serializing_if = "Option::is_none", rename = "x")]
    pub text: Option<String>,
    pub line: u32,
    pub col: u32,
    pub end_line: u32,
    /// Parent node id (None when parent is outside included set).
    #[serde(skip_serializing_if = "Option::is_none", rename = "p")]
    pub parent_id: Option<NodeId>,
}

/// Compact edge for CPG subgraph visualization.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpgEdgeData {
    /// Source node id.
    pub s: NodeId,
    /// Destination node id.
    pub d: NodeId,
    /// Edge kind: "A" = AST parent→child, "D" = DFG dataflow.
    pub k: String,
    /// Variable name (DFG edges only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub v: Option<String>,
}

/// Compact CPG subgraph for a single function, embedded in syntax/composite findings
/// for interactive graph visualization in the editor.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpgSubgraph {
    pub nodes: Vec<CpgNodeData>,
    pub edges: Vec<CpgEdgeData>,
    /// True when the original function had too many nodes and the graph was pruned.
    #[serde(default)]
    pub pruned: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Cpg {
    pub ast: BTreeMap<NodeId, AstNode>,
    #[serde(default)]
    pub basic_blocks: BTreeMap<String, BasicBlock>,
    #[serde(default)]
    pub call_graph: BTreeMap<NodeId, CallGraphEntry>,
    #[serde(default)]
    pub dataflow: DataflowGraph,
    #[serde(default)]
    pub source_file: Option<String>,
    #[serde(default = "default_language")]
    pub language: String,
    /// Source comments collected during parsing, used for suppression directives.
    #[serde(default)]
    pub comments: Vec<SourceComment>,
    /// C/C++ preprocessor metadata: macro aliases, macro bodies, custom allocators.
    /// Empty for all other languages.
    #[serde(default)]
    pub c_file: CFileMetadata,
    /// C++-specific per-node metadata stored in a sparse side-table.
    /// Only function_definition, declaration, and class_specifier nodes have entries.
    /// Kept separate from AstNode to avoid paying ~150 bytes per node on C code.
    #[serde(default)]
    pub cpp_metadata: BTreeMap<NodeId, CppNodeMetadata>,
    #[serde(default)]
    pub go_metadata: BTreeMap<NodeId, GoNodeMetadata>,
    #[serde(default)]
    pub python_metadata: BTreeMap<NodeId, PythonNodeMetadata>,
    #[serde(default)]
    pub java_metadata: BTreeMap<NodeId, JavaNodeMetadata>,
    #[serde(default)]
    pub js_metadata: BTreeMap<NodeId, JsNodeMetadata>,
    #[serde(default)]
    pub ts_metadata: BTreeMap<NodeId, TsNodeMetadata>,
    #[serde(default)]
    pub rust_metadata: BTreeMap<NodeId, RustNodeMetadata>,
    /// Engine-level workspace state produced during single-file analysis but consumed
    /// at the workspace/codebase layer (cross-file edges, hierarchy, summaries).
    #[serde(default)]
    pub workspace: WorkspaceIndex,
}

/// C++-specific metadata for a single AST node, stored in `Cpg::cpp_metadata`.
/// Only populated for function_definition, declaration, and class_specifier nodes.
///
/// NOTE: No `skip_serializing_if` on any field — bincode requires every field
/// to always be written, in declaration order. Skipping a field shifts all
/// subsequent fields and corrupts the binary round-trip.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CppNodeMetadata {
    /// Enclosing class name for methods/nested types.
    #[serde(default)]
    pub class_context: Option<String>,
    /// Enclosing namespace.
    #[serde(default)]
    pub namespace: Option<String>,
    /// Access specifier: "public" | "protected" | "private".
    #[serde(default)]
    pub visibility: Option<String>,
    /// True when this function_definition is a constructor.
    #[serde(default)]
    pub is_constructor: Option<bool>,
    /// True when this function_definition is a destructor.
    #[serde(default)]
    pub is_destructor: Option<bool>,
    /// True when this method is declared virtual.
    #[serde(default)]
    pub is_virtual: Option<bool>,
    /// Template parameter names, e.g. ["T", "Alloc"].
    #[serde(default)]
    pub template_params: Option<Vec<String>>,
    /// Fully-qualified name, e.g. "std::string::append".
    #[serde(default)]
    pub qualified_name: Option<String>,
    /// Base class names (for class_specifier nodes).
    #[serde(default)]
    pub base_classes: Option<Vec<String>>,
    /// True for a template instantiation; template_origin is the template NodeId.
    #[serde(default)]
    pub template_origin: Option<NodeId>,
    /// `FunctionKind` for this definition/declaration node.
    #[serde(default)]
    pub function_kind: FunctionKind,
    /// Inferred C/C++ type for literal nodes (populated by the type-inference pass).
    #[serde(default)]
    pub inferred_type: Option<CType>,
    /// True when this call site is a virtual dispatch candidate (set by call-graph enrichment).
    #[serde(default)]
    pub is_virtual_dispatch: bool,
}

// ── Go per-node metadata ──────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct GoNodeMetadata {
    #[serde(default)] pub package_name: Option<String>,
    #[serde(default)] pub receiver_type: Option<String>,
    #[serde(default)] pub receiver_name: Option<String>,
    #[serde(default)] pub is_exported: bool,
    #[serde(default)] pub is_variadic: bool,
    #[serde(default)] pub channel_direction: Option<ChannelDirection>,
    #[serde(default)] pub is_interface: bool,
    #[serde(default)] pub is_alias: bool,
    #[serde(default)] pub is_const: bool,
    #[serde(default)] pub is_closure: bool,
    #[serde(default)] pub is_goroutine: bool,
    #[serde(default)] pub is_deferred: bool,
    #[serde(default)] pub is_init: bool,
    #[serde(default)] pub generic_type_params: Option<Vec<String>>,
    #[serde(default)] pub embedded_interfaces: Option<Vec<String>>,
    #[serde(default)] pub qualified_name: Option<String>,
    #[serde(default)] pub is_imaginary: bool,
    #[serde(default)] pub function_kind: FunctionKind,
    #[serde(default)] pub inferred_type: Option<GoType>,
}

// ── Python per-node metadata ──────────────────────────────────────────────────

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PythonNodeMetadata {
    // Function / method properties
    #[serde(default)] pub is_async: bool,
    #[serde(default)] pub is_generator: bool,
    #[serde(default)] pub is_staticmethod: bool,
    #[serde(default)] pub is_classmethod: bool,
    #[serde(default)] pub is_property: bool,
    #[serde(default)] pub is_abstract: bool,
    #[serde(default)] pub decorators: Vec<String>,
    #[serde(default)] pub return_annotation: Option<String>,
    #[serde(default)] pub closure_vars: Vec<String>,
    // Parameter properties
    #[serde(default)] pub annotation: Option<String>,
    #[serde(default)] pub has_default: bool,
    #[serde(default)] pub is_star_param: bool,
    #[serde(default)] pub is_double_star_param: bool,
    #[serde(default)] pub is_keyword_only: bool,
    #[serde(default)] pub is_positional_only: bool,
    // Class properties
    #[serde(default)] pub metaclass: Option<String>,
    // Assignment properties
    #[serde(default)] pub is_augmented: bool,
    #[serde(default)] pub is_multi_target: bool,
    #[serde(default)] pub is_annotated: bool,
    #[serde(default)] pub is_tuple_unpack: bool,
    // Loop properties
    #[serde(default)] pub has_loop_else: bool,
    // Try/except properties
    #[serde(default)] pub has_try_else: bool,
    #[serde(default)] pub has_finally: bool,
    // Except clause properties
    #[serde(default)] pub exception_type: Option<String>,
    #[serde(default)] pub exception_alias: Option<String>,
    // With item properties
    #[serde(default)] pub with_alias: Option<String>,
    // Import properties
    #[serde(default)] pub import_kind: ImportKind,
    #[serde(default)] pub import_module: Option<String>,
    #[serde(default)] pub import_names: Vec<String>,
    #[serde(default)] pub import_aliases: Vec<(String, String)>,
    #[serde(default)] pub import_is_wildcard: bool,
    #[serde(default)] pub import_relative_dots: u32,
    #[serde(default)] pub import_original_name: Option<String>,
    // Global / Nonlocal properties
    #[serde(default)] pub global_names: Vec<String>,
    #[serde(default)] pub global_kind: GlobalKind,
    // Comprehension properties
    #[serde(default)] pub comprehension_kind: ComprehensionKind,
    // Collection literal properties
    #[serde(default)] pub collection_kind: CollectionKind,
    // Match / case properties
    #[serde(default)] pub guard_expr: Option<String>,
    #[serde(default)] pub pattern_is_union: bool,
    #[serde(default)] pub pattern_bindings: Vec<String>,
    // Call-site properties
    #[serde(default)] pub is_constructor_call: bool,
    #[serde(default)] pub is_super_call: bool,
    #[serde(default)] pub is_decorator_call: bool,
    #[serde(default)] pub is_generator_send: bool,
    #[serde(default)] pub is_dunder_call: bool,
    #[serde(default)] pub has_star_args: bool,
    #[serde(default)] pub has_double_star_args: bool,
    #[serde(default)] pub call_receiver_text: Option<String>,
    // Yield properties
    #[serde(default)] pub is_yield_from: bool,
    // Comparison properties
    #[serde(default)] pub is_chained_comparison: bool,
    // Type inference
    #[serde(default)] pub resolved_type: Option<String>,
    #[serde(default)] pub type_narrow_condition: Option<String>,
    // Function kind
    #[serde(default)] pub function_kind: FunctionKind,
    #[serde(default)] pub inferred_type: Option<PyType>,
}

// ── Java per-node metadata ────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct JavaNodeMetadata {
    // Package / class identity
    #[serde(default)] pub package_name: Option<String>,
    #[serde(default)] pub fully_qualified_class: Option<String>,
    #[serde(default)] pub enclosing_class: Option<String>,
    // Class-level flags
    #[serde(default)] pub is_interface: bool,
    #[serde(default)] pub is_enum: bool,
    #[serde(default)] pub is_record: bool,
    #[serde(default)] pub is_annotation_type: bool,
    #[serde(default)] pub is_abstract: bool,
    #[serde(default)] pub is_final: bool,
    #[serde(default)] pub is_sealed: bool,
    #[serde(default)] pub is_anonymous: bool,
    #[serde(default)] pub is_local_class: bool,
    // Inheritance / generics
    #[serde(default)] pub extends_type: Option<String>,
    #[serde(default)] pub implements_types: Vec<String>,
    #[serde(default)] pub permitted_subtypes: Vec<String>,
    #[serde(default)] pub generic_type_params: Vec<String>,
    // Access / modifiers
    #[serde(default)] pub access_modifiers: Vec<String>,
    // Method-level flags
    #[serde(default)] pub is_static: bool,
    #[serde(default)] pub is_synchronized: bool,
    #[serde(default)] pub is_native: bool,
    #[serde(default)] pub is_default_method: bool,
    #[serde(default)] pub is_static_initializer: bool,
    #[serde(default)] pub is_instance_initializer: bool,
    #[serde(default)] pub is_compact_constructor: bool,
    // Throws / exceptions
    #[serde(default)] pub throws_types: Vec<String>,
    #[serde(default)] pub has_finally: bool,
    // Annotations
    #[serde(default)] pub annotations: Vec<String>,
    // Call site flags
    #[serde(default)] pub is_this_call: bool,
    #[serde(default)] pub is_super_call: bool,
    #[serde(default)] pub is_virtual_dispatch: bool,
    #[serde(default)] pub is_static_import: bool,
    // Catch / switch specifics
    #[serde(default)] pub catch_types: Vec<String>,
    #[serde(default)] pub label_target: Option<String>,
    // Misc
    #[serde(default)] pub is_varargs: bool,
    #[serde(default)] pub is_postfix: bool,
    #[serde(default)] pub function_kind: FunctionKind,
    #[serde(default)] pub inferred_type: Option<JavaType>,
}

// ── JavaScript per-node metadata ──────────────────────────────────────────────

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct JsNodeMetadata {
    #[serde(default)] pub is_async: bool,
    #[serde(default)] pub is_generator: bool,
    #[serde(default)] pub is_arrow: bool,
    #[serde(default)] pub is_constructor: bool,
    #[serde(default)] pub is_getter: bool,
    #[serde(default)] pub is_setter: bool,
    #[serde(default)] pub is_static: bool,
    #[serde(default)] pub is_private: bool,
    #[serde(default)] pub is_delegate: bool,
    #[serde(default)] pub module_kind: Option<String>,
    #[serde(default)] pub scope_kind: Option<String>,
    #[serde(default)] pub class_context: Option<String>,
    #[serde(default)] pub decorator_names: Vec<String>,
    #[serde(default)] pub export_kind: Option<String>,
    #[serde(default)] pub import_source: Option<String>,
    #[serde(default)] pub is_for_of: bool,
    #[serde(default)] pub inferred_type: Option<JsType>,
}

// ── TypeScript per-node metadata ──────────────────────────────────────────────

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TsNodeMetadata {
    // Modifiers
    #[serde(default)] pub is_async: bool,
    #[serde(default)] pub is_abstract: bool,
    #[serde(default)] pub is_readonly: bool,
    #[serde(default)] pub is_optional: bool,
    #[serde(default)] pub is_definite_assignment: bool,
    #[serde(default)] pub is_ambient: bool,
    #[serde(default)] pub is_declare: bool,
    #[serde(default)] pub is_override: bool,
    #[serde(default)] pub is_using: bool,
    #[serde(default)] pub enum_is_const: bool,
    #[serde(default)] pub module_is_namespace: bool,
    // Access control
    #[serde(default)] pub access_modifier: Option<String>,
    // Type information
    #[serde(default)] pub type_annotation: Option<String>,
    #[serde(default)] pub generic_constraints: Vec<(String, Option<String>)>,
    #[serde(default)] pub implements_types: Vec<String>,
    #[serde(default)] pub extends_type: Option<String>,
    #[serde(default)] pub satisfies_type: Option<String>,
    #[serde(default)] pub type_arguments: Vec<String>,
    // Decorators
    #[serde(default)] pub decorator_names: Vec<String>,
    // Resolved type (placeholder; populated by type inference pass)
    #[serde(default)] pub resolved_type: Option<TsType>,
}

// ── Rust per-node metadata ────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RustNodeMetadata {
    // Access control
    #[serde(default)] pub visibility: Option<String>,
    // Function/block modifiers
    #[serde(default)] pub is_async: bool,
    #[serde(default)] pub is_unsafe: bool,
    #[serde(default)] pub is_const: bool,
    #[serde(default)] pub is_extern: bool,
    #[serde(default)] pub abi: Option<String>,
    // Variable/field modifiers
    #[serde(default)] pub is_mut: bool,
    // Generics and lifetimes
    #[serde(default)] pub lifetimes: Vec<String>,
    #[serde(default)] pub generic_params: Vec<String>,
    #[serde(default)] pub where_clauses: Vec<String>,
    #[serde(default)] pub trait_bounds: Vec<String>,
    // impl block fields
    #[serde(default)] pub self_type: Option<String>,
    #[serde(default)] pub trait_type: Option<String>,
    // Closure fields
    #[serde(default)] pub is_move_closure: bool,
    // Derive macros
    #[serde(default)] pub derive_macros: Vec<String>,
    // Unsafe context
    #[serde(default)] pub is_unsafe_context: bool,
    // Ownership / type inference (populated by analysis passes, not the lifter)
    #[serde(default)] pub ownership_state: Option<OwnershipState>,
    #[serde(default)] pub inferred_type: Option<RustType>,
    // no_std flag
    #[serde(default)] pub is_no_std: bool,
    // Use-after-move detection (set by DFG ownership pass)
    #[serde(default)] pub use_after_move: bool,
}

/// Represents a preprocessor macro definition for expression evaluation.
/// `params` is empty for object-like macros (`#define SIZE 64`).
/// For function-like macros (`#define F(x) x+2`), `params = ["x"]`, `body = "x+2"`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacroBody {
    pub params: Vec<String>,
    pub body: String,
}

/// C/C++ preprocessor metadata stored at the file level (not per-node).
/// Populated during CPG construction via `gcc -dM -E` output and attribute parsing.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CFileMetadata {
    /// Function-like macro aliases: maps macro name → wrapped function name
    /// (e.g. `"SQLITE_MALLOC"` → `"malloc"`).
    #[serde(default)]
    pub macro_aliases: BTreeMap<String, String>,
    /// Macro definitions for expression evaluation.  Maps macro name → `MacroBody`
    /// (params + body text).  Used by the size tracker to expand macro arguments.
    #[serde(default)]
    pub macro_bodies: BTreeMap<String, MacroBody>,
    /// Custom allocator functions detected via `__attribute__((malloc))` or
    /// `__attribute__((alloc_size(...)))`.  Maps function name → size argument
    /// index (0-based; -1 means "implicit size" like `strdup`).  Merged with
    /// `HEAP_ALLOCATORS` during alias analysis.
    #[serde(default)]
    pub custom_allocators: BTreeMap<String, i32>,
}

/// Engine-level data produced during single-file analysis but consumed at the
/// workspace/codebase layer.  Stored on `Cpg` as a staging area; the workspace
/// layer moves or resolves these fields once all files are indexed.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceIndex {
    /// Calls to functions whose definitions live in other files.
    /// Resolved by the workspace layer into cross-file interprocedural DFG edges
    /// after all CPGs are built.
    #[serde(default)]
    pub cross_file_calls: Vec<CrossFileCallEdge>,
    /// Class / interface / trait hierarchy: maps a type name to its declared
    /// direct supertypes (extends + implements).
    /// Populated by `build_class_hierarchy` after lifting.
    #[serde(default)]
    pub class_hierarchy: BTreeMap<String, Vec<String>>,
    /// Per-function summaries for interprocedural DFG propagation.
    /// Maps `MethodDef` NodeId → summary of which params flow to which return positions.
    #[serde(default)]
    pub function_summaries: BTreeMap<NodeId, FunctionSummary>,
}

fn default_language() -> String {
    "c".to_string()
}

impl Cpg {
    pub fn get_node(&self, node_id: NodeId) -> Option<&AstNode> {
        self.ast.get(&node_id)
    }

    pub fn iter_nodes(&self) -> impl Iterator<Item = (&NodeId, &AstNode)> {
        self.ast.iter()
    }

    pub fn cpp_meta(&self, node_id: NodeId) -> Option<&CppNodeMetadata> {
        self.cpp_metadata.get(&node_id)
    }
    pub fn cpp_meta_mut(&mut self, node_id: NodeId) -> &mut CppNodeMetadata {
        self.cpp_metadata.entry(node_id).or_default()
    }
    pub fn go_meta(&self, node_id: NodeId) -> Option<&GoNodeMetadata> {
        self.go_metadata.get(&node_id)
    }
    pub fn go_meta_mut(&mut self, node_id: NodeId) -> &mut GoNodeMetadata {
        self.go_metadata.entry(node_id).or_default()
    }
    pub fn python_meta(&self, node_id: NodeId) -> Option<&PythonNodeMetadata> {
        self.python_metadata.get(&node_id)
    }
    pub fn python_meta_mut(&mut self, node_id: NodeId) -> &mut PythonNodeMetadata {
        self.python_metadata.entry(node_id).or_default()
    }
    pub fn java_meta(&self, node_id: NodeId) -> Option<&JavaNodeMetadata> {
        self.java_metadata.get(&node_id)
    }
    pub fn java_meta_mut(&mut self, node_id: NodeId) -> &mut JavaNodeMetadata {
        self.java_metadata.entry(node_id).or_default()
    }
    pub fn js_meta(&self, node_id: NodeId) -> Option<&JsNodeMetadata> {
        self.js_metadata.get(&node_id)
    }
    pub fn js_meta_mut(&mut self, node_id: NodeId) -> &mut JsNodeMetadata {
        self.js_metadata.entry(node_id).or_default()
    }
    pub fn ts_meta(&self, node_id: NodeId) -> Option<&TsNodeMetadata> {
        self.ts_metadata.get(&node_id)
    }
    pub fn ts_meta_mut(&mut self, node_id: NodeId) -> &mut TsNodeMetadata {
        self.ts_metadata.entry(node_id).or_default()
    }
    pub fn rust_meta(&self, node_id: NodeId) -> Option<&RustNodeMetadata> {
        self.rust_metadata.get(&node_id)
    }
    pub fn rust_meta_mut(&mut self, node_id: NodeId) -> &mut RustNodeMetadata {
        self.rust_metadata.entry(node_id).or_default()
    }

    /// Returns the `FunctionKind` for a node.
    /// Checks cpp_metadata first (authoritative), falls back to inferring from
    /// whether the node has a `function_definition` type.
    pub fn function_kind(&self, node_id: NodeId) -> FunctionKind {
        if let Some(meta) = self.cpp_metadata.get(&node_id) {
            return meta.function_kind;
        }
        if let Some(node) = self.ast.get(&node_id) {
            if node.kind == IrNodeKind::MethodDef
                || node.node_type == "function_definition"
                || node.node_type == "lambda_expression"
            {
                return FunctionKind::Internal;
            }
        }
        FunctionKind::ExternalDecl
    }
}

// ── CPG modules ────────────────────────────────────────────────────────────────

pub mod cfg;
pub mod cpg_generator;
pub mod dfg;
pub mod incremental;
pub mod lifter;
pub mod symbol_anonymizer;
pub mod type_inference;
pub mod call_analysis;

pub use cpg_generator::{
    CpgGenerator, GraphBuildOptions, SourceLanguage, extract_macros, extract_schema,
    generate_cpg_from_code, generate_cpg_from_file, get_node_graph, prune_identifiers,
};
pub use lifter::{
    CLifter, CppLifter, GoLifter, PythonLifter, JavaLifter, JsLifter, TsLifter, RustLifter,
    DynLifter, LanguageLifter, lifter_for_language,
};
pub use incremental::{
    AffectedRegion, ChangeType, IncrementalCpgGenerator, IncrementalCpgState, LightweightIndex,
    TextEdit, compute_edit,
};
pub use symbol_anonymizer::{AnonymizedCpg, SymbolAnonymizer};

/// Detect source language from a file path or URI by extension.
/// Uses tree-sitter-language-pack for comprehensive extension detection.
/// Falls back to `SourceLanguage::C` for unrecognized extensions.
pub fn language_from_path(path: &str) -> SourceLanguage {
    match tree_sitter_language_pack::detect_language_from_path(path) {
        Some("c") => SourceLanguage::C,
        Some("cpp") => SourceLanguage::Cpp,
        Some("go") => SourceLanguage::Go,
        Some("python") => SourceLanguage::Python,
        Some("java") => SourceLanguage::Java,
        Some("javascript") => SourceLanguage::JavaScript,
        Some("typescript") => SourceLanguage::TypeScript,
        Some("rust") => SourceLanguage::Rust,
        _ => SourceLanguage::C,
    }
}
