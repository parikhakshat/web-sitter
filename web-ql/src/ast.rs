use serde::{Deserialize, Serialize};
use crate::lexer::Span;

// ── Top-level ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct RuleFile {
    pub items: Vec<TopLevelItem>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TopLevelItem {
    Rule(Rule),
    PredicateDef(PredicateDef),
    SourceDef(SourceDef),
    SinkDef(SinkDef),
    SanitizerDef(SanitizerDef),
    PropagatorDef(PropagatorDef),
}

// ── Rule ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub span: Span,
    pub id: String, // the string literal after `rule`
    pub severity: Option<Severity>,
    pub languages: Option<Vec<Language>>,
    pub tags: Option<Vec<String>>,
    pub message: Option<String>,
    pub clauses: Vec<RuleClause>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "critical"),
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
            Self::Info => write!(f, "info"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    C,
    Cpp,
    Go,
    Java,
    Python,
    JavaScript,
    TypeScript,
    Rust,
}

impl std::fmt::Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::C => write!(f, "c"),
            Self::Cpp => write!(f, "cpp"),
            Self::Go => write!(f, "go"),
            Self::Java => write!(f, "java"),
            Self::Python => write!(f, "python"),
            Self::JavaScript => write!(f, "javascript"),
            Self::TypeScript => write!(f, "typescript"),
            Self::Rust => write!(f, "rust"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RuleClause {
    Search(SearchClause),
    Taint(TaintClause),
}

// ── Search clause ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct SearchClause {
    pub span: Span,
    pub bindings: Vec<Binding>,
    pub condition: Expr,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Binding {
    pub span: Span,
    pub name: String,
    pub ty: TypeExpr,
}

// ── Taint clause ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct TaintClause {
    pub span: Span,
    pub sources: Vec<NamedRef>,
    pub sinks: Vec<NamedRef>,
    pub sanitizers: Vec<NamedRef>,
    pub propagators: Vec<NamedRef>,
    /// Function names that, when called on the tainted value inside a
    /// conditional whose branch CFG-dominates the sink (and which textually
    /// precedes it — see `guard_dominates` in taint.rs), suppress that
    /// particular source→sink finding. Unlike `sanitizers` (a node the value
    /// flows *through* and comes out clean), a guard is a control-flow gate:
    /// the tainted variable's own value is unchanged, but the sink is only
    /// reachable when the guard call approved it (`if (validate(x)) sink(x);`).
    pub guards: Vec<String>,
    pub require_interprocedural: Option<bool>,
    pub max_call_depth: Option<u32>,
    pub require_same_function: Option<bool>,
}

/// A reference to a named source/sink/sanitizer/propagator/predicate,
/// written as `name(arg1, arg2, ...)`.
#[derive(Debug, Clone, PartialEq)]
pub struct NamedRef {
    pub span: Span,
    pub name: String,
    pub args: Vec<Expr>,
}

// ── Type expressions ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TypeExpr {
    // Supersets
    Node,
    Expr,
    Stmt,
    Decl,
    // Concrete kinds
    Call,
    MethodDef,
    ClassDef,
    Identifier,
    Literal,
    Assign,
    BinaryOp,
    Return,
    Loop,
    Conditional,
    Block,
    Try,
    Catch,
    ParamDef,
    LocalDef,
    FieldDef,
    MemberAccess,
    Subscript,
    Cast,
    // Lang-specific
    GoStmt,
    DeferStmt,
    MatchExpr,
    Comprehension,
    Await,
    Yield,
    UnsafeBlock,
    ImplBlock,
    // Escape hatch
    NodeType(String),
    // User-defined identifier (for use in predicates/type params)
    Named(String),
}

impl std::fmt::Display for TypeExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Node => write!(f, "Node"),
            Self::Expr => write!(f, "Expr"),
            Self::Stmt => write!(f, "Stmt"),
            Self::Decl => write!(f, "Decl"),
            Self::Call => write!(f, "Call"),
            Self::MethodDef => write!(f, "MethodDef"),
            Self::ClassDef => write!(f, "ClassDef"),
            Self::Identifier => write!(f, "Identifier"),
            Self::Literal => write!(f, "Literal"),
            Self::Assign => write!(f, "Assign"),
            Self::BinaryOp => write!(f, "BinaryOp"),
            Self::Return => write!(f, "Return"),
            Self::Loop => write!(f, "Loop"),
            Self::Conditional => write!(f, "Conditional"),
            Self::Block => write!(f, "Block"),
            Self::Try => write!(f, "Try"),
            Self::Catch => write!(f, "Catch"),
            Self::ParamDef => write!(f, "ParamDef"),
            Self::LocalDef => write!(f, "LocalDef"),
            Self::FieldDef => write!(f, "FieldDef"),
            Self::MemberAccess => write!(f, "MemberAccess"),
            Self::Subscript => write!(f, "Subscript"),
            Self::Cast => write!(f, "Cast"),
            Self::GoStmt => write!(f, "GoStmt"),
            Self::DeferStmt => write!(f, "DeferStmt"),
            Self::MatchExpr => write!(f, "MatchExpr"),
            Self::Comprehension => write!(f, "Comprehension"),
            Self::Await => write!(f, "Await"),
            Self::Yield => write!(f, "Yield"),
            Self::UnsafeBlock => write!(f, "UnsafeBlock"),
            Self::ImplBlock => write!(f, "ImplBlock"),
            Self::NodeType(s) => write!(f, "NodeType({s:?})"),
            Self::Named(s) => write!(f, "{s}"),
        }
    }
}

// ── Expressions ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct Expr {
    pub span: Span,
    pub kind: ExprKind,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExprKind {
    // Logical
    Or(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    // Comparison
    Compare {
        lhs: Box<Expr>,
        op: CmpOp,
        rhs: Box<Expr>,
    },
    // Method call chain:  expr.method(args)
    MethodCall {
        receiver: Box<Expr>,
        method: String,
        args: Vec<Expr>,
    },
    // Quantifiers
    Exists {
        var: String,
        ty: TypeExpr,
        body: Box<Expr>,
    },
    Forall {
        var: String,
        ty: TypeExpr,
        body: Box<Expr>,
    },
    // Free-standing predicate / function call: name(args)
    Call {
        name: String,
        args: Vec<Expr>,
    },
    // Pattern matching:  expr matches Pattern { field: constraint, ... }
    MatchesPattern {
        expr: Box<Expr>,
        pattern: NodePattern,
    },
    // Let binding: bind a derived node to a name, then evaluate body with it in scope.
    // Syntax: `let var = method_chain in body`
    Let {
        var: String,
        binding: Box<Expr>, // must evaluate to a node (method chain)
        body: Box<Expr>,
    },
    // Primary atoms
    Ident(String),
    Literal(Literal),
    // Parenthesized
    Paren(Box<Expr>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
    In,    // `in ["a", "b"]`  or  `in set_expr`
}

/// Inline structural pattern used with `matches`:
///   `call.arg(0) matches Literal { lit_kind: String }`
#[derive(Debug, Clone, PartialEq)]
pub struct NodePattern {
    pub ty: TypeExpr,
    pub fields: Vec<(String, Expr)>,
}

// ── Literals ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    Int(i64),
    Float(f64),
    Str(String),
    Bool(bool),
    Null,
    /// Regex literal: the raw text including / delimiters and flags
    Regex(String),
    /// Array of literals
    List(Vec<Literal>),
}

// ── Named declarations ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct Param {
    pub span: Span,
    pub name: String,
    pub ty: TypeExpr,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PredicateDef {
    pub span: Span,
    pub name: String,
    pub params: Vec<Param>,
    pub body: Expr,
}

/// A source definition: one or more `find … where …` alternatives.
#[derive(Debug, Clone, PartialEq)]
pub struct SourceDef {
    pub span: Span,
    pub name: String,
    pub params: Vec<Param>,
    pub body: Vec<FindExpr>, // alternatives combined with `or`
}

#[derive(Debug, Clone, PartialEq)]
pub struct SinkDef {
    pub span: Span,
    pub name: String,
    pub params: Vec<Param>,
    pub body: Vec<FindExpr>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SanitizerDef {
    pub span: Span,
    pub name: String,
    pub params: Vec<Param>,
    pub body: Vec<FindExpr>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PropagatorDef {
    pub span: Span,
    pub name: String,
    pub params: Vec<Param>,
    pub body: PropBody,
}

/// propagator body:  pattern: <expr>  from: <ident>  to: <ident>
#[derive(Debug, Clone, PartialEq)]
pub struct PropBody {
    pub pattern: Expr,
    pub from_binding: String,
    pub to_binding: String,
}

/// A `find <bindings> where <expr>` expression used inside source/sink bodies.
#[derive(Debug, Clone, PartialEq)]
pub struct FindExpr {
    pub span: Span,
    pub bindings: Vec<Binding>,
    pub condition: Expr,
}
