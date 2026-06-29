use logos::Logos;

/// A source span: byte offset range in the original input string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }
    pub fn merge(self, other: Self) -> Self {
        Self {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }
}

/// Complete token set for the ScuzzQL DSL grammar.
#[derive(Logos, Debug, Clone, PartialEq)]
#[logos(skip r"[ \t\r\n\f]+")]
pub enum Token {
    // ── Keywords ──────────────────────────────────────────────────────────
    #[token("rule")]
    Rule,
    #[token("find")]
    Find,
    #[token("where")]
    Where,
    #[token("taint")]
    Taint,
    #[token("source")]
    Source,
    #[token("sink")]
    Sink,
    #[token("sanitizer")]
    Sanitizer,
    #[token("propagator")]
    Propagator,
    #[token("pred")]
    Pred,
    #[token("exists")]
    Exists,
    #[token("forall")]
    Forall,
    #[token("and")]
    And,
    #[token("or")]
    Or,
    #[token("not")]
    Not,
    #[token("in")]
    In,
    #[token("matches")]
    Matches,
    #[token("pattern")]
    Pattern,
    #[token("from")]
    From,
    #[token("to")]
    To,
    // Taint body keys
    #[token("sources")]
    Sources,
    #[token("sinks")]
    Sinks,
    #[token("sanitizers")]
    Sanitizers,
    #[token("propagators")]
    Propagators,
    #[token("require_interprocedural")]
    RequireInterprocedural,
    #[token("require_same_function")]
    RequireSameFunction,
    #[token("max_call_depth")]
    MaxCallDepth,
    // Rule metadata keys
    #[token("severity")]
    Severity,
    #[token("languages")]
    Languages,
    #[token("tags")]
    Tags,
    #[token("message")]
    Message,
    // Severity values
    #[token("critical")]
    Critical,
    #[token("high")]
    High,
    #[token("medium")]
    Medium,
    #[token("low")]
    Low,
    #[token("info")]
    Info,
    // Bool literals (before Ident so they don't get captured as identifiers)
    #[token("true")]
    True,
    #[token("false")]
    False,
    // Null literal
    #[token("null")]
    Null,
    // Type keywords (built-in type aliases)
    #[token("Node")]
    TyNode,
    #[token("Expr")]
    TyExpr,
    #[token("Stmt")]
    TyStmt,
    #[token("Decl")]
    TyDecl,
    #[token("Call")]
    TyCall,
    #[token("MethodDef")]
    TyMethodDef,
    #[token("ClassDef")]
    TyClassDef,
    #[token("Identifier")]
    TyIdentifier,
    #[token("Literal")]
    TyLiteral,
    #[token("Assign")]
    TyAssign,
    #[token("BinaryOp")]
    TyBinaryOp,
    #[token("Return")]
    TyReturn,
    #[token("Loop")]
    TyLoop,
    #[token("Conditional")]
    TyConditional,
    #[token("Block")]
    TyBlock,
    #[token("Try")]
    TyTry,
    #[token("Catch")]
    TyCatch,
    #[token("ParamDef")]
    TyParamDef,
    #[token("LocalDef")]
    TyLocalDef,
    #[token("FieldDef")]
    TyFieldDef,
    #[token("MemberAccess")]
    TyMemberAccess,
    #[token("Subscript")]
    TySubscript,
    #[token("Cast")]
    TyCast,
    #[token("GoStmt")]
    TyGoStmt,
    #[token("DeferStmt")]
    TyDeferStmt,
    #[token("MatchExpr")]
    TyMatchExpr,
    #[token("Comprehension")]
    TyComprehension,
    #[token("Await")]
    TyAwait,
    #[token("Yield")]
    TyYield,
    #[token("UnsafeBlock")]
    TyUnsafeBlock,
    #[token("ImplBlock")]
    TyImplBlock,
    #[token("NodeType")]
    TyNodeType,
    // ── Operators & punctuation ───────────────────────────────────────────
    #[token("==")]
    Eq,
    #[token("!=")]
    Ne,
    #[token("<=")]
    Le,
    #[token(">=")]
    Ge,
    #[token("<")]
    Lt,
    #[token(">")]
    Gt,
    #[token("{")]
    LBrace,
    #[token("}")]
    RBrace,
    #[token("(")]
    LParen,
    #[token(")")]
    RParen,
    #[token("[")]
    LBracket,
    #[token("]")]
    RBracket,
    #[token(",")]
    Comma,
    #[token(":")]
    Colon,
    #[token(".")]
    Dot,
    #[token("=")]
    Assign,
    #[token("|")]
    Pipe,
    // ── Literals ──────────────────────────────────────────────────────────
    #[regex(r"[a-zA-Z_][a-zA-Z0-9_]*")]
    Ident,
    #[regex(r#""([^"\\]|\\.)*""#)]
    StringLit,
    /// /pattern/flags  — captured raw including delimiters
    #[regex(r"/([^/\\\n]|\\.)+/[gimsuy]*")]
    RegexLit,
    #[regex(r"[0-9]+\.[0-9]+([eE][+-]?[0-9]+)?")]
    FloatLit,
    #[regex(r"[0-9]+")]
    IntLit,
    // ── Comments (skipped) ────────────────────────────────────────────────
    #[regex(r"//[^\n]*", logos::skip)]
    #[regex(r"/\*([^*]|\*[^/])*\*/", logos::skip)]
    Comment,
}

/// A spanned token: the token kind plus its source byte range.
#[derive(Clone, Debug, PartialEq)]
pub struct SpannedToken {
    pub token: Token,
    pub span: Span,
    /// The raw source slice for this token.
    pub text: String,
}

/// Lex the full source into a `Vec<SpannedToken>`, returning errors inline
/// so the parser can produce diagnostics.
pub fn lex(source: &str) -> (Vec<SpannedToken>, Vec<LexError>) {
    let mut tokens = Vec::new();
    let mut errors = Vec::new();
    let mut lexer = Token::lexer(source);
    while let Some(result) = lexer.next() {
        let span = lexer.span();
        match result {
            Ok(tok) => tokens.push(SpannedToken {
                token: tok,
                span: Span::new(span.start, span.end),
                text: source[span.start..span.end].to_owned(),
            }),
            Err(_) => errors.push(LexError {
                span: Span::new(span.start, span.end),
                slice: source[span.start..span.end].to_owned(),
            }),
        }
    }
    (tokens, errors)
}

#[derive(Debug, Clone, PartialEq)]
pub struct LexError {
    pub span: Span,
    pub slice: String,
}

impl std::fmt::Display for LexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unexpected character {:?} at byte {}..{}",
            self.slice, self.span.start, self.span.end
        )
    }
}
