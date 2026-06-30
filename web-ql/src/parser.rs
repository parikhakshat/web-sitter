use crate::ast::*;
use crate::lexer::{Span, SpannedToken, Token, lex};
use thiserror::Error;

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Error)]
pub enum ParseError {
    #[error("unexpected token `{found}` at {span:?}, expected {expected}")]
    UnexpectedToken {
        found: String,
        expected: String,
        span: Span,
    },
    #[error("unexpected end of input, expected {expected}")]
    UnexpectedEof { expected: String },
    #[error("lex error: {msg}")]
    LexError { msg: String, span: Span },
}

pub type ParseResult<T> = Result<T, ParseError>;

// ── Parser state ──────────────────────────────────────────────────────────────

pub struct Parser {
    tokens: Vec<SpannedToken>,
    pos: usize,
}

impl Parser {
    pub fn new(tokens: Vec<SpannedToken>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<&SpannedToken> {
        self.tokens.get(self.pos)
    }

    fn peek_tok(&self) -> Option<&Token> {
        self.peek().map(|s| &s.token)
    }

    fn advance(&mut self) -> Option<&SpannedToken> {
        let tok = self.tokens.get(self.pos);
        if tok.is_some() {
            self.pos += 1;
        }
        tok
    }

    fn current_span(&self) -> Span {
        self.peek().map(|t| t.span).unwrap_or_default()
    }

    fn expect(&mut self, tok: &Token, desc: &str) -> ParseResult<SpannedToken> {
        match self.peek() {
            Some(st) if &st.token == tok => {
                let st = st.clone();
                self.pos += 1;
                Ok(st)
            }
            Some(st) => Err(ParseError::UnexpectedToken {
                found: format!("{:?}", st.token),
                expected: desc.to_owned(),
                span: st.span,
            }),
            None => Err(ParseError::UnexpectedEof {
                expected: desc.to_owned(),
            }),
        }
    }

    fn expect_ident(&mut self) -> ParseResult<(String, Span)> {
        // Many keywords can also appear as identifiers in some positions (e.g. named predicates);
        // we handle the common case by accepting Ident; keyword-as-ident is NOT supported here.
        match self.peek() {
            Some(st) if matches!(st.token, Token::Ident) => {
                let (text, span) = (st.text.clone(), st.span);
                self.pos += 1;
                Ok((text, span))
            }
            Some(st) => Err(ParseError::UnexpectedToken {
                found: format!("{:?}", st.token),
                expected: "identifier".to_owned(),
                span: st.span,
            }),
            None => Err(ParseError::UnexpectedEof {
                expected: "identifier".to_owned(),
            }),
        }
    }

    fn eat(&mut self, tok: &Token) -> bool {
        if self.peek_tok() == Some(tok) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect_string_lit(&mut self) -> ParseResult<(String, Span)> {
        match self.peek() {
            Some(st) if st.token == Token::StringLit => {
                let raw = st.text.clone();
                let span = st.span;
                self.pos += 1;
                let s = unescape_string(&raw);
                Ok((s, span))
            }
            Some(st) => Err(ParseError::UnexpectedToken {
                found: format!("{:?}", st.token),
                expected: "string literal".to_owned(),
                span: st.span,
            }),
            None => Err(ParseError::UnexpectedEof {
                expected: "string literal".to_owned(),
            }),
        }
    }

    /// Accept an identifier OR any keyword token that could appear as a field name / predicate name.
    fn expect_name(&mut self) -> ParseResult<(String, Span)> {
        match self.peek().cloned() {
            Some(st) => {
                let name = match &st.token {
                    Token::Ident => st.text.clone(),
                    // Allow some keywords as identifier names (predicate / method names)
                    Token::Source => "source".to_owned(),
                    Token::Sink => "sink".to_owned(),
                    Token::Sanitizer => "sanitizer".to_owned(),
                    Token::Propagator => "propagator".to_owned(),
                    Token::Find => "find".to_owned(),
                    Token::From => "from".to_owned(),
                    Token::To => "to".to_owned(),
                    Token::Pattern => "pattern".to_owned(),
                    Token::Rule => "rule".to_owned(),
                    _ => {
                        return Err(ParseError::UnexpectedToken {
                            found: format!("{:?}", st.token),
                            expected: "identifier or name".to_owned(),
                            span: st.span,
                        });
                    }
                };
                self.pos += 1;
                Ok((name, st.span))
            }
            None => Err(ParseError::UnexpectedEof {
                expected: "identifier".to_owned(),
            }),
        }
    }
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Parse a complete `.sq` rule file from source text.
/// Returns both parse result and any lex errors encountered.
pub fn parse_rule_file(source: &str) -> ParseResult<RuleFile> {
    let (tokens, lex_errors) = lex(source);
    if let Some(le) = lex_errors.first() {
        return Err(ParseError::LexError {
            msg: le.to_string(),
            span: le.span,
        });
    }
    let mut p = Parser::new(tokens);
    p.parse_rule_file()
}

// ── Grammar rules ─────────────────────────────────────────────────────────────

impl Parser {
    fn parse_rule_file(&mut self) -> ParseResult<RuleFile> {
        let mut items = Vec::new();
        while self.peek().is_some() {
            items.push(self.parse_top_level_item()?);
        }
        Ok(RuleFile { items })
    }

    fn parse_top_level_item(&mut self) -> ParseResult<TopLevelItem> {
        match self.peek_tok() {
            Some(Token::Rule) => Ok(TopLevelItem::Rule(self.parse_rule()?)),
            Some(Token::Pred) => Ok(TopLevelItem::PredicateDef(self.parse_predicate_def()?)),
            Some(Token::Source) => Ok(TopLevelItem::SourceDef(self.parse_source_def()?)),
            Some(Token::Sink) => Ok(TopLevelItem::SinkDef(self.parse_sink_def()?)),
            Some(Token::Sanitizer) => Ok(TopLevelItem::SanitizerDef(self.parse_sanitizer_def()?)),
            Some(Token::Propagator) => {
                Ok(TopLevelItem::PropagatorDef(self.parse_propagator_def()?))
            }
            Some(_) => {
                let st = self.peek().unwrap();
                Err(ParseError::UnexpectedToken {
                    found: format!("{:?}", st.token),
                    expected: "rule | pred | source | sink | sanitizer | propagator".to_owned(),
                    span: st.span,
                })
            }
            None => Err(ParseError::UnexpectedEof {
                expected: "top-level item".to_owned(),
            }),
        }
    }

    // ── Rule ──────────────────────────────────────────────────────────────────

    fn parse_rule(&mut self) -> ParseResult<Rule> {
        let start = self.current_span();
        self.expect(&Token::Rule, "`rule`")?;
        let (id, _) = self.expect_string_lit()?;
        self.expect(&Token::LBrace, "`{`")?;

        let mut severity = None;
        let mut languages = None;
        let mut tags = None;
        let mut message = None;
        let mut clauses = Vec::new();

        loop {
            match self.peek_tok() {
                Some(Token::RBrace) => {
                    self.advance();
                    break;
                }
                Some(Token::Severity) => {
                    self.advance();
                    self.expect(&Token::Colon, "`:`")?;
                    severity = Some(self.parse_severity()?);
                }
                Some(Token::Languages) => {
                    self.advance();
                    self.expect(&Token::Colon, "`:`")?;
                    languages = Some(self.parse_language_list()?);
                }
                Some(Token::Tags) => {
                    self.advance();
                    self.expect(&Token::Colon, "`:`")?;
                    tags = Some(self.parse_string_list()?);
                }
                Some(Token::Message) => {
                    self.advance();
                    self.expect(&Token::Colon, "`:`")?;
                    let (msg, _) = self.expect_string_lit()?;
                    message = Some(msg);
                }
                Some(Token::Find) => {
                    clauses.push(RuleClause::Search(self.parse_search_clause()?));
                }
                Some(Token::Taint) => {
                    clauses.push(RuleClause::Taint(self.parse_taint_clause()?));
                }
                Some(_) => {
                    let st = self.peek().unwrap();
                    return Err(ParseError::UnexpectedToken {
                        found: format!("{:?}", st.token),
                        expected: "severity | languages | tags | message | find | taint | `}`".to_owned(),
                        span: st.span,
                    });
                }
                None => {
                    return Err(ParseError::UnexpectedEof {
                        expected: "`}`".to_owned(),
                    });
                }
            }
        }

        let end = self.tokens.get(self.pos.saturating_sub(1)).map(|t| t.span).unwrap_or(start);
        Ok(Rule {
            span: start.merge(end),
            id,
            severity,
            languages,
            tags,
            message,
            clauses,
        })
    }

    fn parse_severity(&mut self) -> ParseResult<Severity> {
        let st = self.peek().cloned().ok_or(ParseError::UnexpectedEof {
            expected: "severity level".to_owned(),
        })?;
        let sev = match &st.token {
            Token::Critical => Severity::Critical,
            Token::High => Severity::High,
            Token::Medium => Severity::Medium,
            Token::Low => Severity::Low,
            Token::Info => Severity::Info,
            _ => {
                return Err(ParseError::UnexpectedToken {
                    found: format!("{:?}", st.token),
                    expected: "critical | high | medium | low | info".to_owned(),
                    span: st.span,
                });
            }
        };
        self.pos += 1;
        Ok(sev)
    }

    fn parse_language_list(&mut self) -> ParseResult<Vec<Language>> {
        self.expect(&Token::LBracket, "`[`")?;
        let mut langs = Vec::new();
        while self.peek_tok() != Some(&Token::RBracket) {
            let st = self.peek().cloned().ok_or(ParseError::UnexpectedEof {
                expected: "language name".to_owned(),
            })?;
            let lang = match st.token {
                Token::Ident => match st.text.as_str() {
                    "c" => Language::C,
                    "cpp" => Language::Cpp,
                    "go" => Language::Go,
                    "java" => Language::Java,
                    "python" => Language::Python,
                    "javascript" => Language::JavaScript,
                    "typescript" => Language::TypeScript,
                    "rust" => Language::Rust,
                    other => {
                        return Err(ParseError::UnexpectedToken {
                            found: other.to_owned(),
                            expected: "language name".to_owned(),
                            span: st.span,
                        });
                    }
                },
                _ => {
                    return Err(ParseError::UnexpectedToken {
                        found: format!("{:?}", st.token),
                        expected: "language name".to_owned(),
                        span: st.span,
                    });
                }
            };
            self.pos += 1;
            langs.push(lang);
            if !self.eat(&Token::Comma) {
                break;
            }
        }
        self.expect(&Token::RBracket, "`]`")?;
        Ok(langs)
    }

    fn parse_string_list(&mut self) -> ParseResult<Vec<String>> {
        self.expect(&Token::LBracket, "`[`")?;
        let mut items = Vec::new();
        while self.peek_tok() != Some(&Token::RBracket) {
            let (s, _) = self.expect_string_lit()?;
            items.push(s);
            if !self.eat(&Token::Comma) {
                break;
            }
        }
        self.expect(&Token::RBracket, "`]`")?;
        Ok(items)
    }

    // ── Search clause ─────────────────────────────────────────────────────────

    fn parse_search_clause(&mut self) -> ParseResult<SearchClause> {
        let start = self.current_span();
        self.expect(&Token::Find, "`find`")?;
        let bindings = self.parse_binding_list()?;
        // `where <condition>` is optional — if absent, defaults to `true`
        let (condition, end) = if self.peek_tok() == Some(&Token::Where) {
            self.pos += 1;
            let cond = self.parse_expr()?;
            let e = cond.span;
            (cond, e)
        } else {
            let sp = self.current_span();
            (Expr { span: sp, kind: ExprKind::Literal(Literal::Bool(true)) }, sp)
        };
        Ok(SearchClause {
            span: start.merge(end),
            bindings,
            condition,
        })
    }

    fn parse_binding_list(&mut self) -> ParseResult<Vec<Binding>> {
        let mut bindings = Vec::new();
        bindings.push(self.parse_binding()?);
        while self.eat(&Token::Comma) {
            bindings.push(self.parse_binding()?);
        }
        Ok(bindings)
    }

    fn parse_binding(&mut self) -> ParseResult<Binding> {
        let (name, span) = self.expect_ident()?;
        self.expect(&Token::Colon, "`:`")?;
        let ty = self.parse_type_expr()?;
        Ok(Binding {
            span: span.merge(self.tokens.get(self.pos.saturating_sub(1)).map(|t| t.span).unwrap_or(span)),
            name,
            ty,
        })
    }

    // ── Taint clause ──────────────────────────────────────────────────────────

    fn parse_taint_clause(&mut self) -> ParseResult<TaintClause> {
        let start = self.current_span();
        self.expect(&Token::Taint, "`taint`")?;
        self.expect(&Token::LBrace, "`{`")?;

        let mut sources = Vec::new();
        let mut sinks = Vec::new();
        let mut sanitizers = Vec::new();
        let mut propagators = Vec::new();
        let mut require_interprocedural = None;
        let mut max_call_depth = None;
        let mut require_same_function = None;

        loop {
            match self.peek_tok() {
                Some(Token::RBrace) => {
                    self.advance();
                    break;
                }
                Some(Token::Sources) => {
                    self.advance();
                    self.expect(&Token::Colon, "`:`")?;
                    sources = self.parse_named_ref_list()?;
                }
                Some(Token::Sinks) => {
                    self.advance();
                    self.expect(&Token::Colon, "`:`")?;
                    sinks = self.parse_named_ref_list()?;
                }
                Some(Token::Sanitizers) => {
                    self.advance();
                    self.expect(&Token::Colon, "`:`")?;
                    sanitizers = self.parse_named_ref_list()?;
                }
                Some(Token::Propagators) => {
                    self.advance();
                    self.expect(&Token::Colon, "`:`")?;
                    propagators = self.parse_named_ref_list()?;
                }
                Some(Token::RequireInterprocedural) => {
                    self.advance();
                    self.expect(&Token::Colon, "`:`")?;
                    require_interprocedural = Some(self.parse_bool_lit()?);
                }
                Some(Token::MaxCallDepth) => {
                    self.advance();
                    self.expect(&Token::Colon, "`:`")?;
                    max_call_depth = Some(self.parse_int_lit()? as u32);
                }
                Some(Token::RequireSameFunction) => {
                    self.advance();
                    self.expect(&Token::Colon, "`:`")?;
                    require_same_function = Some(self.parse_bool_lit()?);
                }
                Some(_) => {
                    let st = self.peek().unwrap();
                    return Err(ParseError::UnexpectedToken {
                        found: format!("{:?}", st.token),
                        expected: "sources | sinks | sanitizers | propagators | require_interprocedural | max_call_depth | `}`".to_owned(),
                        span: st.span,
                    });
                }
                None => {
                    return Err(ParseError::UnexpectedEof {
                        expected: "`}`".to_owned(),
                    });
                }
            }
        }

        let end = self.tokens.get(self.pos.saturating_sub(1)).map(|t| t.span).unwrap_or(start);
        Ok(TaintClause {
            span: start.merge(end),
            sources,
            sinks,
            sanitizers,
            propagators,
            require_interprocedural,
            max_call_depth,
            require_same_function,
        })
    }

    fn parse_named_ref_list(&mut self) -> ParseResult<Vec<NamedRef>> {
        self.expect(&Token::LBracket, "`[`")?;
        let mut refs = Vec::new();
        while self.peek_tok() != Some(&Token::RBracket) {
            refs.push(self.parse_named_ref()?);
            if !self.eat(&Token::Comma) {
                break;
            }
        }
        self.expect(&Token::RBracket, "`]`")?;
        Ok(refs)
    }

    fn parse_named_ref(&mut self) -> ParseResult<NamedRef> {
        // Accept both bare identifiers and string literals: `user_input` or `"user_input"`
        let (name, span) = if self.peek_tok() == Some(&Token::StringLit) {
            self.expect_string_lit()?
        } else {
            self.expect_name()?
        };
        let args = if self.eat(&Token::LParen) {
            let mut args = Vec::new();
            while self.peek_tok() != Some(&Token::RParen) {
                args.push(self.parse_expr()?);
                if !self.eat(&Token::Comma) {
                    break;
                }
            }
            self.expect(&Token::RParen, "`)`")?;
            args
        } else {
            Vec::new()
        };
        let end = self.tokens.get(self.pos.saturating_sub(1)).map(|t| t.span).unwrap_or(span);
        Ok(NamedRef { span: span.merge(end), name, args })
    }

    // ── Type expressions ──────────────────────────────────────────────────────

    fn parse_type_expr(&mut self) -> ParseResult<TypeExpr> {
        let st = self.peek().cloned().ok_or(ParseError::UnexpectedEof {
            expected: "type expression".to_owned(),
        })?;
        let ty = match &st.token {
            Token::TyNode => { self.pos += 1; TypeExpr::Node }
            Token::TyExpr => { self.pos += 1; TypeExpr::Expr }
            Token::TyStmt => { self.pos += 1; TypeExpr::Stmt }
            Token::TyDecl => { self.pos += 1; TypeExpr::Decl }
            Token::TyCall => { self.pos += 1; TypeExpr::Call }
            Token::TyMethodDef => { self.pos += 1; TypeExpr::MethodDef }
            Token::TyClassDef => { self.pos += 1; TypeExpr::ClassDef }
            Token::TyIdentifier => { self.pos += 1; TypeExpr::Identifier }
            Token::TyLiteral => { self.pos += 1; TypeExpr::Literal }
            Token::TyAssign => { self.pos += 1; TypeExpr::Assign }
            Token::TyBinaryOp => { self.pos += 1; TypeExpr::BinaryOp }
            Token::TyReturn => { self.pos += 1; TypeExpr::Return }
            Token::TyLoop => { self.pos += 1; TypeExpr::Loop }
            Token::TyConditional => { self.pos += 1; TypeExpr::Conditional }
            Token::TyBlock => { self.pos += 1; TypeExpr::Block }
            Token::TyTry => { self.pos += 1; TypeExpr::Try }
            Token::TyCatch => { self.pos += 1; TypeExpr::Catch }
            Token::TyParamDef => { self.pos += 1; TypeExpr::ParamDef }
            Token::TyLocalDef => { self.pos += 1; TypeExpr::LocalDef }
            Token::TyFieldDef => { self.pos += 1; TypeExpr::FieldDef }
            Token::TyMemberAccess => { self.pos += 1; TypeExpr::MemberAccess }
            Token::TySubscript => { self.pos += 1; TypeExpr::Subscript }
            Token::TyCast => { self.pos += 1; TypeExpr::Cast }
            Token::TyGoStmt => { self.pos += 1; TypeExpr::GoStmt }
            Token::TyDeferStmt => { self.pos += 1; TypeExpr::DeferStmt }
            Token::TyMatchExpr => { self.pos += 1; TypeExpr::MatchExpr }
            Token::TyComprehension => { self.pos += 1; TypeExpr::Comprehension }
            Token::TyAwait => { self.pos += 1; TypeExpr::Await }
            Token::TyYield => { self.pos += 1; TypeExpr::Yield }
            Token::TyUnsafeBlock => { self.pos += 1; TypeExpr::UnsafeBlock }
            Token::TyImplBlock => { self.pos += 1; TypeExpr::ImplBlock }
            Token::TyNodeType => {
                self.pos += 1;
                self.expect(&Token::LParen, "`(`")?;
                let (raw, _) = self.expect_string_lit()?;
                self.expect(&Token::RParen, "`)`")?;
                TypeExpr::NodeType(raw)
            }
            Token::Ident => {
                let name = st.text.clone();
                self.pos += 1;
                TypeExpr::Named(name)
            }
            _ => {
                return Err(ParseError::UnexpectedToken {
                    found: format!("{:?}", st.token),
                    expected: "type expression".to_owned(),
                    span: st.span,
                });
            }
        };
        Ok(ty)
    }

    // ── Expressions (Pratt parser) ────────────────────────────────────────────

    fn parse_expr(&mut self) -> ParseResult<Expr> {
        self.parse_or_expr()
    }

    fn parse_or_expr(&mut self) -> ParseResult<Expr> {
        let mut lhs = self.parse_and_expr()?;
        while self.eat(&Token::Or) {
            let rhs = self.parse_and_expr()?;
            let span = lhs.span.merge(rhs.span);
            lhs = Expr {
                span,
                kind: ExprKind::Or(Box::new(lhs), Box::new(rhs)),
            };
        }
        Ok(lhs)
    }

    fn parse_and_expr(&mut self) -> ParseResult<Expr> {
        let mut lhs = self.parse_not_expr()?;
        while self.eat(&Token::And) {
            let rhs = self.parse_not_expr()?;
            let span = lhs.span.merge(rhs.span);
            lhs = Expr {
                span,
                kind: ExprKind::And(Box::new(lhs), Box::new(rhs)),
            };
        }
        Ok(lhs)
    }

    fn parse_not_expr(&mut self) -> ParseResult<Expr> {
        if let Some(st) = self.peek().cloned() {
            match st.token {
                Token::Not => {
                    let start = st.span;
                    self.pos += 1;
                    let inner = self.parse_not_expr()?;
                    let end = inner.span;
                    return Ok(Expr {
                        span: start.merge(end),
                        kind: ExprKind::Not(Box::new(inner)),
                    });
                }
                Token::Let => return self.parse_let_expr(),
                _ => {}
            }
        }
        self.parse_compare_expr()
    }

    /// Parse `let var = call_expr in body_expr`.
    ///
    /// The RHS is intentionally limited to `parse_call_expr` (method chains,
    /// no comparison operators) to avoid ambiguity with the `in` keyword.
    fn parse_let_expr(&mut self) -> ParseResult<Expr> {
        let start = self.current_span();
        self.expect(&Token::Let, "`let`")?;
        let (var, _) = self.expect_ident()?;
        self.expect(&Token::Assign, "`=`")?;
        let binding = self.parse_call_expr()?;
        self.expect(&Token::In, "`in`")?;
        let body = self.parse_expr()?;
        let end = body.span;
        Ok(Expr {
            span: start.merge(end),
            kind: ExprKind::Let {
                var,
                binding: Box::new(binding),
                body: Box::new(body),
            },
        })
    }

    fn parse_compare_expr(&mut self) -> ParseResult<Expr> {
        let lhs = self.parse_call_expr()?;

        let op = match self.peek_tok() {
            Some(Token::Eq) => CmpOp::Eq,
            Some(Token::Ne) => CmpOp::Ne,
            Some(Token::Lt) => CmpOp::Lt,
            Some(Token::Gt) => CmpOp::Gt,
            Some(Token::Le) => CmpOp::Le,
            Some(Token::Ge) => CmpOp::Ge,
            Some(Token::In) => CmpOp::In,
            Some(Token::Matches) => {
                self.pos += 1;
                let pattern = self.parse_node_pattern()?;
                let end = self.tokens.get(self.pos.saturating_sub(1)).map(|t| t.span).unwrap_or(lhs.span);
                return Ok(Expr {
                    span: lhs.span.merge(end),
                    kind: ExprKind::MatchesPattern {
                        expr: Box::new(lhs),
                        pattern,
                    },
                });
            }
            _ => return Ok(lhs),
        };
        self.pos += 1;
        let rhs = self.parse_call_expr()?;
        let span = lhs.span.merge(rhs.span);
        Ok(Expr {
            span,
            kind: ExprKind::Compare {
                lhs: Box::new(lhs),
                op,
                rhs: Box::new(rhs),
            },
        })
    }

    /// Parse a call-expression chain: `primary(.method(args))*` or `primary.field`
    fn parse_call_expr(&mut self) -> ParseResult<Expr> {
        let mut expr = self.parse_primary()?;
        while self.eat(&Token::Dot) {
            let (method, method_span) = self.expect_ident()?;
            // Field access `n.name` and method call `n.method(args)` share this path.
            // If no `(` follows, treat as zero-arg method (field accessor).
            let args = if self.eat(&Token::LParen) {
                let mut args = Vec::new();
                while self.peek_tok() != Some(&Token::RParen) {
                    args.push(self.parse_expr()?);
                    if !self.eat(&Token::Comma) {
                        break;
                    }
                }
                self.expect(&Token::RParen, "`)`")?;
                args
            } else {
                Vec::new()
            };
            let end = self.tokens.get(self.pos.saturating_sub(1))
                .map(|t| t.span)
                .unwrap_or(method_span);
            let span = expr.span.merge(end);
            expr = Expr {
                span,
                kind: ExprKind::MethodCall {
                    receiver: Box::new(expr),
                    method,
                    args,
                },
            };
        }
        Ok(expr)
    }

    fn parse_primary(&mut self) -> ParseResult<Expr> {
        let st = self.peek().cloned().ok_or(ParseError::UnexpectedEof {
            expected: "expression".to_owned(),
        })?;
        match &st.token {
            Token::LParen => {
                self.pos += 1;
                // Could be exists/forall which have already been consumed, just a paren group
                let inner = self.parse_expr()?;
                let end = self.expect(&Token::RParen, "`)`")?.span;
                Ok(Expr {
                    span: st.span.merge(end),
                    kind: ExprKind::Paren(Box::new(inner)),
                })
            }
            Token::Exists => {
                self.pos += 1;
                self.expect(&Token::LParen, "`(`")?;
                let (var, _) = self.expect_ident()?;
                self.expect(&Token::Colon, "`:`")?;
                let ty = self.parse_type_expr()?;
                self.expect(&Token::Pipe, "`|`")?;
                let body = self.parse_expr()?;
                let end = self.expect(&Token::RParen, "`)`")?.span;
                Ok(Expr {
                    span: st.span.merge(end),
                    kind: ExprKind::Exists {
                        var,
                        ty,
                        body: Box::new(body),
                    },
                })
            }
            Token::Forall => {
                self.pos += 1;
                self.expect(&Token::LParen, "`(`")?;
                let (var, _) = self.expect_ident()?;
                self.expect(&Token::Colon, "`:`")?;
                let ty = self.parse_type_expr()?;
                self.expect(&Token::Pipe, "`|`")?;
                let body = self.parse_expr()?;
                let end = self.expect(&Token::RParen, "`)`")?.span;
                Ok(Expr {
                    span: st.span.merge(end),
                    kind: ExprKind::Forall {
                        var,
                        ty,
                        body: Box::new(body),
                    },
                })
            }
            Token::Ident => {
                let name = st.text.clone();
                let start = st.span;
                self.pos += 1;
                // Check if this is a function call
                if self.eat(&Token::LParen) {
                    let mut args = Vec::new();
                    while self.peek_tok() != Some(&Token::RParen) {
                        args.push(self.parse_expr()?);
                        if !self.eat(&Token::Comma) {
                            break;
                        }
                    }
                    let end = self.expect(&Token::RParen, "`)`")?.span;
                    Ok(Expr {
                        span: start.merge(end),
                        kind: ExprKind::Call { name, args },
                    })
                } else {
                    Ok(Expr {
                        span: start,
                        kind: ExprKind::Ident(name),
                    })
                }
            }
            Token::StringLit => {
                let (s, span) = self.expect_string_lit()?;
                Ok(Expr {
                    span,
                    kind: ExprKind::Literal(Literal::Str(s)),
                })
            }
            Token::IntLit => {
                let text = st.text.clone();
                let span = st.span;
                self.pos += 1;
                let n: i64 = text.parse().map_err(|_| ParseError::UnexpectedToken {
                    found: text.clone(),
                    expected: "integer literal".to_owned(),
                    span,
                })?;
                Ok(Expr {
                    span,
                    kind: ExprKind::Literal(Literal::Int(n)),
                })
            }
            Token::FloatLit => {
                let text = st.text.clone();
                let span = st.span;
                self.pos += 1;
                let n: f64 = text.parse().map_err(|_| ParseError::UnexpectedToken {
                    found: text.clone(),
                    expected: "float literal".to_owned(),
                    span,
                })?;
                Ok(Expr {
                    span,
                    kind: ExprKind::Literal(Literal::Float(n)),
                })
            }
            Token::True => {
                let span = st.span;
                self.pos += 1;
                Ok(Expr { span, kind: ExprKind::Literal(Literal::Bool(true)) })
            }
            Token::False => {
                let span = st.span;
                self.pos += 1;
                Ok(Expr { span, kind: ExprKind::Literal(Literal::Bool(false)) })
            }
            Token::Null => {
                let span = st.span;
                self.pos += 1;
                Ok(Expr { span, kind: ExprKind::Literal(Literal::Null) })
            }
            Token::RegexLit => {
                let raw = st.text.clone();
                let span = st.span;
                self.pos += 1;
                Ok(Expr {
                    span,
                    kind: ExprKind::Literal(Literal::Regex(raw)),
                })
            }
            Token::LBracket => {
                let start = st.span;
                self.pos += 1;
                let mut items = Vec::new();
                while self.peek_tok() != Some(&Token::RBracket) {
                    let lit = self.parse_literal()?;
                    items.push(lit);
                    if !self.eat(&Token::Comma) {
                        break;
                    }
                }
                let end = self.expect(&Token::RBracket, "`]`")?.span;
                Ok(Expr {
                    span: start.merge(end),
                    kind: ExprKind::Literal(Literal::List(items)),
                })
            }
            _ => Err(ParseError::UnexpectedToken {
                found: format!("{:?}", st.token),
                expected: "expression".to_owned(),
                span: st.span,
            }),
        }
    }

    fn parse_literal(&mut self) -> ParseResult<Literal> {
        let st = self.peek().cloned().ok_or(ParseError::UnexpectedEof {
            expected: "literal".to_owned(),
        })?;
        match &st.token {
            Token::StringLit => {
                let (s, _) = self.expect_string_lit()?;
                Ok(Literal::Str(s))
            }
            Token::IntLit => {
                let text = st.text.clone();
                self.pos += 1;
                Ok(Literal::Int(text.parse().unwrap_or(0)))
            }
            Token::FloatLit => {
                let text = st.text.clone();
                self.pos += 1;
                Ok(Literal::Float(text.parse().unwrap_or(0.0)))
            }
            Token::True => { self.pos += 1; Ok(Literal::Bool(true)) }
            Token::False => { self.pos += 1; Ok(Literal::Bool(false)) }
            Token::Null => { self.pos += 1; Ok(Literal::Null) }
            Token::RegexLit => {
                let raw = st.text.clone();
                self.pos += 1;
                Ok(Literal::Regex(raw))
            }
            _ => Err(ParseError::UnexpectedToken {
                found: format!("{:?}", st.token),
                expected: "literal".to_owned(),
                span: st.span,
            }),
        }
    }

    fn parse_bool_lit(&mut self) -> ParseResult<bool> {
        match self.peek_tok() {
            Some(Token::True) => { self.pos += 1; Ok(true) }
            Some(Token::False) => { self.pos += 1; Ok(false) }
            Some(_) => {
                let st = self.peek().unwrap();
                Err(ParseError::UnexpectedToken {
                    found: format!("{:?}", st.token),
                    expected: "true | false".to_owned(),
                    span: st.span,
                })
            }
            None => Err(ParseError::UnexpectedEof { expected: "bool literal".to_owned() }),
        }
    }

    fn parse_int_lit(&mut self) -> ParseResult<i64> {
        match self.peek().cloned() {
            Some(st) if st.token == Token::IntLit => {
                self.pos += 1;
                Ok(st.text.parse().unwrap_or(0))
            }
            Some(st) => Err(ParseError::UnexpectedToken {
                found: format!("{:?}", st.token),
                expected: "integer literal".to_owned(),
                span: st.span,
            }),
            None => Err(ParseError::UnexpectedEof { expected: "integer literal".to_owned() }),
        }
    }

    /// Parse an inline node pattern: `TypeExpr { field: expr, ... }`
    fn parse_node_pattern(&mut self) -> ParseResult<NodePattern> {
        let ty = self.parse_type_expr()?;
        let fields = if self.eat(&Token::LBrace) {
            let mut fields = Vec::new();
            while self.peek_tok() != Some(&Token::RBrace) {
                let (field, _) = self.expect_ident()?;
                self.expect(&Token::Colon, "`:`")?;
                let val = self.parse_expr()?;
                fields.push((field, val));
                if !self.eat(&Token::Comma) {
                    break;
                }
            }
            self.expect(&Token::RBrace, "`}`")?;
            fields
        } else {
            Vec::new()
        };
        Ok(NodePattern { ty, fields })
    }

    // ── Named declarations ────────────────────────────────────────────────────

    fn parse_param_list(&mut self) -> ParseResult<Vec<Param>> {
        self.expect(&Token::LParen, "`(`")?;
        let mut params = Vec::new();
        while self.peek_tok() != Some(&Token::RParen) {
            let (name, span) = self.expect_ident()?;
            self.expect(&Token::Colon, "`:`")?;
            let ty = self.parse_type_expr()?;
            let end = self.tokens.get(self.pos.saturating_sub(1)).map(|t| t.span).unwrap_or(span);
            params.push(Param { span: span.merge(end), name, ty });
            if !self.eat(&Token::Comma) {
                break;
            }
        }
        self.expect(&Token::RParen, "`)`")?;
        Ok(params)
    }

    fn parse_predicate_def(&mut self) -> ParseResult<PredicateDef> {
        let start = self.current_span();
        self.expect(&Token::Pred, "`pred`")?;
        let (name, _) = self.expect_ident()?;
        let params = self.parse_param_list()?;
        // Support both `= expr` and `{ expr }` body forms.
        let body = if self.eat(&Token::LBrace) {
            let body = self.parse_expr()?;
            self.expect(&Token::RBrace, "`}`")?;
            body
        } else {
            self.expect(&Token::Assign, "`=`")?;
            self.parse_expr()?
        };
        let end = body.span;
        Ok(PredicateDef { span: start.merge(end), name, params, body })
    }

    fn parse_find_expr(&mut self) -> ParseResult<FindExpr> {
        let start = self.current_span();
        self.expect(&Token::Find, "`find`")?;
        let bindings = self.parse_binding_list()?;
        // `where <condition>` is optional — if omitted, condition defaults to `true`
        let (condition, end) = if self.peek_tok() == Some(&Token::Where) {
            self.pos += 1; // consume `where`
            let cond = self.parse_expr()?;
            let e = cond.span;
            (cond, e)
        } else {
            let sp = self.current_span();
            let cond = Expr { span: sp, kind: ExprKind::Literal(Literal::Bool(true)) };
            (cond, sp)
        };
        Ok(FindExpr { span: start.merge(end), bindings, condition })
    }

    fn parse_find_expr_alternatives(&mut self) -> ParseResult<Vec<FindExpr>> {
        let mut alts = Vec::new();
        alts.push(self.parse_find_expr()?);
        // alternatives joined by `or` at the top level
        while self.peek_tok() == Some(&Token::Or) {
            // peek ahead to see if the next is `find`
            if self.tokens.get(self.pos + 1).map(|t| &t.token) == Some(&Token::Find) {
                self.pos += 1; // consume `or`
                alts.push(self.parse_find_expr()?);
            } else {
                break;
            }
        }
        Ok(alts)
    }

    fn parse_source_def(&mut self) -> ParseResult<SourceDef> {
        let start = self.current_span();
        self.expect(&Token::Source, "`source`")?;
        let (name, _) = self.expect_ident()?;
        let body = if self.peek_tok() == Some(&Token::LBrace) {
            // Attribute block form: source name { kind: Type, name: "str" }
            vec![self.parse_attr_block_as_find_expr()?]
        } else {
            if self.peek_tok() == Some(&Token::LParen) {
                let params = self.parse_param_list()?;
                let _ = params; // params ignored for now
            }
            self.expect(&Token::Assign, "`=`")?;
            self.parse_find_expr_alternatives()?
        };
        let end = self.tokens.get(self.pos.saturating_sub(1)).map(|t| t.span).unwrap_or(start);
        Ok(SourceDef { span: start.merge(end), name, params: vec![], body })
    }

    fn parse_sink_def(&mut self) -> ParseResult<SinkDef> {
        let start = self.current_span();
        self.expect(&Token::Sink, "`sink`")?;
        let (name, _) = self.expect_ident()?;
        let body = if self.peek_tok() == Some(&Token::LBrace) {
            vec![self.parse_attr_block_as_find_expr()?]
        } else {
            if self.peek_tok() == Some(&Token::LParen) {
                let params = self.parse_param_list()?;
                let _ = params;
            }
            self.expect(&Token::Assign, "`=`")?;
            self.parse_find_expr_alternatives()?
        };
        let end = self.tokens.get(self.pos.saturating_sub(1)).map(|t| t.span).unwrap_or(start);
        Ok(SinkDef { span: start.merge(end), name, params: vec![], body })
    }

    /// Parse `{ kind: Type, name: "str", ... }` and synthesize a `FindExpr`.
    fn parse_attr_block_as_find_expr(&mut self) -> ParseResult<FindExpr> {
        let start = self.current_span();
        self.expect(&Token::LBrace, "`{`")?;

        let mut kind_ty = TypeExpr::Node;
        let mut name_constraint: Option<String> = None;

        while self.peek_tok() != Some(&Token::RBrace) {
            let (key, _) = self.expect_ident()?;
            self.expect(&Token::Colon, "`:`")?;
            match key.as_str() {
                "kind" => { kind_ty = self.parse_type_expr()?; }
                "name" => { name_constraint = Some(self.expect_string_lit()?.0); }
                _ => { let _ = self.parse_expr()?; } // skip unknown attrs
            }
            self.eat(&Token::Comma);
        }
        let end = self.expect(&Token::RBrace, "`}`")?.span;
        let span = start.merge(end);

        // Synthesize: find _n: Kind where _n.name == "str"
        let var = "_n".to_owned();
        let binding = Binding {
            span,
            name: var.clone(),
            ty: kind_ty,
        };
        let condition = if let Some(name_val) = name_constraint {
            Expr {
                span,
                kind: ExprKind::Compare {
                    lhs: Box::new(Expr {
                        span,
                        kind: ExprKind::MethodCall {
                            receiver: Box::new(Expr { span, kind: ExprKind::Ident(var) }),
                            method: "name".to_owned(),
                            args: vec![],
                        },
                    }),
                    op: CmpOp::Eq,
                    rhs: Box::new(Expr {
                        span,
                        kind: ExprKind::Literal(Literal::Str(name_val)),
                    }),
                },
            }
        } else {
            Expr { span, kind: ExprKind::Literal(Literal::Bool(true)) }
        };
        Ok(FindExpr { span, bindings: vec![binding], condition })
    }

    fn parse_sanitizer_def(&mut self) -> ParseResult<SanitizerDef> {
        let start = self.current_span();
        self.expect(&Token::Sanitizer, "`sanitizer`")?;
        let (name, _) = self.expect_ident()?;
        let params = if self.peek_tok() == Some(&Token::LParen) {
            self.parse_param_list()?
        } else {
            vec![]
        };
        self.expect(&Token::Assign, "`=`")?;
        let body = self.parse_find_expr_alternatives()?;
        let end = self.tokens.get(self.pos.saturating_sub(1)).map(|t| t.span).unwrap_or(start);
        Ok(SanitizerDef { span: start.merge(end), name, params, body })
    }

    fn parse_propagator_def(&mut self) -> ParseResult<PropagatorDef> {
        let start = self.current_span();
        self.expect(&Token::Propagator, "`propagator`")?;
        let (name, _) = self.expect_ident()?;
        let params = self.parse_param_list()?;
        self.expect(&Token::Assign, "`=`")?;
        let body = self.parse_prop_body()?;
        let end = self.tokens.get(self.pos.saturating_sub(1)).map(|t| t.span).unwrap_or(start);
        Ok(PropagatorDef { span: start.merge(end), name, params, body })
    }

    fn parse_prop_body(&mut self) -> ParseResult<PropBody> {
        self.expect(&Token::Pattern, "`pattern`")?;
        self.expect(&Token::Colon, "`:`")?;
        let pattern = self.parse_expr()?;
        self.expect(&Token::From, "`from`")?;
        self.expect(&Token::Colon, "`:`")?;
        let (from_binding, _) = self.expect_ident()?;
        self.expect(&Token::To, "`to`")?;
        self.expect(&Token::Colon, "`:`")?;
        let (to_binding, _) = self.expect_ident()?;
        Ok(PropBody { pattern, from_binding, to_binding })
    }
}

// ── Helper: unescape a quoted string literal ──────────────────────────────────

fn unescape_string(raw: &str) -> String {
    let inner = raw.trim_matches('"');
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some('\'') => out.push('\''),
                Some(other) => { out.push('\\'); out.push(other); }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}
