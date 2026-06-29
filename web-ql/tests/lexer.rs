use web_ql::lexer::{Token, lex};

fn tokens(src: &str) -> Vec<Token> {
    let (toks, errs) = lex(src);
    assert!(errs.is_empty(), "unexpected lex errors: {errs:?}");
    toks.into_iter().map(|t| t.token).collect()
}

fn has_errors(src: &str) -> bool {
    let (_, errs) = lex(src);
    !errs.is_empty()
}

// ── Keywords ──────────────────────────────────────────────────────────────────

#[test]
fn keyword_rule() {
    assert_eq!(tokens("rule"), vec![Token::Rule]);
}

#[test]
fn keyword_find() {
    assert_eq!(tokens("find"), vec![Token::Find]);
}

#[test]
fn keyword_where() {
    assert_eq!(tokens("where"), vec![Token::Where]);
}

#[test]
fn keyword_taint() {
    assert_eq!(tokens("taint"), vec![Token::Taint]);
}

#[test]
fn keyword_source_sink_sanitizer() {
    assert_eq!(
        tokens("source sink sanitizer propagator"),
        vec![Token::Source, Token::Sink, Token::Sanitizer, Token::Propagator]
    );
}

#[test]
fn keyword_pred() {
    assert_eq!(tokens("pred"), vec![Token::Pred]);
}

#[test]
fn keyword_exists_forall() {
    assert_eq!(tokens("exists forall"), vec![Token::Exists, Token::Forall]);
}

#[test]
fn keyword_and_or_not() {
    assert_eq!(tokens("and or not"), vec![Token::And, Token::Or, Token::Not]);
}

#[test]
fn keyword_matches_in() {
    assert_eq!(tokens("matches in"), vec![Token::Matches, Token::In]);
}

#[test]
fn keyword_severity_variants() {
    assert_eq!(
        tokens("critical high medium low info"),
        vec![Token::Critical, Token::High, Token::Medium, Token::Low, Token::Info]
    );
}

#[test]
fn keyword_severity_field() {
    assert_eq!(tokens("severity"), vec![Token::Severity]);
}

#[test]
fn keyword_languages_tags_message() {
    assert_eq!(
        tokens("languages tags message"),
        vec![Token::Languages, Token::Tags, Token::Message]
    );
}

#[test]
fn keyword_bool_literals() {
    assert_eq!(tokens("true false"), vec![Token::True, Token::False]);
}

#[test]
fn keyword_null() {
    assert_eq!(tokens("null"), vec![Token::Null]);
}

#[test]
fn type_keywords() {
    let src = "Node Expr Stmt Decl Call MethodDef ClassDef Identifier Literal";
    let toks = tokens(src);
    assert_eq!(
        toks,
        vec![
            Token::TyNode, Token::TyExpr, Token::TyStmt, Token::TyDecl, Token::TyCall,
            Token::TyMethodDef, Token::TyClassDef, Token::TyIdentifier, Token::TyLiteral,
        ]
    );
}

#[test]
fn taint_block_keywords() {
    assert_eq!(
        tokens("sources sinks sanitizers propagators"),
        vec![Token::Sources, Token::Sinks, Token::Sanitizers, Token::Propagators]
    );
}

// ── Operators and punctuation ─────────────────────────────────────────────────

#[test]
fn comparison_operators() {
    assert_eq!(
        tokens("== != < > <= >="),
        vec![Token::Eq, Token::Ne, Token::Lt, Token::Gt, Token::Le, Token::Ge]
    );
}

#[test]
fn punctuation() {
    assert_eq!(
        tokens("{ } ( ) [ ] , : . = |"),
        vec![
            Token::LBrace, Token::RBrace,
            Token::LParen, Token::RParen,
            Token::LBracket, Token::RBracket,
            Token::Comma, Token::Colon, Token::Dot,
            Token::Assign, Token::Pipe,
        ]
    );
}

// ── Identifier ────────────────────────────────────────────────────────────────

#[test]
fn ident_simple() {
    assert_eq!(tokens("foo"), vec![Token::Ident]);
}

#[test]
fn ident_with_underscore() {
    assert_eq!(tokens("my_var_123"), vec![Token::Ident]);
}

#[test]
fn ident_starts_with_underscore() {
    assert_eq!(tokens("_private"), vec![Token::Ident]);
}

#[test]
fn multiple_idents() {
    let (toks, _) = lex("foo bar baz");
    assert_eq!(toks.len(), 3);
    assert!(toks.iter().all(|t| t.token == Token::Ident));
    assert_eq!(toks[0].text, "foo");
    assert_eq!(toks[1].text, "bar");
    assert_eq!(toks[2].text, "baz");
}

// ── String literals ───────────────────────────────────────────────────────────

#[test]
fn string_literal_basic() {
    let (toks, errs) = lex(r#""hello""#);
    assert!(errs.is_empty());
    assert_eq!(toks.len(), 1);
    assert_eq!(toks[0].token, Token::StringLit);
}

#[test]
fn string_literal_with_spaces() {
    let (toks, _) = lex(r#""hello world""#);
    assert_eq!(toks[0].token, Token::StringLit);
}

#[test]
fn string_literal_with_escape() {
    let (toks, errs) = lex(r#""hello \"world\"""#);
    assert!(errs.is_empty());
    assert_eq!(toks[0].token, Token::StringLit);
}

#[test]
fn string_literal_empty() {
    let (toks, errs) = lex(r#""""#);
    assert!(errs.is_empty());
    assert_eq!(toks[0].token, Token::StringLit);
}

// ── Numeric literals ──────────────────────────────────────────────────────────

#[test]
fn int_literal() {
    let (toks, _) = lex("42");
    assert_eq!(toks[0].token, Token::IntLit);
    assert_eq!(toks[0].text, "42");
}

#[test]
fn int_literal_zero() {
    let (toks, _) = lex("0");
    assert_eq!(toks[0].token, Token::IntLit);
}

#[test]
fn float_literal() {
    let (toks, _) = lex("3.14");
    assert_eq!(toks[0].token, Token::FloatLit);
}

#[test]
fn float_literal_with_exponent() {
    let (toks, _) = lex("1.5e10");
    assert_eq!(toks[0].token, Token::FloatLit);
}

#[test]
fn int_vs_float_disambiguation() {
    let (toks, _) = lex("1 1.0");
    assert_eq!(toks[0].token, Token::IntLit);
    assert_eq!(toks[1].token, Token::FloatLit);
}

// ── Regex literals ────────────────────────────────────────────────────────────

#[test]
fn regex_literal() {
    let (toks, errs) = lex("/pattern/gi");
    assert!(errs.is_empty(), "errors: {errs:?}");
    assert_eq!(toks[0].token, Token::RegexLit);
}

#[test]
fn regex_literal_no_flags() {
    let (toks, errs) = lex("/foo.*/");
    assert!(errs.is_empty(), "errors: {errs:?}");
    assert_eq!(toks[0].token, Token::RegexLit);
}

// ── Comments ──────────────────────────────────────────────────────────────────

#[test]
fn line_comment_skipped() {
    let (toks, _) = lex("foo // this is a comment\nbar");
    assert_eq!(toks.len(), 2);
    assert_eq!(toks[0].text, "foo");
    assert_eq!(toks[1].text, "bar");
}

#[test]
fn block_comment_skipped() {
    let (toks, _) = lex("foo /* this is\na block comment */ bar");
    assert_eq!(toks.len(), 2);
    assert_eq!(toks[0].text, "foo");
    assert_eq!(toks[1].text, "bar");
}

#[test]
fn comment_only_input() {
    let (toks, errs) = lex("// just a comment");
    assert!(errs.is_empty());
    assert!(toks.is_empty());
}

// ── Whitespace ────────────────────────────────────────────────────────────────

#[test]
fn whitespace_only() {
    let (toks, errs) = lex("   \t\n  ");
    assert!(errs.is_empty());
    assert!(toks.is_empty());
}

#[test]
fn empty_input() {
    let (toks, errs) = lex("");
    assert!(errs.is_empty());
    assert!(toks.is_empty());
}

// ── Error handling ────────────────────────────────────────────────────────────

#[test]
fn unknown_char_produces_error() {
    assert!(has_errors("@bad"));
}

#[test]
fn unknown_char_offset_reported() {
    let (_, errs) = lex("foo @bar");
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0].span.start, 4);
}

// ── Span tracking ────────────────────────────────────────────────────────────

#[test]
fn spans_are_byte_accurate() {
    let src = "rule \"test\"";
    let (toks, _) = lex(src);
    assert_eq!(toks.len(), 2);
    // "rule" occupies bytes 0..4
    assert_eq!(toks[0].span.start, 0);
    assert_eq!(toks[0].span.end, 4);
    // "\"test\"" occupies bytes 5..11
    assert_eq!(toks[1].span.start, 5);
    assert_eq!(toks[1].span.end, 11);
}

// ── Full rule tokenization ────────────────────────────────────────────────────

#[test]
fn tokenize_minimal_rule() {
    let src = r#"rule "xss" { find n: Call where n.name() == "eval" }"#;
    let (toks, errs) = lex(src);
    assert!(errs.is_empty(), "lex errors: {errs:?}");
    // Should produce a non-empty token stream without errors
    assert!(!toks.is_empty());
    // First two tokens: Rule then StringLit
    assert_eq!(toks[0].token, Token::Rule);
    assert_eq!(toks[1].token, Token::StringLit);
    assert_eq!(toks[1].text, "\"xss\"");
}
