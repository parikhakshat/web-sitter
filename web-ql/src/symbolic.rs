use std::collections::HashMap;
use web_sitter::{Cpg, IrNodeKind, LiteralKind, NodeId};

/// The result of symbolically evaluating a CPG expression node.
#[derive(Clone, Debug, PartialEq)]
pub enum SymbolicValue {
    Int(i64),
    Bool(bool),
    Str(String),
    /// Expression is not constant-foldable (contains variables, calls, etc.).
    Unknown,
}

/// Lightweight constant-folder / symbolic evaluator over CPG expression nodes.
///
/// Handles:
/// - Integer / boolean / string / null literals (all languages)
/// - Binary arithmetic and comparison operators on constant operands
/// - Unary negation, bitwise-not, logical-not
/// - Transparent parenthesized expressions and casts
/// - sizeof expressions with a known `array_size` field
///
/// Results are memoised per `SymbolicEval` instance to avoid re-visiting nodes.
pub struct SymbolicEval<'a> {
    cpg: &'a Cpg,
    cache: HashMap<NodeId, SymbolicValue>,
}

impl<'a> SymbolicEval<'a> {
    pub fn new(cpg: &'a Cpg) -> Self {
        Self { cpg, cache: HashMap::new() }
    }

    /// Evaluate `node_id` to a `SymbolicValue`, with memoisation.
    pub fn eval(&mut self, node_id: NodeId) -> SymbolicValue {
        if let Some(v) = self.cache.get(&node_id) {
            return v.clone();
        }
        let v = self.compute(node_id);
        self.cache.insert(node_id, v.clone());
        v
    }

    fn compute(&mut self, node_id: NodeId) -> SymbolicValue {
        let node = match self.cpg.ast.get(&node_id) {
            Some(n) => n.clone(),
            None => return SymbolicValue::Unknown,
        };

        // ── Literals ─────────────────────────────────────────────────────────
        if node.kind == IrNodeKind::Literal {
            if let Some(ref text) = node.text {
                match &node.lit_kind {
                    Some(LiteralKind::Integer) => {
                        return parse_int(text)
                            .map(SymbolicValue::Int)
                            .unwrap_or(SymbolicValue::Unknown);
                    }
                    Some(LiteralKind::Bool) => {
                        return SymbolicValue::Bool(matches!(
                            text.as_str(),
                            "true" | "True" | "TRUE"
                        ));
                    }
                    Some(LiteralKind::String) | Some(LiteralKind::Template) => {
                        return SymbolicValue::Str(text.clone());
                    }
                    Some(LiteralKind::Null) => {
                        return SymbolicValue::Int(0);
                    }
                    _ => {
                        // Best-effort for unlabelled literals
                        if let Some(n) = parse_int(text) {
                            return SymbolicValue::Int(n);
                        }
                        if matches!(text.as_str(), "true" | "True" | "TRUE") {
                            return SymbolicValue::Bool(true);
                        }
                        if matches!(text.as_str(), "false" | "False" | "FALSE") {
                            return SymbolicValue::Bool(false);
                        }
                    }
                }
            }
            return SymbolicValue::Unknown;
        }

        // ── Parenthesized / cast: transparent ────────────────────────────────
        if node.is_parenthesized() || node.kind == IrNodeKind::Cast {
            // Evaluate the last (innermost) child which is the value child
            if let Some(&cid) = node.children.last() {
                return self.eval(cid);
            }
        }

        // ── sizeof expression with a populated array_size field ───────────────
        if node.kind == IrNodeKind::SizeofExpr {
            if let Some(sz) = node.array_size {
                return SymbolicValue::Int(sz);
            }
        }

        // ── Binary arithmetic / comparison ────────────────────────────────────
        if node.kind == IrNodeKind::BinaryOp && node.children.len() >= 2 {
            let lhs_id = node.children[0];
            let rhs_id = *node.children.last().unwrap();
            let lv = self.eval(lhs_id);
            let rv = self.eval(rhs_id);
            let op = node.operator.as_deref().unwrap_or("");

            if let (SymbolicValue::Int(l), SymbolicValue::Int(r)) = (&lv, &rv) {
                let (l, r) = (*l, *r);
                return match op {
                    "+"  => SymbolicValue::Int(l.wrapping_add(r)),
                    "-"  => SymbolicValue::Int(l.wrapping_sub(r)),
                    "*"  => SymbolicValue::Int(l.wrapping_mul(r)),
                    "/"  if r != 0 => SymbolicValue::Int(l / r),
                    "%"  if r != 0 => SymbolicValue::Int(l % r),
                    "**" => SymbolicValue::Int(l.wrapping_pow(r.max(0) as u32)),
                    "<<" if r >= 0 && r < 64 => SymbolicValue::Int(l.wrapping_shl(r as u32)),
                    ">>" if r >= 0 && r < 64 => SymbolicValue::Int(l.wrapping_shr(r as u32)),
                    "&"  => SymbolicValue::Int(l & r),
                    "|"  => SymbolicValue::Int(l | r),
                    "^"  => SymbolicValue::Int(l ^ r),
                    "==" => SymbolicValue::Bool(l == r),
                    "!=" | "<>" => SymbolicValue::Bool(l != r),
                    "<"  => SymbolicValue::Bool(l < r),
                    "<=" => SymbolicValue::Bool(l <= r),
                    ">"  => SymbolicValue::Bool(l > r),
                    ">=" => SymbolicValue::Bool(l >= r),
                    _ => SymbolicValue::Unknown,
                };
            }
            // Boolean logic
            if let (SymbolicValue::Bool(l), SymbolicValue::Bool(r)) = (&lv, &rv) {
                let (l, r) = (*l, *r);
                if let Some(v) = match op {
                    "&&" | "and" => Some(SymbolicValue::Bool(l && r)),
                    "||" | "or"  => Some(SymbolicValue::Bool(l || r)),
                    "==" => Some(SymbolicValue::Bool(l == r)),
                    "!=" => Some(SymbolicValue::Bool(l != r)),
                    _ => None,
                } {
                    return v;
                }
            }
            // String concatenation
            if op == "+" {
                if let (SymbolicValue::Str(l), SymbolicValue::Str(r)) = (&lv, &rv) {
                    return SymbolicValue::Str(format!("{l}{r}"));
                }
            }
        }

        // ── Unary operations ─────────────────────────────────────────────────
        if node.kind == IrNodeKind::UnaryOp {
            let op = node.operator.as_deref().unwrap_or("");
            if let Some(&cid) = node.children.first() {
                let cv = self.eval(cid);
                return match (op, cv) {
                    ("-",  SymbolicValue::Int(n))  => SymbolicValue::Int(-n),
                    ("~",  SymbolicValue::Int(n))  => SymbolicValue::Int(!n),
                    ("!",  SymbolicValue::Bool(b)) => SymbolicValue::Bool(!b),
                    ("not", SymbolicValue::Bool(b)) => SymbolicValue::Bool(!b),
                    ("!",  SymbolicValue::Int(n))  => SymbolicValue::Bool(n == 0),
                    ("+",  v @ SymbolicValue::Int(_)) => v,
                    _ => SymbolicValue::Unknown,
                };
            }
        }

        SymbolicValue::Unknown
    }

    /// Evaluate to an integer if the expression is constant-foldable.
    pub fn eval_int(&mut self, node_id: NodeId) -> Option<i64> {
        match self.eval(node_id) {
            SymbolicValue::Int(n) => Some(n),
            _ => None,
        }
    }

    /// Evaluate to a boolean if the expression is constant-foldable.
    pub fn eval_bool(&mut self, node_id: NodeId) -> Option<bool> {
        match self.eval(node_id) {
            SymbolicValue::Bool(b) => Some(b),
            _ => None,
        }
    }

    /// True if the expression evaluates to a concrete value (not Unknown).
    pub fn is_const(&mut self, node_id: NodeId) -> bool {
        !matches!(self.eval(node_id), SymbolicValue::Unknown)
    }
}

// ── Integer literal parser ────────────────────────────────────────────────────

/// Parse a numeric literal string (C/Java/Python/Go/Rust/JS styles) to i64.
/// Handles hex (0x…), binary (0b…), octal (0o…/0…), and decimal.
/// Strips common suffixes (ULL, LL, L, U, u, n, f, etc.).
pub(crate) fn parse_int(raw: &str) -> Option<i64> {
    let s = raw.trim();
    // Strip trailing integer type suffixes (u/U/l/L/n).
    // Do NOT strip 'f'/'F' — those are valid hex digits (e.g. 0xFF).
    let s = s.trim_end_matches(|c: char| matches!(c, 'u' | 'U' | 'l' | 'L' | 'n'));
    // Remove Python/Rust visual separators
    let no_sep: String = s.chars().filter(|&c| c != '_' && c != '\'').collect();
    let s = no_sep.as_str();
    if s.is_empty() {
        return None;
    }
    let (neg, s) = if let Some(rest) = s.strip_prefix('-') { (true, rest) } else { (false, s) };
    let val: i64 = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).ok()?
    } else if let Some(bin) = s.strip_prefix("0b").or_else(|| s.strip_prefix("0B")) {
        i64::from_str_radix(bin, 2).ok()?
    } else if let Some(oct) = s.strip_prefix("0o").or_else(|| s.strip_prefix("0O")) {
        i64::from_str_radix(oct, 8).ok()?
    } else if s.starts_with('0') && s.len() > 1 && s.bytes().all(|b| b.is_ascii_digit()) {
        // C-style octal: leading zero
        i64::from_str_radix(&s[1..], 8).ok()?
    } else {
        s.parse::<i64>().ok()?
    };
    Some(if neg { val.wrapping_neg() } else { val })
}
