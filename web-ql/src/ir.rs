use std::collections::HashMap;
use regex::Regex;
use web_sitter::IrNodeKind;
use crate::ast::{CmpOp, Language, Literal, Severity, TypeExpr};

// ── String matcher ────────────────────────────────────────────────────────────

/// A compiled string predicate — either exact, glob-style prefix/suffix, or regex.
#[derive(Debug, Clone)]
pub enum StringMatcher {
    Exact(String),
    /// Matches any string containing this substring
    Contains(String),
    /// Prefix* glob
    Prefix(String),
    /// *Suffix glob
    Suffix(String),
    /// Full regex
    Regex(Regex),
    /// Matches any string in a fixed list
    OneOf(Vec<String>),
}

impl StringMatcher {
    pub fn matches(&self, s: &str) -> bool {
        match self {
            Self::Exact(e) => s == e,
            Self::Contains(sub) => s.contains(sub.as_str()),
            Self::Prefix(p) => s.starts_with(p.as_str()),
            Self::Suffix(suf) => s.ends_with(suf.as_str()),
            Self::Regex(re) => re.is_match(s),
            Self::OneOf(list) => list.iter().any(|e| e == s),
        }
    }

    pub fn from_literal(lit: &str) -> Self {
        if lit.starts_with('*') && lit.ends_with('*') && lit.len() > 2 {
            Self::Contains(lit[1..lit.len() - 1].to_owned())
        } else if lit.starts_with('*') {
            Self::Suffix(lit[1..].to_owned())
        } else if lit.ends_with('*') {
            Self::Prefix(lit[..lit.len() - 1].to_owned())
        } else {
            Self::Exact(lit.to_owned())
        }
    }
}

// ── Seed hints ────────────────────────────────────────────────────────────────

/// Hints that tell Phase 1 which IrNodes to extract as seeds before full eval.
#[derive(Debug, Clone)]
pub enum SeedHint {
    /// Any node of this kind
    Kind(IrNodeKind),
    /// A Call node whose callee matches
    CalleeMatch(StringMatcher),
    /// A MethodDef node whose name matches
    MethodNameMatch(StringMatcher),
    /// A Literal node
    AnyLiteral,
    /// All nodes (fallback; used when no more specific hint is derivable)
    AllNodes,
}

// ── Query plan ────────────────────────────────────────────────────────────────

/// A compiled, type-checked query plan tree.
#[derive(Debug, Clone)]
pub enum QueryPlan {
    /// All children must hold
    AndAll(Vec<QueryPlan>),
    /// At least one child must hold
    OrAny(Vec<QueryPlan>),
    /// Child must NOT hold
    Not(Box<QueryPlan>),

    /// `exists var: Ty | body`
    Exists {
        var: String,
        kinds: Vec<IrNodeKind>,
        body: Box<QueryPlan>,
    },
    /// `forall var: Ty | body`
    Forall {
        var: String,
        kinds: Vec<IrNodeKind>,
        body: Box<QueryPlan>,
    },

    /// A simple AST-level predicate: compare a method chain against a value.
    AstConstraint(AstConstraint),

    /// CFG-level predicate: node A dominates / post-dominates node B, etc.
    CfgPredicate(CfgPredicate),

    /// DFG-level predicate: data flows from node A to node B.
    DfgPredicate(DfgPredicate),

    /// Full taint check between sources and sinks with sanitizers.
    TaintCheck(TaintSpec),

    /// Recursive predicate group (semi-naive fixpoint).
    FixpointGroup {
        /// Ordered list of predicate names in the SCC
        names: Vec<String>,
        /// Plans for each predicate body (indexed by names order)
        bodies: Vec<QueryPlan>,
    },

    /// Inline structural `matches` pattern
    MatchesPattern {
        var: String,
        ty: TypeExpr,
        fields: Vec<FieldConstraint>,
    },

    /// User-defined predicate call: name(resolved args)
    PredicateCall {
        name: String,
        args: Vec<PlanExpr>,
    },

    /// Trivially true / false (used after constant folding)
    Literal(bool),
}

/// A field constraint inside a `matches` pattern.
#[derive(Debug, Clone)]
pub struct FieldConstraint {
    pub field: String,
    pub constraint: PlanExpr,
}

/// An evaluated expression that appears as a value within a plan (RHS of compare, arg, etc.).
#[derive(Debug, Clone)]
pub enum PlanExpr {
    /// Variable reference — looked up in BindingEnv at eval time
    Var(String),
    /// Constant literal
    Lit(Literal),
    /// Method call chain: `.method(args)` applied to another PlanExpr
    MethodChain {
        receiver: Box<PlanExpr>,
        steps: Vec<MethodStep>,
    },
    /// Binary comparison that yields a bool (used inside expressions)
    Compare {
        lhs: Box<PlanExpr>,
        op: CmpOp,
        rhs: Box<PlanExpr>,
    },
}

#[derive(Debug, Clone)]
pub struct MethodStep {
    pub method: String,
    pub args: Vec<PlanExpr>,
}

// ── AST constraint ────────────────────────────────────────────────────────────

/// A predicate expressed purely over AST-node properties (no CFG/DFG).
#[derive(Debug, Clone)]
pub struct AstConstraint {
    pub lhs: PlanExpr,
    pub op: CmpOp,
    pub rhs: PlanExpr,
}

// ── CFG predicates ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum CfgPredicate {
    /// `a` dominates `b` in the CFG of their enclosing function
    Dominates { a: String, b: String },
    /// `a` post-dominates `b`
    PostDominates { a: String, b: String },
    /// `a` is in the same basic block as `b`
    SameBlock { a: String, b: String },
    /// `a` reaches `b` along control flow (not necessarily dominates)
    CfgReaches { a: String, b: String },
}

// ── DFG predicates ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum DfgPredicate {
    /// Direct data-flow edge from `from` to `to`
    DirectFlow { from: String, to: String },
    /// Transitive (reachability) flow from `from` to `to`
    ReachesFlow { from: String, to: String },
    /// `from` must reach `to` and NOT pass through any node matching `barrier`
    ReachesWithBarrier {
        from: String,
        to: String,
        barrier_kinds: Vec<IrNodeKind>,
    },
}

// ── Taint spec ────────────────────────────────────────────────────────────────

/// The compiled version of a taint clause.
#[derive(Debug, Clone)]
pub struct TaintSpec {
    pub sources: Vec<TaintEndpointRef>,
    pub sinks: Vec<TaintEndpointRef>,
    pub sanitizers: Vec<TaintEndpointRef>,
    pub propagators: Vec<TaintEndpointRef>,
    pub require_interprocedural: bool,
    pub max_call_depth: u32,
    pub require_same_function: bool,
}

impl Default for TaintSpec {
    fn default() -> Self {
        Self {
            sources: Vec::new(),
            sinks: Vec::new(),
            sanitizers: Vec::new(),
            propagators: Vec::new(),
            require_interprocedural: true,
            max_call_depth: 10,
            require_same_function: false,
        }
    }
}

/// A reference to a source/sink/sanitizer/propagator with bound args.
#[derive(Debug, Clone)]
pub struct TaintEndpointRef {
    pub name: String,
    pub args: Vec<PlanExpr>,
}

// ── Binding environment ───────────────────────────────────────────────────────

/// Maps binding names to the IrNode IDs they're currently bound to.
/// Also tracks type information for each binding.
#[derive(Debug, Clone)]
pub struct BindingEnv {
    pub bindings: HashMap<String, BindingValue>,
}

#[derive(Debug, Clone)]
pub enum BindingValue {
    Node(web_sitter::NodeId),
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    Null,
    List(Vec<BindingValue>),
}

impl BindingEnv {
    pub fn new() -> Self {
        Self { bindings: HashMap::new() }
    }

    pub fn insert(&mut self, name: impl Into<String>, val: BindingValue) {
        self.bindings.insert(name.into(), val);
    }

    pub fn get(&self, name: &str) -> Option<&BindingValue> {
        self.bindings.get(name)
    }

    pub fn get_node(&self, name: &str) -> Option<web_sitter::NodeId> {
        match self.bindings.get(name)? {
            BindingValue::Node(id) => Some(*id),
            _ => None,
        }
    }

    pub fn child(&self) -> Self {
        self.clone()
    }
}

impl Default for BindingEnv {
    fn default() -> Self {
        Self::new()
    }
}

// ── Compiled rule ─────────────────────────────────────────────────────────────

/// A fully compiled, type-checked rule ready for evaluation.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub id: String,
    pub severity: Option<Severity>,
    pub languages: Option<Vec<Language>>,
    pub tags: Vec<String>,
    pub message: Option<String>,
    /// All seed kinds across all clauses (union) — used for Phase 1 filtering.
    pub seed_hints: Vec<SeedHint>,
    /// The compiled clause plans. Findings are emitted when ANY clause matches.
    pub clauses: Vec<CompiledClause>,
}

#[derive(Debug, Clone)]
pub enum CompiledClause {
    Search(SearchPlan),
    Taint(TaintSpec),
}

#[derive(Debug, Clone)]
pub struct SearchPlan {
    /// All bindings introduced at the top level of this clause.
    pub root_bindings: Vec<RootBinding>,
    /// The compiled predicate tree evaluated over those bindings.
    pub plan: QueryPlan,
    /// Which variables to include in the finding (all root binding names by default).
    pub report_vars: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RootBinding {
    pub name: String,
    pub ty: TypeExpr,
    pub kinds: Vec<IrNodeKind>,
    /// Derived seed hints from this binding's type + plan context.
    pub hints: Vec<SeedHint>,
}

// ── Rule set ──────────────────────────────────────────────────────────────────

/// The complete set of compiled rules for a scan run.
#[derive(Debug, Clone)]
pub struct RuleSet {
    pub rules: Vec<CompiledRule>,
    /// Pre-computed union of all seed hints across all rules.
    pub global_seed_hints: Vec<SeedHint>,
}

impl RuleSet {
    pub fn new(rules: Vec<CompiledRule>) -> Self {
        let global_seed_hints = rules
            .iter()
            .flat_map(|r| r.seed_hints.iter().cloned())
            .collect();
        Self { rules, global_seed_hints }
    }

    pub fn rules_for_language(&self, lang: Language) -> impl Iterator<Item = &CompiledRule> {
        self.rules.iter().filter(move |r| {
            r.languages.as_ref().map_or(true, |langs| langs.contains(&lang))
        })
    }
}
