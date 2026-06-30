use std::sync::Arc;

use crate::{IrNodeKind, LiteralKind, LoopKind, TryKind};

use crate::cpg_generator::SourceLanguage;


/// Maps tree-sitter node kind strings to language-agnostic `IrNodeKind` values.
///
/// Implement this trait for each tree-sitter language to add CPG support.
/// The CFG, DFG, and call-graph algorithms dispatch on `IrNodeKind` and never
/// need to know which tree-sitter grammar produced the node.
///
/// The C and C++ implementations live in this file; adding a new language
/// (Python, Java, Go, …) only requires implementing this trait.
pub trait LanguageLifter: Send + Sync + 'static {
    /// The tree-sitter language used when constructing the parser.
    fn ts_language(&self) -> tree_sitter::Language;

    /// Primary lift: translate a tree-sitter node kind string → `IrNodeKind`.
    /// Called once per node during the AST walk.
    fn lift_kind(&self, ts_kind: &str) -> IrNodeKind;

    /// Returns the `LoopKind` discriminator for `Loop` nodes.
    /// Only called when `lift_kind(ts_kind) == IrNodeKind::Loop`.
    fn loop_kind(&self, ts_kind: &str) -> LoopKind {
        let _ = ts_kind;
        LoopKind::While
    }

    /// Returns the `TryKind` discriminator for `Try` nodes.
    /// Only called when `lift_kind(ts_kind) == IrNodeKind::Try`.
    fn try_kind(&self, ts_kind: &str) -> TryKind {
        let _ = ts_kind;
        TryKind::Standard
    }

    /// Returns the `LiteralKind` discriminator for `Literal` nodes.
    /// Only called when `lift_kind(ts_kind) == IrNodeKind::Literal`.
    fn lit_kind(&self, ts_kind: &str) -> LiteralKind {
        let _ = ts_kind;
        LiteralKind::Integer
    }

    /// True when this tree-sitter kind introduces a function-scope boundary.
    /// The CPG generator uses this to assign `function_id` to child nodes.
    /// Defaults to checking `lift_kind(ts_kind) == MethodDef || == LambdaDef`.
    fn is_function_scope(&self, ts_kind: &str) -> bool {
        matches!(
            self.lift_kind(ts_kind),
            IrNodeKind::MethodDef | IrNodeKind::LambdaDef
        )
    }

    /// Strip namespace prefixes for security-pattern lookups.
    /// e.g. "std::string::append" → "append". No-op for C.
    fn short_callee_name<'a>(&self, raw: &'a str) -> &'a str {
        raw
    }

    /// Normalize a fully-qualified callee name (e.g. strip leading "::").
    fn normalize_callee_name<'a>(&self, raw: &'a str) -> &'a str {
        raw
    }

    /// True when this language uses exception handling (try/catch/throw).
    fn has_exceptions(&self) -> bool {
        false
    }

    /// True when this language has lambda expressions.
    fn has_lambdas(&self) -> bool {
        false
    }

    /// True when this language supports namespaces.
    fn has_namespaces(&self) -> bool {
        false
    }

    /// True when this language has structured bindings (auto [a,b] = …).
    fn has_structured_bindings(&self) -> bool {
        false
    }

    /// Short display name for the language (e.g. "c", "cpp").
    fn name(&self) -> &str;
}

pub type DynLifter = Arc<dyn LanguageLifter>;

// ── C lifter ─────────────────────────────────────────────────────────────────

pub struct CLifter;

impl LanguageLifter for CLifter {
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_c::LANGUAGE.into()
    }

    fn lift_kind(&self, ts_kind: &str) -> IrNodeKind {
        lift_c_kind(ts_kind)
    }

    fn loop_kind(&self, ts_kind: &str) -> LoopKind {
        c_loop_kind(ts_kind)
    }

    fn lit_kind(&self, ts_kind: &str) -> LiteralKind {
        c_lit_kind(ts_kind)
    }

    fn name(&self) -> &str {
        "c"
    }
}

// ── C++ lifter ────────────────────────────────────────────────────────────────

pub struct CppLifter;

impl LanguageLifter for CppLifter {
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_cpp::LANGUAGE.into()
    }

    fn lift_kind(&self, ts_kind: &str) -> IrNodeKind {
        // C++ is a superset of C for purposes of node classification.
        match ts_kind {
            // C++-specific constructs
            "lambda_expression" => IrNodeKind::LambdaDef,
            "namespace_definition" => IrNodeKind::Namespace,
            "class_specifier" => IrNodeKind::ClassDef,
            "try_statement" => IrNodeKind::Try,
            "seh_try_statement" => IrNodeKind::Try,
            "catch_clause" | "seh_except_clause" | "seh_finally_clause" => IrNodeKind::Catch,
            "throw_expression" => IrNodeKind::Throw,
            "for_range_loop" => IrNodeKind::Loop,
            "new_expression" => IrNodeKind::NewExpr,
            "delete_expression" => IrNodeKind::DeleteExpr,
            "static_cast_expression"
            | "dynamic_cast_expression"
            | "reinterpret_cast_expression"
            | "const_cast_expression" => IrNodeKind::Cast,
            "co_await_expression" => IrNodeKind::UnaryOp,
            "co_return_statement" => IrNodeKind::Return,
            "co_yield_expression" => IrNodeKind::UnaryOp,
            "template_declaration" | "template_instantiation" => IrNodeKind::Unknown,
            "structured_binding_declaration" => IrNodeKind::LocalDef,
            "condition_clause" => IrNodeKind::Unknown,
            _ => lift_c_kind(ts_kind), // fall through to shared C table
        }
    }

    fn loop_kind(&self, ts_kind: &str) -> LoopKind {
        if ts_kind == "for_range_loop" {
            return LoopKind::ForEach;
        }
        c_loop_kind(ts_kind)
    }

    fn try_kind(&self, ts_kind: &str) -> TryKind {
        if ts_kind == "seh_try_statement" {
            TryKind::Seh
        } else {
            TryKind::Standard
        }
    }

    fn lit_kind(&self, ts_kind: &str) -> LiteralKind {
        match ts_kind {
            "true" | "false" => LiteralKind::Bool,
            "nullptr" | "null" => LiteralKind::Null,
            _ => c_lit_kind(ts_kind),
        }
    }

    fn is_function_scope(&self, ts_kind: &str) -> bool {
        // Preserve old behavior: only function_definition creates a new fn_id in
        // the AST walk. Lambda bodies intentionally share the enclosing function's
        // fn_id so the lambda-capture taint analysis can track captured variables
        // across the lambda boundary without needing cross-scope DFG edges.
        ts_kind == "function_definition"
    }

    fn short_callee_name<'a>(&self, raw: &'a str) -> &'a str {
        match raw.rfind("::") {
            Some(pos) => &raw[pos + 2..],
            None => raw,
        }
    }

    fn normalize_callee_name<'a>(&self, raw: &'a str) -> &'a str {
        raw.strip_prefix("::").unwrap_or(raw)
    }

    fn has_exceptions(&self) -> bool {
        true
    }

    fn has_lambdas(&self) -> bool {
        true
    }

    fn has_namespaces(&self) -> bool {
        true
    }

    fn has_structured_bindings(&self) -> bool {
        true
    }

    fn name(&self) -> &str {
        "cpp"
    }
}

// ── Shared mapping tables ─────────────────────────────────────────────────────

fn lift_c_kind(ts_kind: &str) -> IrNodeKind {
    match ts_kind {
        // ── Structural ──────────────────────────────────────────────────────
        "translation_unit" => IrNodeKind::File,
        "function_definition" => IrNodeKind::MethodDef,
        "struct_specifier" | "union_specifier" | "enum_specifier" => IrNodeKind::ClassDef,
        // ── Declarations ───────────────────────────────────────────────────
        "parameter_declaration" => IrNodeKind::ParamDef,
        "declaration" | "init_declarator" => IrNodeKind::LocalDef,
        "field_declaration" => IrNodeKind::FieldDef,
        "type_definition" => IrNodeKind::TypeAlias,
        // ── Statements ─────────────────────────────────────────────────────
        "compound_statement" => IrNodeKind::Block,
        "return_statement" => IrNodeKind::Return,
        "for_statement" | "while_statement" | "do_statement" => IrNodeKind::Loop,
        "if_statement" => IrNodeKind::Conditional,
        "switch_statement" => IrNodeKind::Switch,
        "case_statement" => IrNodeKind::Case,
        "default_statement" => IrNodeKind::SwitchDefault,
        "break_statement" => IrNodeKind::Break,
        "continue_statement" => IrNodeKind::Continue,
        "goto_statement" => IrNodeKind::Goto,
        "labeled_statement" => IrNodeKind::Label,
        "expression_statement" => IrNodeKind::ExprStmt,
        // ── C exception-like constructs (MSVC SEH in C mode) ───────────────
        "seh_try_statement" => IrNodeKind::Try,
        "seh_except_clause" | "seh_finally_clause" => IrNodeKind::Catch,
        "seh_leave_statement" => IrNodeKind::SehLeave,
        // ── Expressions ────────────────────────────────────────────────────
        "call_expression" => IrNodeKind::Call,
        "assignment_expression" | "augmented_assignment_expression" => IrNodeKind::Assign,
        "binary_expression" => IrNodeKind::BinaryOp,
        "unary_expression" | "pointer_expression" | "update_expression" => IrNodeKind::UnaryOp,
        "conditional_expression" => IrNodeKind::TernaryOp,
        "cast_expression" => IrNodeKind::Cast,
        "subscript_expression" => IrNodeKind::Subscript,
        "field_expression" => IrNodeKind::MemberAccess,
        "sizeof_expression" | "alignof_expression" | "offsetof_expression" => {
            IrNodeKind::SizeofExpr
        }
        "gnu_asm_expression" | "ms_based_declarator" => IrNodeKind::Unknown,
        "comma_expression" => IrNodeKind::BinaryOp,
        "parenthesized_expression" => IrNodeKind::Unknown, // transparent wrapper
        // ── Leaves ─────────────────────────────────────────────────────────
        "identifier" | "field_identifier" | "qualified_identifier" | "scoped_identifier" => {
            IrNodeKind::Identifier
        }
        "number_literal"
        | "string_literal"
        | "char_literal"
        | "concatenated_string"
        | "true"
        | "false"
        | "null" => IrNodeKind::Literal,
        "primitive_type"
        | "type_identifier"
        | "sized_type_specifier"
        | "type_qualifier"
        | "storage_class_specifier" => IrNodeKind::TypeRef,
        // ── Declarator nodes (often children of LocalDef / ParamDef) ───────
        "pointer_declarator"
        | "function_declarator"
        | "array_declarator"
        | "abstract_declarator"
        | "abstract_pointer_declarator"
        | "abstract_array_declarator"
        | "abstract_function_declarator"
        | "reference_declarator" => IrNodeKind::Unknown,
        // ── Everything else ─────────────────────────────────────────────────
        _ => IrNodeKind::Unknown,
    }
}

fn c_loop_kind(ts_kind: &str) -> LoopKind {
    match ts_kind {
        "for_statement" => LoopKind::For,
        "do_statement" => LoopKind::DoWhile,
        _ => LoopKind::While,
    }
}

fn c_lit_kind(ts_kind: &str) -> LiteralKind {
    match ts_kind {
        "string_literal" | "concatenated_string" => LiteralKind::String,
        "char_literal" => LiteralKind::Char,
        "true" | "false" => LiteralKind::Bool,
        "null" | "nullptr" => LiteralKind::Null,
        _ => LiteralKind::Integer, // number_literal covers int and float; refine later if needed
    }
}

// ── Go lifter ─────────────────────────────────────────────────────────────────

pub struct GoLifter;

impl LanguageLifter for GoLifter {
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_go::LANGUAGE.into()
    }

    fn lift_kind(&self, ts_kind: &str) -> IrNodeKind {
        match ts_kind {
            // ── Structural ──────────────────────────────────────────────────
            "source_file" => IrNodeKind::File,
            "function_declaration" | "method_declaration" => IrNodeKind::MethodDef,
            "func_literal" => IrNodeKind::LambdaDef,
            "block" => IrNodeKind::Block,
            // ── Declarations ───────────────────────────────────────────────
            "var_spec" | "const_spec" => IrNodeKind::LocalDef,
            "short_var_declaration" => IrNodeKind::ShortVarDecl,
            "parameter_declaration" | "variadic_parameter_declaration" => IrNodeKind::ParamDef,
            "field_declaration" => IrNodeKind::FieldDef,
            "type_spec" | "type_alias" => IrNodeKind::TypeAlias,
            "struct_type" | "interface_type" => IrNodeKind::ClassDef,
            "method_elem" => IrNodeKind::MethodDef,
            // ── Statements ─────────────────────────────────────────────────
            "return_statement" => IrNodeKind::Return,
            "if_statement" => IrNodeKind::Conditional,
            "for_statement" => IrNodeKind::Loop,
            "expression_switch_statement" => IrNodeKind::Switch,
            "expression_case" => IrNodeKind::Case,
            "default_case" => IrNodeKind::SwitchDefault,
            "type_switch_statement" => IrNodeKind::TypeSwitch,
            "type_case" => IrNodeKind::TypeCase,
            "select_statement" => IrNodeKind::SelectStmt,
            "communication_case" => IrNodeKind::CommCase,
            "send_statement" => IrNodeKind::SendStmt,
            "go_statement" => IrNodeKind::GoStmt,
            "defer_statement" => IrNodeKind::DeferStmt,
            "break_statement" => IrNodeKind::Break,
            "continue_statement" => IrNodeKind::Continue,
            "goto_statement" => IrNodeKind::Goto,
            "labeled_statement" => IrNodeKind::Label,
            "fallthrough_statement" => IrNodeKind::Fallthrough,
            "inc_statement" => IrNodeKind::IncDecStmt,
            "dec_statement" => IrNodeKind::IncDecStmt,
            "assignment_statement" => IrNodeKind::Assign,
            "expression_statement" => IrNodeKind::ExprStmt,
            // ── Expressions ────────────────────────────────────────────────
            "call_expression" => IrNodeKind::Call,
            "selector_expression" => IrNodeKind::MemberAccess,
            "index_expression" | "slice_expression" => IrNodeKind::Subscript,
            "type_assertion_expression" => IrNodeKind::TypeAssertion,
            "type_conversion_expression" => IrNodeKind::Cast,
            "composite_literal" | "literal_value" => IrNodeKind::CompositeLit,
            "unary_expression" | "variadic_argument" | "negated_type" => IrNodeKind::UnaryOp,
            "binary_expression" => IrNodeKind::BinaryOp,
            // receive: `<-ch` used as expression (not inside short_var_declaration)
            // tree-sitter-go uses "unary_expression" for `<-ch`, but we
            // need to distinguish it; actual receive is detected at walk time.
            // ── Types ───────────────────────────────────────────────────────
            "pointer_type"
            | "slice_type"
            | "array_type"
            | "implicit_length_array_type"
            | "map_type"
            | "channel_type"
            | "function_type"
            | "qualified_type"
            | "generic_type"
            | "type_instantiation_expression"
            | "type_identifier" => IrNodeKind::TypeRef,
            // ── Leaves ─────────────────────────────────────────────────────
            "identifier" | "field_identifier" | "package_identifier" | "label_name"
            | "blank_identifier" => IrNodeKind::Identifier,
            "int_literal" | "float_literal" | "imaginary_literal" | "rune_literal"
            | "interpreted_string_literal" | "raw_string_literal"
            | "true" | "false" | "nil" | "iota" => IrNodeKind::Literal,
            // ── Transparent wrappers (Unknown) ─────────────────────────────
            _ => IrNodeKind::Unknown,
        }
    }

    fn loop_kind(&self, ts_kind: &str) -> LoopKind {
        // The for_statement's loop kind depends on child presence, which we
        // can't inspect here; the CPG generator should set ForEach when it
        // finds a range_clause child. Default to While (covers infinite and
        // condition-only forms); For is set by the generator for for_clause.
        let _ = ts_kind;
        LoopKind::While
    }

    fn lit_kind(&self, ts_kind: &str) -> LiteralKind {
        match ts_kind {
            "interpreted_string_literal" | "raw_string_literal" => LiteralKind::String,
            "rune_literal" => LiteralKind::Char,
            "float_literal" | "imaginary_literal" => LiteralKind::Float,
            "true" | "false" => LiteralKind::Bool,
            "nil" => LiteralKind::Null,
            _ => LiteralKind::Integer, // int_literal, iota
        }
    }

    fn is_function_scope(&self, ts_kind: &str) -> bool {
        matches!(ts_kind, "function_declaration" | "method_declaration" | "func_literal")
    }

    fn short_callee_name<'a>(&self, raw: &'a str) -> &'a str {
        match raw.rfind('.') {
            Some(pos) => &raw[pos + 1..],
            None => raw,
        }
    }

    fn has_lambdas(&self) -> bool { true }

    fn name(&self) -> &str { "go" }
}

// ── Python lifter ────────────────────────────────────────────────────────────

pub struct PythonLifter;

impl LanguageLifter for PythonLifter {
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_python::LANGUAGE.into()
    }

    fn lift_kind(&self, ts_kind: &str) -> IrNodeKind {
        match ts_kind {
            // ── Structural ──────────────────────────────────────────────────
            "module" => IrNodeKind::File,
            "function_definition" | "async_function_definition" => IrNodeKind::MethodDef,
            "class_definition" => IrNodeKind::ClassDef,
            "block" => IrNodeKind::Block,
            "lambda" => IrNodeKind::LambdaDef,
            "decorated_definition" => IrNodeKind::Decorator,
            // ── Declarations ───────────────────────────────────────────────
            "import_statement" | "import_from_statement" | "future_import_statement" => {
                IrNodeKind::Import
            }
            "assignment" | "augmented_assignment" | "annotated_assignment" => IrNodeKind::Assign,
            "named_expression" => IrNodeKind::NamedExpr,
            "global_statement" | "nonlocal_statement" => IrNodeKind::Global,
            "type_alias_statement" => IrNodeKind::TypeAlias,
            "typed_parameter" | "default_parameter"
            | "typed_default_parameter" | "dictionary_splat_pattern"
            | "list_splat_pattern" => IrNodeKind::ParamDef,
            // ── Statements ─────────────────────────────────────────────────
            "return_statement" => IrNodeKind::Return,
            "if_statement" | "elif_clause" => IrNodeKind::Conditional,
            "for_statement" => IrNodeKind::Loop,
            "while_statement" => IrNodeKind::Loop,
            "try_statement" => IrNodeKind::Try,
            "except_clause" | "except_group_clause" => IrNodeKind::Catch,
            "finally_clause" => IrNodeKind::Finally,
            "raise_statement" => IrNodeKind::Throw,
            "with_statement" => IrNodeKind::With,
            "assert_statement" => IrNodeKind::Assert,
            "delete_statement" => IrNodeKind::Delete,
            "break_statement" => IrNodeKind::Break,
            "continue_statement" => IrNodeKind::Continue,
            "expression_statement" => IrNodeKind::ExprStmt,
            "print_statement" => IrNodeKind::Call, // Python 2 compat
            // ── Expressions ────────────────────────────────────────────────
            "call" => IrNodeKind::Call,
            "attribute" => IrNodeKind::MemberAccess,
            "subscript" => IrNodeKind::Subscript,
            "binary_operator" | "comparison_operator" | "boolean_operator" => IrNodeKind::BinaryOp,
            "unary_operator" | "not_operator" => IrNodeKind::UnaryOp,
            "conditional_expression" => IrNodeKind::TernaryOp,
            "yield" | "yield_statement" => IrNodeKind::Yield,
            "await" => IrNodeKind::Await,
            "list_comprehension" | "set_comprehension" | "dictionary_comprehension"
            | "generator_expression" => IrNodeKind::Comprehension,
            "list" | "tuple" | "set" | "dictionary" => IrNodeKind::CollectionExpr,
            "list_splat" | "dictionary_splat" => IrNodeKind::SpreadExpr,
            // ── Identifiers / literals ──────────────────────────────────────
            "identifier" => IrNodeKind::Identifier,
            "integer" | "float" | "string" | "concatenated_string"
            | "true" | "false" | "none"
            | "ellipsis" => IrNodeKind::Literal,
            "type" | "generic_type" | "union_type" => IrNodeKind::TypeRef,
            // ── Transparent wrappers ────────────────────────────────────────
            _ => IrNodeKind::Unknown,
        }
    }

    fn loop_kind(&self, ts_kind: &str) -> LoopKind {
        match ts_kind {
            "for_statement" => LoopKind::ForEach,
            _ => LoopKind::While,
        }
    }

    fn lit_kind(&self, ts_kind: &str) -> LiteralKind {
        match ts_kind {
            "integer" => LiteralKind::Integer,
            "float" => LiteralKind::Float,
            "string" | "concatenated_string" => LiteralKind::String,
            "true" | "false" => LiteralKind::Bool,
            "none" => LiteralKind::Null,
            "ellipsis" => LiteralKind::Ellipsis,
            _ => LiteralKind::String,
        }
    }

    fn is_function_scope(&self, ts_kind: &str) -> bool {
        matches!(
            ts_kind,
            "function_definition" | "async_function_definition" | "lambda"
            // Comprehensions and generator expressions create their own scope in Python 3.
            | "list_comprehension" | "set_comprehension" | "dictionary_comprehension"
            | "generator_expression"
        )
    }

    fn short_callee_name<'a>(&self, raw: &'a str) -> &'a str {
        match raw.rfind('.') {
            Some(pos) => &raw[pos + 1..],
            None => raw,
        }
    }

    fn has_lambdas(&self) -> bool { true }
    fn has_exceptions(&self) -> bool { true }
    fn name(&self) -> &str { "python" }
}

// ── Java lifter ───────────────────────────────────────────────────────────────

pub struct JavaLifter;

impl LanguageLifter for JavaLifter {
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_java::LANGUAGE.into()
    }

    fn lift_kind(&self, ts_kind: &str) -> IrNodeKind {
        match ts_kind {
            // ── Structural ──────────────────────────────────────────────────
            "program" => IrNodeKind::File,
            "class_declaration" | "interface_declaration"
            | "record_declaration" | "annotation_type_declaration" => IrNodeKind::ClassDef,
            "enum_declaration" => IrNodeKind::EnumDef,
            "enum_constant" => IrNodeKind::EnumConstant,
            "method_declaration" | "constructor_declaration" => IrNodeKind::MethodDef,
            "block" => IrNodeKind::Block,
            "lambda_expression" => IrNodeKind::LambdaDef,
            "method_reference" => IrNodeKind::MethodRef,
            // ── Declarations ───────────────────────────────────────────────
            "local_variable_declaration" | "variable_declarator" => IrNodeKind::LocalDef,
            "formal_parameter" | "spread_parameter" => IrNodeKind::ParamDef,
            "field_declaration" => IrNodeKind::FieldDef,
            "type_declaration" => IrNodeKind::Unknown, // transparent
            "import_declaration" => IrNodeKind::Import,
            "package_declaration" => IrNodeKind::Unknown,
            "module_declaration" => IrNodeKind::ModuleDecl,
            "annotation" | "marker_annotation" => IrNodeKind::Decorator,
            // ── Statements ─────────────────────────────────────────────────
            "return_statement" => IrNodeKind::Return,
            "if_statement" => IrNodeKind::Conditional,
            "for_statement" => IrNodeKind::Loop,
            "enhanced_for_statement" => IrNodeKind::Loop,
            "while_statement" => IrNodeKind::Loop,
            "do_statement" => IrNodeKind::Loop,
            "switch_statement" => IrNodeKind::Switch,
            "switch_expression" => IrNodeKind::Switch,
            "switch_block_statement_group" => IrNodeKind::Unknown,
            "switch_rule" => IrNodeKind::SwitchRule,
            "switch_label" => IrNodeKind::Case,
            "try_statement" | "try_with_resources_statement" => IrNodeKind::Try,
            "catch_clause" => IrNodeKind::Catch,
            "finally_clause" => IrNodeKind::Finally,
            "throw_statement" => IrNodeKind::Throw,
            "synchronized_statement" => IrNodeKind::Synchronized,
            "break_statement" => IrNodeKind::Break,
            "continue_statement" => IrNodeKind::Continue,
            "assert_statement" => IrNodeKind::Assert,
            "expression_statement" => IrNodeKind::ExprStmt,
            "labeled_statement" => IrNodeKind::Label,
            "yield_statement" => IrNodeKind::Yield,
            // ── Expressions ────────────────────────────────────────────────
            "method_invocation" => IrNodeKind::Call,
            "object_creation_expression" => IrNodeKind::NewExpr,
            "array_creation_expression" => IrNodeKind::NewArray,
            "array_initializer" => IrNodeKind::ArrayInit,
            "assignment_expression" => IrNodeKind::Assign,
            "binary_expression" => IrNodeKind::BinaryOp,
            "unary_expression" | "update_expression" => IrNodeKind::UnaryOp,
            "ternary_expression" => IrNodeKind::TernaryOp,
            "cast_expression" => IrNodeKind::Cast,
            "array_access" => IrNodeKind::Subscript,
            "field_access" => IrNodeKind::MemberAccess,
            "instanceof_expression" | "pattern_expression" => IrNodeKind::InstanceofExpr,
            "type_pattern" => IrNodeKind::LocalDef,
            "this" | "super" => IrNodeKind::ThisExpr,
            "string_template" => IrNodeKind::StringTemplate,
            "class_literal" => IrNodeKind::ClassLiteral,
            // ── Identifiers / literals ──────────────────────────────────────
            "identifier" => IrNodeKind::Identifier,
            "decimal_integer_literal" | "hex_integer_literal" | "octal_integer_literal"
            | "binary_integer_literal" | "decimal_floating_point_literal"
            | "hex_floating_point_literal" | "string_literal" | "character_literal"
            | "true" | "false" | "null_literal" | "text_block" => IrNodeKind::Literal,
            "void_type" | "integral_type" | "floating_point_type" | "boolean_type"
            | "type_identifier" | "generic_type" | "array_type" | "scoped_type_identifier"
            | "annotated_type" => IrNodeKind::TypeRef,
            // ── Transparent ────────────────────────────────────────────────
            _ => IrNodeKind::Unknown,
        }
    }

    fn loop_kind(&self, ts_kind: &str) -> LoopKind {
        match ts_kind {
            "for_statement" => LoopKind::For,
            "enhanced_for_statement" => LoopKind::ForEach,
            "do_statement" => LoopKind::DoWhile,
            _ => LoopKind::While,
        }
    }

    fn try_kind(&self, ts_kind: &str) -> TryKind {
        if ts_kind == "try_with_resources_statement" {
            TryKind::WithResources
        } else {
            TryKind::Standard
        }
    }

    fn lit_kind(&self, ts_kind: &str) -> LiteralKind {
        match ts_kind {
            "decimal_integer_literal" | "hex_integer_literal" | "octal_integer_literal"
            | "binary_integer_literal" => LiteralKind::Integer,
            "decimal_floating_point_literal" | "hex_floating_point_literal" => LiteralKind::Float,
            "string_literal" | "text_block" => LiteralKind::String,
            "character_literal" => LiteralKind::Char,
            "true" | "false" => LiteralKind::Bool,
            "null_literal" => LiteralKind::Null,
            _ => LiteralKind::Integer,
        }
    }

    fn is_function_scope(&self, ts_kind: &str) -> bool {
        matches!(
            ts_kind,
            "method_declaration" | "constructor_declaration" | "lambda_expression"
            // Static and instance initializers create a function scope in Java.
            | "static_initializer" | "instance_initializer"
        )
    }

    fn short_callee_name<'a>(&self, raw: &'a str) -> &'a str {
        match raw.rfind('.') {
            Some(pos) => &raw[pos + 1..],
            None => raw,
        }
    }

    fn normalize_callee_name<'a>(&self, raw: &'a str) -> &'a str {
        raw
    }

    fn has_exceptions(&self) -> bool { true }
    fn has_lambdas(&self) -> bool { true }
    fn has_namespaces(&self) -> bool { true }
    fn name(&self) -> &str { "java" }
}

// ── JavaScript lifter ────────────────────────────────────────────────────────

pub struct JsLifter;

impl LanguageLifter for JsLifter {
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_javascript::LANGUAGE.into()
    }

    fn lift_kind(&self, ts_kind: &str) -> IrNodeKind {
        lift_js_kind(ts_kind)
    }

    fn loop_kind(&self, ts_kind: &str) -> LoopKind {
        js_loop_kind(ts_kind)
    }

    fn lit_kind(&self, ts_kind: &str) -> LiteralKind {
        js_lit_kind(ts_kind)
    }

    fn is_function_scope(&self, ts_kind: &str) -> bool {
        matches!(
            ts_kind,
            "function_declaration" | "function" | "arrow_function"
            | "generator_function_declaration" | "generator_function"
            | "method_definition"
        )
    }

    fn short_callee_name<'a>(&self, raw: &'a str) -> &'a str {
        match raw.rfind('.') {
            Some(pos) => &raw[pos + 1..],
            None => raw,
        }
    }

    fn has_lambdas(&self) -> bool { true }
    fn has_exceptions(&self) -> bool { true }
    fn name(&self) -> &str { "javascript" }
}

fn lift_js_kind(ts_kind: &str) -> IrNodeKind {
    match ts_kind {
        // ── Structural ──────────────────────────────────────────────────────
        "program" => IrNodeKind::File,
        "function_declaration" | "function" | "method_definition" => IrNodeKind::MethodDef,
        "arrow_function" => IrNodeKind::LambdaDef,
        "generator_function_declaration" | "generator_function" => IrNodeKind::MethodDef,
        "class_declaration" | "class" => IrNodeKind::ClassDef,
        "statement_block" => IrNodeKind::Block,
        // ── Declarations ───────────────────────────────────────────────────
        "lexical_declaration" | "variable_declaration" => IrNodeKind::LocalDef,
        "variable_declarator" => IrNodeKind::LocalDef,
        "field_definition" | "public_field_definition" | "property_signature" => IrNodeKind::FieldDef,
        "import_statement" => IrNodeKind::Import,
        "export_statement" => IrNodeKind::Export,
        // ── Statements ─────────────────────────────────────────────────────
        "return_statement" => IrNodeKind::Return,
        "if_statement" => IrNodeKind::Conditional,
        "for_statement" => IrNodeKind::Loop,
        "for_in_statement" => IrNodeKind::Loop,
        "while_statement" => IrNodeKind::Loop,
        "do_statement" => IrNodeKind::Loop,
        "switch_statement" => IrNodeKind::Switch,
        "switch_case" => IrNodeKind::Case,
        "switch_default" => IrNodeKind::SwitchDefault,
        "try_statement" => IrNodeKind::Try,
        "catch_clause" => IrNodeKind::Catch,
        "finally_clause" => IrNodeKind::Finally,
        "throw_statement" => IrNodeKind::Throw,
        "break_statement" => IrNodeKind::Break,
        "continue_statement" => IrNodeKind::Continue,
        "labeled_statement" => IrNodeKind::Label,
        "expression_statement" => IrNodeKind::ExprStmt,
        "debugger_statement" => IrNodeKind::Unknown,
        "empty_statement" => IrNodeKind::Unknown,
        // ── Expressions ────────────────────────────────────────────────────
        "call_expression" => IrNodeKind::Call,
        "new_expression" => IrNodeKind::NewExpr,
        "assignment_expression" | "augmented_assignment_expression" => IrNodeKind::Assign,
        "binary_expression" | "logical_expression" => IrNodeKind::BinaryOp,
        "unary_expression" | "update_expression" => IrNodeKind::UnaryOp,
        "ternary_expression" => IrNodeKind::TernaryOp,
        "subscript_expression" => IrNodeKind::Subscript,
        "member_expression" => IrNodeKind::MemberAccess,
        "await_expression" => IrNodeKind::AwaitExpr,
        "yield_expression" => IrNodeKind::YieldExpr,
        "template_string" => IrNodeKind::TemplateStr,
        "spread_element" => IrNodeKind::SpreadExpr,
        "optional_chain" => IrNodeKind::OptionalChain,
        "jsx_element" | "jsx_self_closing_element" | "jsx_fragment" => IrNodeKind::JsxElement,
        "object" => IrNodeKind::CompositeLit,
        "array" => IrNodeKind::CollectionExpr,
        "sequence_expression" => IrNodeKind::SequenceExpr,
        // ── Identifiers / literals ──────────────────────────────────────────
        "identifier" | "property_identifier" | "shorthand_property_identifier"
        | "shorthand_property_identifier_pattern" => IrNodeKind::Identifier,
        "number" | "string" | "template_string" | "true" | "false"
        | "null" | "undefined" | "regex" => IrNodeKind::Literal,
        // ── Transparent ────────────────────────────────────────────────────
        _ => IrNodeKind::Unknown,
    }
}

fn js_loop_kind(ts_kind: &str) -> LoopKind {
    match ts_kind {
        "for_statement" => LoopKind::For,
        "for_in_statement" => LoopKind::ForEach,
        "do_statement" => LoopKind::DoWhile,
        _ => LoopKind::While,
    }
}

fn js_lit_kind(ts_kind: &str) -> LiteralKind {
    match ts_kind {
        "number" => LiteralKind::Integer,
        "string" => LiteralKind::String,
        "template_string" => LiteralKind::Template,
        "true" | "false" => LiteralKind::Bool,
        "null" | "undefined" => LiteralKind::Null,
        "regex" => LiteralKind::Regex,
        _ => LiteralKind::String,
    }
}

// ── TypeScript lifter ────────────────────────────────────────────────────────

pub struct TsLifter;

impl LanguageLifter for TsLifter {
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
    }

    fn lift_kind(&self, ts_kind: &str) -> IrNodeKind {
        match ts_kind {
            // ── TypeScript-specific ─────────────────────────────────────────
            "interface_declaration" => IrNodeKind::InterfaceDecl,
            "enum_declaration" => IrNodeKind::EnumDecl,
            "type_alias_declaration" => IrNodeKind::TypeAlias,
            "as_expression" => IrNodeKind::AsExpr,
            "non_null_expression" => IrNodeKind::NonNullExpr,
            "satisfies_expression" => IrNodeKind::SatisfiesExpr,
            "ambient_declaration" | "declare" => IrNodeKind::AmbientDecl,
            "module" | "internal_module" => IrNodeKind::Namespace,
            "abstract_class_declaration" => IrNodeKind::ClassDef,
            "type_predicate" | "type_predicate_annotation" => IrNodeKind::TypePredicate,
            "required_parameter" | "optional_parameter" | "mandatory_parameter" => IrNodeKind::ParamDef,
            "public_field_definition" => IrNodeKind::FieldDef,
            "const_enum" => IrNodeKind::EnumDecl,
            "decorator" => IrNodeKind::Decorator,
            // ── Type references ─────────────────────────────────────────────
            "predefined_type" | "type_identifier" | "generic_type"
            | "union_type" | "intersection_type" | "array_type"
            | "tuple_type" | "object_type" | "function_type"
            | "literal_type" | "conditional_type" | "infer_type"
            | "mapped_type_clause" | "template_literal_type"
            | "readonly_type" | "lookup_type" | "type_query"
            | "existential_type" | "flow_maybe_type" => IrNodeKind::TypeRef,
            // ── Shared with JS (fall through to js table) ──────────────────
            _ => lift_js_kind(ts_kind),
        }
    }

    fn loop_kind(&self, ts_kind: &str) -> LoopKind {
        js_loop_kind(ts_kind)
    }

    fn lit_kind(&self, ts_kind: &str) -> LiteralKind {
        js_lit_kind(ts_kind)
    }

    fn is_function_scope(&self, ts_kind: &str) -> bool {
        matches!(
            ts_kind,
            "function_declaration" | "function" | "arrow_function"
            | "generator_function_declaration" | "generator_function"
            | "method_definition"
        )
    }

    fn short_callee_name<'a>(&self, raw: &'a str) -> &'a str {
        match raw.rfind('.') {
            Some(pos) => &raw[pos + 1..],
            None => raw,
        }
    }

    fn has_lambdas(&self) -> bool { true }
    fn has_exceptions(&self) -> bool { true }
    fn has_namespaces(&self) -> bool { true }
    fn name(&self) -> &str { "typescript" }
}

// ── Rust lifter ───────────────────────────────────────────────────────────────

pub struct RustLifter;

impl LanguageLifter for RustLifter {
    fn ts_language(&self) -> tree_sitter::Language {
        tree_sitter_rust::LANGUAGE.into()
    }

    fn lift_kind(&self, ts_kind: &str) -> IrNodeKind {
        match ts_kind {
            // ── Structural ──────────────────────────────────────────────────
            "source_file" => IrNodeKind::File,
            "function_item" => IrNodeKind::MethodDef,
            "closure_expression" => IrNodeKind::LambdaDef,
            "block" => IrNodeKind::Block,
            "struct_item" | "enum_item" | "union_item" => IrNodeKind::ClassDef,
            "impl_item" => IrNodeKind::ImplBlock,
            "trait_item" => IrNodeKind::TraitDef,
            "mod_item" => IrNodeKind::ModDef,
            "use_declaration" | "extern_crate_declaration" => IrNodeKind::UseDecl,
            // ── Declarations ───────────────────────────────────────────────
            "let_declaration" => IrNodeKind::LocalDef,
            "parameter" | "self_parameter" => IrNodeKind::ParamDef,
            "field_declaration" => IrNodeKind::FieldDef,
            "type_item" => IrNodeKind::TypeAlias,
            "attribute_item" | "inner_attribute_item" => IrNodeKind::Decorator,
            "foreign_mod_item" => IrNodeKind::Import,
            // ── Statements ─────────────────────────────────────────────────
            "return_expression" => IrNodeKind::Return,
            "if_expression" => IrNodeKind::Conditional,
            "loop_expression" => IrNodeKind::LoopExpr,
            "while_expression" | "while_let_expression" => IrNodeKind::Loop,
            "for_expression" => IrNodeKind::Loop,
            "match_expression" => IrNodeKind::MatchExpr,
            "match_arm" => IrNodeKind::MatchArm,
            "break_expression" => IrNodeKind::BreakExpr,
            "continue_expression" => IrNodeKind::Continue,
            "unsafe_block" => IrNodeKind::UnsafeBlock,
            "async_block" => IrNodeKind::Block,
            "expression_statement" => IrNodeKind::ExprStmt,
            "labeled_block" => IrNodeKind::Block,
            // ── Expressions ────────────────────────────────────────────────
            "call_expression" => IrNodeKind::Call,
            "method_call_expression" => IrNodeKind::Call,
            "macro_invocation" => IrNodeKind::MacroInvocation,
            "assignment_expression" | "compound_assignment_expr" => IrNodeKind::Assign,
            "binary_expression" => IrNodeKind::BinaryOp,
            "unary_expression" | "reference_expression" | "dereference_expression" => {
                IrNodeKind::UnaryOp
            }
            "await_expression" => IrNodeKind::AwaitExpr,
            "try_expression" => IrNodeKind::TryExpr,
            "cast_expression" | "type_cast_expression" => IrNodeKind::Cast,
            "index_expression" => IrNodeKind::Subscript,
            "field_expression" => IrNodeKind::MemberAccess,
            "struct_expression" => IrNodeKind::StructExpr,
            "range_expression" => IrNodeKind::RangeExpr,
            "if_let_expression" => IrNodeKind::Conditional,
            // ── Identifiers / literals ──────────────────────────────────────
            "identifier" | "self" | "super" => IrNodeKind::Identifier,
            "integer_literal" | "float_literal" | "string_literal" | "raw_string_literal"
            | "char_literal" | "boolean_literal" | "byte_literal"
            | "byte_string_literal" | "raw_byte_string_literal" => IrNodeKind::Literal,
            "lifetime" => IrNodeKind::LifetimeRef,
            "type_identifier" | "primitive_type" | "scoped_type_identifier"
            | "generic_type" | "reference_type" | "pointer_type" | "array_type"
            | "slice_type" | "tuple_type" | "function_type" | "abstract_type"
            | "dynamic_type" => IrNodeKind::TypeRef,
            // ── Transparent ────────────────────────────────────────────────
            _ => IrNodeKind::Unknown,
        }
    }

    fn loop_kind(&self, ts_kind: &str) -> LoopKind {
        match ts_kind {
            "for_expression" => LoopKind::ForEach,
            "while_let_expression" => LoopKind::While,
            _ => LoopKind::While,
        }
    }

    fn lit_kind(&self, ts_kind: &str) -> LiteralKind {
        match ts_kind {
            "integer_literal" | "byte_literal" => LiteralKind::Integer,
            "float_literal" => LiteralKind::Float,
            "string_literal" | "raw_string_literal" | "byte_string_literal"
            | "raw_byte_string_literal" => LiteralKind::String,
            "char_literal" => LiteralKind::Char,
            "boolean_literal" => LiteralKind::Bool,
            _ => LiteralKind::Integer,
        }
    }

    fn is_function_scope(&self, ts_kind: &str) -> bool {
        matches!(
            ts_kind,
            "function_item" | "closure_expression"
            // async blocks create a new scope (like an async closure).
            | "async_block"
        )
    }

    fn short_callee_name<'a>(&self, raw: &'a str) -> &'a str {
        match raw.rfind("::") {
            Some(pos) => &raw[pos + 2..],
            None => raw,
        }
    }

    fn normalize_callee_name<'a>(&self, raw: &'a str) -> &'a str {
        raw.strip_prefix("::").unwrap_or(raw)
    }

    fn has_lambdas(&self) -> bool { true }
    fn has_exceptions(&self) -> bool { true }
    fn name(&self) -> &str { "rust" }
}

// ── Constructor ───────────────────────────────────────────────────────────────

pub fn lifter_for_language(lang: SourceLanguage) -> DynLifter {
    match lang {
        SourceLanguage::C => Arc::new(CLifter),
        SourceLanguage::Cpp => Arc::new(CppLifter),
        SourceLanguage::Go => Arc::new(GoLifter),
        SourceLanguage::Python => Arc::new(PythonLifter),
        SourceLanguage::Java => Arc::new(JavaLifter),
        SourceLanguage::JavaScript => Arc::new(JsLifter),
        SourceLanguage::TypeScript => Arc::new(TsLifter),
        SourceLanguage::Rust => Arc::new(RustLifter),
    }
}
