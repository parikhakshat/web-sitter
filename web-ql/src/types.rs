use web_sitter::IrNodeKind;
use crate::ast::TypeExpr;

/// Expand a `TypeExpr` alias into the set of `IrNodeKind` values it covers.
/// Returns `None` for `NodeType(raw)` (raw kind match, not an IrNodeKind).
pub fn expand_type(ty: &TypeExpr) -> Option<Vec<IrNodeKind>> {
    match ty {
        TypeExpr::Node => Some(all_ir_kinds()),
        TypeExpr::Expr => Some(expr_kinds()),
        TypeExpr::Stmt => Some(stmt_kinds()),
        TypeExpr::Decl => Some(decl_kinds()),
        TypeExpr::Call => Some(vec![IrNodeKind::Call]),
        TypeExpr::MethodDef => Some(vec![IrNodeKind::MethodDef]),
        TypeExpr::ClassDef => Some(vec![IrNodeKind::ClassDef]),
        TypeExpr::Identifier => Some(vec![IrNodeKind::Identifier]),
        TypeExpr::Literal => Some(vec![IrNodeKind::Literal]),
        TypeExpr::Assign => Some(vec![IrNodeKind::Assign]),
        TypeExpr::BinaryOp => Some(vec![IrNodeKind::BinaryOp]),
        TypeExpr::Return => Some(vec![IrNodeKind::Return]),
        TypeExpr::Loop => Some(vec![IrNodeKind::Loop]),
        TypeExpr::Conditional => Some(vec![IrNodeKind::Conditional]),
        TypeExpr::Block => Some(vec![IrNodeKind::Block]),
        TypeExpr::Try => Some(vec![IrNodeKind::Try]),
        TypeExpr::Catch => Some(vec![IrNodeKind::Catch]),
        TypeExpr::ParamDef => Some(vec![IrNodeKind::ParamDef]),
        TypeExpr::LocalDef => Some(vec![IrNodeKind::LocalDef]),
        TypeExpr::FieldDef => Some(vec![IrNodeKind::FieldDef]),
        TypeExpr::MemberAccess => Some(vec![IrNodeKind::MemberAccess]),
        TypeExpr::Subscript => Some(vec![IrNodeKind::Subscript]),
        TypeExpr::Cast => Some(vec![IrNodeKind::Cast]),
        TypeExpr::GoStmt => Some(vec![IrNodeKind::GoStmt]),
        TypeExpr::DeferStmt => Some(vec![IrNodeKind::DeferStmt]),
        TypeExpr::MatchExpr => Some(vec![IrNodeKind::MatchExpr]),
        TypeExpr::Comprehension => Some(vec![IrNodeKind::Comprehension]),
        TypeExpr::Await => Some(vec![IrNodeKind::Await]),
        TypeExpr::Yield => Some(vec![IrNodeKind::Yield]),
        TypeExpr::UnsafeBlock => Some(vec![IrNodeKind::UnsafeBlock]),
        TypeExpr::ImplBlock => Some(vec![IrNodeKind::ImplBlock]),
        TypeExpr::NodeType(_) => None, // raw kind — not an IrNodeKind match
        TypeExpr::Named(_) => None,    // user-defined, caller must resolve
    }
}

/// True if the given `IrNodeKind` is a member of the type alias `ty`.
pub fn kind_in_type(kind: IrNodeKind, ty: &TypeExpr) -> bool {
    match expand_type(ty) {
        Some(kinds) => kinds.contains(&kind),
        None => false, // NodeType / Named — handled separately
    }
}

fn all_ir_kinds() -> Vec<IrNodeKind> {
    // All variants from the taxonomy (structural + lang-specific)
    vec![
        IrNodeKind::File, IrNodeKind::Namespace, IrNodeKind::ClassDef, IrNodeKind::MethodDef,
        IrNodeKind::ParamDef, IrNodeKind::LocalDef, IrNodeKind::FieldDef, IrNodeKind::TypeAlias,
        IrNodeKind::Block, IrNodeKind::Return, IrNodeKind::Loop, IrNodeKind::Conditional,
        IrNodeKind::Switch, IrNodeKind::Case, IrNodeKind::SwitchDefault, IrNodeKind::Break,
        IrNodeKind::Continue, IrNodeKind::Goto, IrNodeKind::Label, IrNodeKind::Throw,
        IrNodeKind::Try, IrNodeKind::Catch, IrNodeKind::ExprStmt,
        IrNodeKind::Call, IrNodeKind::Assign, IrNodeKind::BinaryOp, IrNodeKind::UnaryOp,
        IrNodeKind::TernaryOp, IrNodeKind::Cast, IrNodeKind::Subscript, IrNodeKind::MemberAccess,
        IrNodeKind::LambdaDef, IrNodeKind::NewExpr, IrNodeKind::DeleteExpr, IrNodeKind::SizeofExpr,
        IrNodeKind::Identifier, IrNodeKind::Literal, IrNodeKind::TypeRef,
        IrNodeKind::Unknown,
        IrNodeKind::Import, IrNodeKind::Yield, IrNodeKind::Await, IrNodeKind::Comprehension,
        IrNodeKind::With, IrNodeKind::Assert, IrNodeKind::Delete, IrNodeKind::Global,
        IrNodeKind::Decorator, IrNodeKind::NamedExpr, IrNodeKind::CollectionExpr,
        IrNodeKind::GoStmt, IrNodeKind::DeferStmt, IrNodeKind::SelectStmt, IrNodeKind::CommCase,
        IrNodeKind::SendStmt, IrNodeKind::ReceiveExpr, IrNodeKind::ShortVarDecl,
        IrNodeKind::IncDecStmt, IrNodeKind::TypeAssertion, IrNodeKind::TypeSwitch,
        IrNodeKind::TypeCase, IrNodeKind::CompositeLit, IrNodeKind::Fallthrough,
        IrNodeKind::EnumDef, IrNodeKind::EnumConstant, IrNodeKind::SwitchExpr,
        IrNodeKind::SwitchRule, IrNodeKind::Finally, IrNodeKind::Synchronized,
        IrNodeKind::InstanceofExpr, IrNodeKind::MethodRef, IrNodeKind::NewArray,
        IrNodeKind::ArrayInit, IrNodeKind::ModuleDecl, IrNodeKind::StringTemplate,
        IrNodeKind::ClassLiteral, IrNodeKind::ThisExpr,
        IrNodeKind::AwaitExpr, IrNodeKind::YieldExpr, IrNodeKind::TemplateStr,
        IrNodeKind::SpreadExpr, IrNodeKind::OptionalChain, IrNodeKind::JsxElement,
        IrNodeKind::Export, IrNodeKind::SequenceExpr,
        IrNodeKind::InterfaceDecl, IrNodeKind::EnumDecl, IrNodeKind::AsExpr,
        IrNodeKind::NonNullExpr, IrNodeKind::SatisfiesExpr, IrNodeKind::AmbientDecl,
        IrNodeKind::TypePredicate,
        IrNodeKind::MatchExpr, IrNodeKind::MatchArm, IrNodeKind::ImplBlock, IrNodeKind::TraitDef,
        IrNodeKind::UnsafeBlock, IrNodeKind::ClosureExpr, IrNodeKind::MacroInvocation,
        IrNodeKind::TryExpr, IrNodeKind::LoopExpr, IrNodeKind::RangeExpr, IrNodeKind::StructExpr,
        IrNodeKind::ModDef, IrNodeKind::BreakExpr, IrNodeKind::LifetimeRef, IrNodeKind::UseDecl,
        IrNodeKind::SehLeave,
    ]
}

fn expr_kinds() -> Vec<IrNodeKind> {
    vec![
        IrNodeKind::Call, IrNodeKind::Assign, IrNodeKind::BinaryOp, IrNodeKind::UnaryOp,
        IrNodeKind::TernaryOp, IrNodeKind::Cast, IrNodeKind::Subscript, IrNodeKind::MemberAccess,
        IrNodeKind::LambdaDef, IrNodeKind::NewExpr, IrNodeKind::DeleteExpr, IrNodeKind::SizeofExpr,
        IrNodeKind::Identifier, IrNodeKind::Literal, IrNodeKind::TypeRef,
        IrNodeKind::Yield, IrNodeKind::Await, IrNodeKind::Comprehension, IrNodeKind::NamedExpr,
        IrNodeKind::CollectionExpr, IrNodeKind::ReceiveExpr, IrNodeKind::TypeAssertion,
        IrNodeKind::CompositeLit, IrNodeKind::SwitchExpr, IrNodeKind::InstanceofExpr,
        IrNodeKind::MethodRef, IrNodeKind::NewArray, IrNodeKind::ArrayInit,
        IrNodeKind::ClassLiteral, IrNodeKind::ThisExpr,
        IrNodeKind::AwaitExpr, IrNodeKind::YieldExpr, IrNodeKind::TemplateStr,
        IrNodeKind::SpreadExpr, IrNodeKind::OptionalChain, IrNodeKind::JsxElement,
        IrNodeKind::SequenceExpr, IrNodeKind::AsExpr, IrNodeKind::NonNullExpr,
        IrNodeKind::SatisfiesExpr, IrNodeKind::MatchExpr, IrNodeKind::ClosureExpr,
        IrNodeKind::TryExpr, IrNodeKind::LoopExpr, IrNodeKind::RangeExpr,
        IrNodeKind::StructExpr, IrNodeKind::BreakExpr,
    ]
}

fn stmt_kinds() -> Vec<IrNodeKind> {
    vec![
        IrNodeKind::Block, IrNodeKind::Return, IrNodeKind::Loop, IrNodeKind::Conditional,
        IrNodeKind::Switch, IrNodeKind::Case, IrNodeKind::SwitchDefault, IrNodeKind::Break,
        IrNodeKind::Continue, IrNodeKind::Goto, IrNodeKind::Label, IrNodeKind::Throw,
        IrNodeKind::Try, IrNodeKind::Catch, IrNodeKind::ExprStmt,
        IrNodeKind::Import, IrNodeKind::With, IrNodeKind::Assert, IrNodeKind::Delete,
        IrNodeKind::Global,
        IrNodeKind::GoStmt, IrNodeKind::DeferStmt, IrNodeKind::SelectStmt, IrNodeKind::SendStmt,
        IrNodeKind::ShortVarDecl, IrNodeKind::IncDecStmt, IrNodeKind::Fallthrough,
        IrNodeKind::TypeSwitch, IrNodeKind::Synchronized, IrNodeKind::Finally,
        IrNodeKind::UseDecl, IrNodeKind::ModDef, IrNodeKind::SehLeave,
    ]
}

fn decl_kinds() -> Vec<IrNodeKind> {
    vec![
        IrNodeKind::ParamDef, IrNodeKind::LocalDef, IrNodeKind::FieldDef,
        IrNodeKind::MethodDef, IrNodeKind::ClassDef, IrNodeKind::TypeAlias,
    ]
}

// ── Method validity table ─────────────────────────────────────────────────────

/// Categories of node methods for type-checking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MethodGroup {
    /// Available on ALL node types
    Universal,
    /// Only on Call nodes
    CallOnly,
    /// Only on MethodDef nodes
    MethodDefOnly,
    /// Only on Literal nodes
    LiteralOnly,
    /// Only on ClassDef nodes
    ClassDefOnly,
    /// Only on Identifier nodes
    IdentifierOnly,
}

/// Returns which method group a given method name belongs to, or `None` if unknown.
pub fn method_group(method: &str) -> Option<MethodGroup> {
    match method {
        // Universal (available on any node type)
        "parent" | "ancestor" | "has_ancestor" | "children" | "child"
        | "descendant" | "has_descendant" | "id" | "function_id" | "class_context"
        | "namespace" | "basic_block" | "line" | "end_line" | "file" | "name" | "text"
        | "raw_kind" | "kind" | "operator" | "cpp_meta" | "go_meta" | "python_meta" | "java_meta"
        | "js_meta" | "ts_meta" | "rust_meta" | "is_some" | "is_none"
        // CFG predicates (all universal — CFG is computed per function, not per type)
        | "cfg_reaches" | "cfg_reaches_feasible" | "cfg_reaches_without"
        | "dominates" | "post_dominates" | "same_block" | "same_function"
        | "in_loop" | "loop_has_no_exit" | "in_exception_path"
        | "guard_evals_true" | "guard_evals_false" | "in_dead_branch"
        // DFG predicates
        | "dfg_reaches" | "dfg_flows_to" | "dfg_def" | "dfg_use"
        // Symbolic evaluation
        | "eval_int" | "eval_bool" | "is_const_expr"
        // Branch/loop condition access
        | "branch_condition" | "loop_condition"
        // Alias analysis
        | "points_to" | "alias_target" | "is_pointer"
        // Nullability
        | "may_be_null" | "null_source"
        // Size tracking
        | "alloc_size" | "has_known_size"
        => Some(MethodGroup::Universal),

        // Call-only
        "callee_name" | "qualified_callee" | "arg" | "arg_count" | "has_arg"
        | "callee_kind" | "return_value" | "receiver"
        => Some(MethodGroup::CallOnly),

        // MethodDef-only
        "is_constructor" | "is_destructor" | "is_virtual" | "visibility"
        | "param" | "param_count" | "return_type"
        => Some(MethodGroup::MethodDefOnly),

        // Literal-only
        "lit_kind" | "string_value" | "int_value"
        => Some(MethodGroup::LiteralOnly),

        // ClassDef-only
        "base_classes" | "implements"
        => Some(MethodGroup::ClassDefOnly),

        // Identifier-only
        "refers_to"
        => Some(MethodGroup::IdentifierOnly),

        _ => None,
    }
}

/// Check if `method` is valid on a variable of type `ty`.
/// Returns `Ok(())` if valid, or `Err(hint)` with a helpful message.
pub fn check_method_on_type(method: &str, ty: &TypeExpr) -> Result<(), String> {
    let group = match method_group(method) {
        Some(g) => g,
        None => return Err(format!("unknown method `{method}()`")),
    };

    match group {
        MethodGroup::Universal => Ok(()),
        MethodGroup::CallOnly => {
            if matches!(ty, TypeExpr::Call | TypeExpr::Node | TypeExpr::Expr | TypeExpr::Named(_)) {
                Ok(())
            } else {
                Err(format!(
                    "`{method}()` is only available on Call nodes, not {ty}; \
                    did you mean a `Call` binding?"
                ))
            }
        }
        MethodGroup::MethodDefOnly => {
            if matches!(ty, TypeExpr::MethodDef | TypeExpr::Node | TypeExpr::Decl | TypeExpr::Named(_)) {
                Ok(())
            } else {
                Err(format!(
                    "`{method}()` is only available on MethodDef nodes, not {ty}; \
                    did you mean a `MethodDef` binding?"
                ))
            }
        }
        MethodGroup::LiteralOnly => {
            if matches!(ty, TypeExpr::Literal | TypeExpr::Node | TypeExpr::Expr | TypeExpr::Named(_)) {
                Ok(())
            } else {
                Err(format!(
                    "`{method}()` is only available on Literal nodes, not {ty}"
                ))
            }
        }
        MethodGroup::ClassDefOnly => {
            if matches!(ty, TypeExpr::ClassDef | TypeExpr::Node | TypeExpr::Decl | TypeExpr::Named(_)) {
                Ok(())
            } else {
                Err(format!(
                    "`{method}()` is only available on ClassDef nodes, not {ty}"
                ))
            }
        }
        MethodGroup::IdentifierOnly => {
            if matches!(ty, TypeExpr::Identifier | TypeExpr::Node | TypeExpr::Expr | TypeExpr::Named(_)) {
                Ok(())
            } else {
                Err(format!(
                    "`{method}()` is only available on Identifier nodes, not {ty}"
                ))
            }
        }
    }
}
