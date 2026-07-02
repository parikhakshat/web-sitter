//! Public read API over the per-language type-inference results in [`crate::type_inference`].
//!
//! `type_inference.rs` itself is almost entirely `pub(crate)` — its `infer_*_types`
//! passes are build-time steps run once during CPG construction, not something an
//! external caller should invoke directly. What an external caller (the MCP server's
//! `symbol_summary` tool, in particular) actually needs is a *read* API: "what type did
//! inference assign to this node?", rendered as something readable rather than a raw
//! `{:?}` dump of a recursive enum. That's what this module provides:
//!
//! - [`Display`] impls for every per-language type enum (`CType`, `GoType`, `PyType`,
//!   `JavaType`, `JsType`, `TsType`, `RustType`), each rendering roughly like the
//!   source-level type syntax of its language (`int*`, `List[int]`, `Map<string, int>`).
//! - [`symbol_type_string`], a single cross-language dispatcher that reads
//!   `cpg.language` to pick the right per-language metadata map (`cpg.cpp_metadata`,
//!   `cpg.go_metadata`, ...) and returns the rendered type, so callers never need to
//!   match on language themselves.
//!
//! Class-hierarchy lookup — the other half of the "type-of-symbol" read API — needs no
//! new code: `Cpg::workspace.class_hierarchy: BTreeMap<String, Vec<String>>` (type name
//! -> direct supertypes) is already a public field, populated by
//! `type_inference::build_class_hierarchy`.

use std::fmt;

use crate::{CType, Cpg, GoType, JavaType, JsType, NodeId, PyType, RustType, TsType};

impl fmt::Display for CType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CType::Void => write!(f, "void"),
            CType::Bool => write!(f, "bool"),
            CType::Char => write!(f, "char"),
            CType::SChar => write!(f, "signed char"),
            CType::UChar => write!(f, "unsigned char"),
            CType::Short => write!(f, "short"),
            CType::UShort => write!(f, "unsigned short"),
            CType::Int => write!(f, "int"),
            CType::UInt => write!(f, "unsigned int"),
            CType::Long => write!(f, "long"),
            CType::ULong => write!(f, "unsigned long"),
            CType::LongLong => write!(f, "long long"),
            CType::ULongLong => write!(f, "unsigned long long"),
            CType::Float => write!(f, "float"),
            CType::Double => write!(f, "double"),
            CType::LongDouble => write!(f, "long double"),
            CType::NullptrT => write!(f, "nullptr_t"),
            CType::Pointer(elem) => write!(f, "{elem}*"),
            CType::Array {
                elem,
                len: Some(len),
            } => write!(f, "{elem}[{len}]"),
            CType::Array { elem, len: None } => write!(f, "{elem}[]"),
            CType::Named(name) => write!(f, "{name}"),
            CType::Unknown => write!(f, "?"),
        }
    }
}

impl fmt::Display for GoType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GoType::Named(name) => write!(f, "{name}"),
            GoType::Pointer(elem) => write!(f, "*{elem}"),
            GoType::Slice(elem) => write!(f, "[]{elem}"),
            GoType::Array {
                len: Some(len),
                elem,
            } => write!(f, "[{len}]{elem}"),
            GoType::Array { len: None, elem } => write!(f, "[...]{elem}"),
            GoType::Map { key, value } => write!(f, "map[{key}]{value}"),
            GoType::Chan { elem, .. } => write!(f, "chan {elem}"),
            GoType::Func { params, returns } => {
                write!(f, "func({})", join(params))?;
                if !returns.is_empty() {
                    write!(f, " ({})", join(returns))?;
                }
                Ok(())
            }
            GoType::Interface(methods) => write!(f, "interface{{{}}}", methods.join(", ")),
            GoType::Tuple(items) => write!(f, "({})", join(items)),
            GoType::Generic { name, args } => write!(f, "{name}[{}]", join(args)),
            GoType::Unknown => write!(f, "?"),
        }
    }
}

impl fmt::Display for PyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PyType::Unknown => write!(f, "?"),
            PyType::None_ => write!(f, "None"),
            PyType::Bool => write!(f, "bool"),
            PyType::Int => write!(f, "int"),
            PyType::Float => write!(f, "float"),
            PyType::Complex => write!(f, "complex"),
            PyType::Str => write!(f, "str"),
            PyType::Bytes => write!(f, "bytes"),
            PyType::List(Some(elem)) => write!(f, "List[{elem}]"),
            PyType::List(None) => write!(f, "List"),
            PyType::Dict {
                key: Some(k),
                value: Some(v),
            } => write!(f, "Dict[{k}, {v}]"),
            PyType::Dict { .. } => write!(f, "Dict"),
            PyType::Set(Some(elem)) => write!(f, "Set[{elem}]"),
            PyType::Set(None) => write!(f, "Set"),
            PyType::Tuple(items) => write!(f, "Tuple[{}]", join(items)),
            PyType::Generator(elem) => write!(f, "Generator[{elem}]"),
            PyType::Coroutine(elem) => write!(f, "Coroutine[{elem}]"),
            PyType::Class(name) => write!(f, "{name}"),
            PyType::Function => write!(f, "Callable"),
            PyType::Module(name) => write!(f, "module {name}"),
            PyType::Optional(elem) => write!(f, "Optional[{elem}]"),
            PyType::Union(items) => write!(f, "Union[{}]", join(items)),
        }
    }
}

impl fmt::Display for JavaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JavaType::Primitive(name) => write!(f, "{name}"),
            JavaType::Object(name) => write!(f, "{name}"),
            JavaType::Array(elem) => write!(f, "{elem}[]"),
            JavaType::Generic { base, args } => write!(f, "{base}<{}>", join(args)),
            JavaType::Void => write!(f, "void"),
            JavaType::Null => write!(f, "null"),
            JavaType::Unknown => write!(f, "?"),
        }
    }
}

impl fmt::Display for JsType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JsType::Undefined => write!(f, "undefined"),
            JsType::Null => write!(f, "null"),
            JsType::Boolean => write!(f, "boolean"),
            JsType::Number => write!(f, "number"),
            JsType::BigInt => write!(f, "bigint"),
            JsType::Str => write!(f, "string"),
            JsType::Symbol => write!(f, "symbol"),
            JsType::Object => write!(f, "object"),
            JsType::Array(Some(elem)) => write!(f, "{elem}[]"),
            JsType::Array(None) => write!(f, "Array"),
            JsType::Function => write!(f, "Function"),
            JsType::Any => write!(f, "any"),
            JsType::Unknown => write!(f, "?"),
        }
    }
}

impl fmt::Display for TsType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TsType::Any => write!(f, "any"),
            TsType::Unknown_ => write!(f, "unknown"),
            TsType::Never => write!(f, "never"),
            TsType::Void => write!(f, "void"),
            TsType::Undefined => write!(f, "undefined"),
            TsType::Null => write!(f, "null"),
            TsType::Boolean => write!(f, "boolean"),
            TsType::Number => write!(f, "number"),
            TsType::BigInt => write!(f, "bigint"),
            TsType::Str => write!(f, "string"),
            TsType::Symbol => write!(f, "symbol"),
            TsType::Object => write!(f, "object"),
            TsType::Array(Some(elem)) => write!(f, "{elem}[]"),
            TsType::Array(None) => write!(f, "Array"),
            TsType::Tuple(items) => write!(f, "[{}]", join(items)),
            TsType::Union(items) => write!(f, "{}", join_with(items, " | ")),
            TsType::Intersection(items) => write!(f, "{}", join_with(items, " & ")),
            TsType::Function { params, ret } => write!(f, "({}) => {ret}", join(params)),
            TsType::Literal(text) => write!(f, "{text}"),
            TsType::Conditional => write!(f, "<conditional>"),
            TsType::Mapped => write!(f, "<mapped>"),
            TsType::Named(name) => write!(f, "{name}"),
            TsType::Generic { name, args } => write!(f, "{name}<{}>", join(args)),
            TsType::Inferred => write!(f, "?"),
        }
    }
}

impl fmt::Display for RustType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RustType::Prim(kind) => write!(f, "{}", prim_kind_str(*kind)),
            RustType::Ref(elem) => write!(f, "&{elem}"),
            RustType::MutRef(elem) => write!(f, "&mut {elem}"),
            RustType::Slice(elem) => write!(f, "[{elem}]"),
            RustType::Array {
                elem,
                len: Some(len),
            } => write!(f, "[{elem}; {len}]"),
            RustType::Array { elem, len: None } => write!(f, "[{elem}; _]"),
            RustType::Str => write!(f, "str"),
            RustType::Named(name) => write!(f, "{name}"),
            RustType::Generic { name, args } => write!(f, "{name}<{}>", join(args)),
            RustType::Tuple(items) => write!(f, "({})", join(items)),
            RustType::Function { params, ret } => write!(f, "fn({}) -> {ret}", join(params)),
            RustType::Trait(name) => write!(f, "dyn {name}"),
            RustType::Opaque(name) => write!(f, "impl {name}"),
            RustType::Unknown => write!(f, "?"),
        }
    }
}

fn prim_kind_str(kind: crate::PrimKind) -> &'static str {
    use crate::PrimKind::*;
    match kind {
        I8 => "i8",
        I16 => "i16",
        I32 => "i32",
        I64 => "i64",
        I128 => "i128",
        Isize => "isize",
        U8 => "u8",
        U16 => "u16",
        U32 => "u32",
        U64 => "u64",
        U128 => "u128",
        Usize => "usize",
        F32 => "f32",
        F64 => "f64",
        Bool => "bool",
        Char => "char",
        Str => "str",
    }
}

fn join<T: fmt::Display>(items: &[T]) -> String {
    join_with(items, ", ")
}

fn join_with<T: fmt::Display>(items: &[T], sep: &str) -> String {
    items
        .iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(sep)
}

/// The inferred/resolved type of `node_id` in `cpg`, rendered as a readable string, or
/// `None` if `cpg.language` isn't recognized, the node has no metadata entry, or
/// inference never assigned it a type. Dispatches on `cpg.language` to the matching
/// per-language metadata map (`cpg.cpp_metadata`, `cpg.go_metadata`, ...) so callers
/// don't need to know which map or which `*Type` enum backs a given language.
pub fn symbol_type_string(cpg: &Cpg, node_id: NodeId) -> Option<String> {
    match cpg.language.as_str() {
        "c" | "cpp" => cpg
            .cpp_metadata
            .get(&node_id)
            .and_then(|m| m.inferred_type.as_ref())
            .map(|t| t.to_string()),
        "go" => cpg
            .go_metadata
            .get(&node_id)
            .and_then(|m| m.inferred_type.as_ref())
            .map(|t| t.to_string()),
        "python" => cpg
            .python_metadata
            .get(&node_id)
            .and_then(|m| m.inferred_type.as_ref())
            .map(|t| t.to_string()),
        "java" => cpg
            .java_metadata
            .get(&node_id)
            .and_then(|m| m.inferred_type.as_ref())
            .map(|t| t.to_string()),
        "javascript" => cpg
            .js_metadata
            .get(&node_id)
            .and_then(|m| m.inferred_type.as_ref())
            .map(|t| t.to_string()),
        "typescript" => cpg
            .ts_metadata
            .get(&node_id)
            .and_then(|m| m.resolved_type.as_ref())
            .map(|t| t.to_string()),
        "rust" => cpg
            .rust_metadata
            .get(&node_id)
            .and_then(|m| m.inferred_type.as_ref())
            .map(|t| t.to_string()),
        _ => None,
    }
}

/// Direct declared supertypes (`extends` + `implements`) of `type_name`, or `None` if
/// `type_name` isn't in the workspace's class hierarchy. Thin named wrapper around
/// `Cpg::workspace.class_hierarchy` — the field itself is already public, but a named
/// accessor documents this as the intended stable read entry point for callers outside
/// this crate (e.g. `web-mcp`'s `symbol_summary` tool) rather than a field they happen
/// to be able to reach.
pub fn class_supertypes<'a>(cpg: &'a Cpg, type_name: &str) -> Option<&'a Vec<String>> {
    cpg.workspace.class_hierarchy.get(type_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpg_generator::{GraphBuildOptions, SourceLanguage};
    use crate::incremental::IncrementalCpgGenerator;
    use crate::IrNodeKind;

    fn parse(lang: SourceLanguage, src: &str) -> Cpg {
        let mut generator =
            IncrementalCpgGenerator::new_for_language(lang, GraphBuildOptions::default())
                .expect("generator");
        generator.parse_full(src.as_bytes()).expect("parse").clone()
    }

    #[test]
    fn ctype_display_renders_pointer_and_named() {
        assert_eq!(CType::Int.to_string(), "int");
        assert_eq!(CType::Pointer(Box::new(CType::Char)).to_string(), "char*");
        assert_eq!(CType::Named("Foo".into()).to_string(), "Foo");
    }

    #[test]
    fn pytype_display_renders_generics() {
        assert_eq!(
            PyType::List(Some(Box::new(PyType::Int))).to_string(),
            "List[int]"
        );
        assert_eq!(
            PyType::Dict {
                key: Some(Box::new(PyType::Str)),
                value: Some(Box::new(PyType::Int))
            }
            .to_string(),
            "Dict[str, int]"
        );
    }

    #[test]
    fn rusttype_display_renders_prim_and_ref() {
        assert_eq!(RustType::Prim(crate::PrimKind::I32).to_string(), "i32");
        assert_eq!(RustType::Ref(Box::new(RustType::Str)).to_string(), "&str");
    }

    #[test]
    fn symbol_type_string_resolves_c_literal_type() {
        let cpg = parse(SourceLanguage::C, "int x = 5;");
        let literal_id = cpg
            .ast
            .iter()
            .find(|(_, n)| n.kind == IrNodeKind::Literal)
            .map(|(id, _)| *id)
            .expect("literal node");
        let type_str = symbol_type_string(&cpg, literal_id);
        assert_eq!(type_str.as_deref(), Some("int"));
    }

    #[test]
    fn symbol_type_string_none_for_untyped_node() {
        let cpg = parse(SourceLanguage::C, "int helper(int y) { return y; }");
        let fn_id = cpg
            .ast
            .iter()
            .find(|(_, n)| n.kind == IrNodeKind::MethodDef)
            .map(|(id, _)| *id)
            .expect("fn node");
        // MethodDef nodes don't carry an inferred_type themselves.
        assert_eq!(symbol_type_string(&cpg, fn_id), None);
    }

    #[test]
    fn class_supertypes_reads_workspace_hierarchy() {
        let mut cpg = parse(SourceLanguage::Cpp, "struct Foo {};");
        cpg.workspace
            .class_hierarchy
            .insert("Bar".to_string(), vec!["Foo".to_string()]);
        assert_eq!(
            class_supertypes(&cpg, "Bar"),
            Some(&vec!["Foo".to_string()])
        );
        assert_eq!(class_supertypes(&cpg, "Nonexistent"), None);
    }
}
