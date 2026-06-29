#![allow(dead_code)]
use std::collections::BTreeMap;

use crate::{CType, ChannelDirection, Cpg, GoType, IrNodeKind, JavaType, JsType, LiteralKind, LoopKind, NodeId, PyType, RustType, TsType};

// ── Type inference passes ──────────────────────────────────────────────────────

/// Parse a C/C++ number_literal suffix to decide int vs float and width/signedness.
/// Returns `CType::Unknown` when the literal text is empty or unrecognised.
pub(crate) fn c_number_literal_type(text: &str) -> CType {
    let t = text.trim_end_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '-');
    let upper = t.to_ascii_uppercase();

    // Float suffixes: f/F → float, l/L → long double, else double.
    let has_dot   = t.contains('.');
    let has_exp   = t.contains('e') || t.contains('E') || t.contains('p') || t.contains('P');
    if has_dot || has_exp {
        return if upper.ends_with('F') {
            CType::Float
        } else if upper.ends_with('L') {
            CType::LongDouble
        } else {
            CType::Double
        };
    }

    // Hex integer (0x…) or octal/binary — strip prefix, then look at suffix.
    // Integer suffixes (case-insensitive): u → unsigned, ll → long long, l → long.
    let is_unsigned = upper.contains('U');
    let is_ll       = upper.contains("LL");
    let is_l        = !is_ll && upper.ends_with('L');

    if is_ll  && is_unsigned { CType::ULongLong }
    else if is_ll             { CType::LongLong  }
    else if is_l  && is_unsigned { CType::ULong  }
    else if is_l              { CType::Long       }
    else if is_unsigned       { CType::UInt       }
    else                      { CType::Int        }
}

/// Map a C/C++ type-specifier text to a `CType` variant.
pub(crate) fn c_type_from_specifier(text: &str) -> CType {
    let upper = text.to_ascii_uppercase();
    match text.trim() {
        "void" => return CType::Void,
        "bool" | "_Bool" => return CType::Bool,
        "char" => return CType::Char,
        "float" => return CType::Float,
        "double" => return CType::Double,
        "int" | "signed" | "signed int" => return CType::Int,
        "unsigned" | "unsigned int" => return CType::UInt,
        _ => {}
    }
    let is_u = upper.contains("UNSIGNED");
    let has_ll = upper.contains("LONG LONG") || {
        let uu = upper.replace("UNSIGNED", "").replace("SIGNED", "");
        uu.contains("LL") || uu.matches("LONG").count() >= 2
    };
    let has_l = !has_ll && upper.contains("LONG");
    let has_short = upper.contains("SHORT");
    let has_ld = has_l && upper.contains("DOUBLE");
    let has_dbl = upper.contains("DOUBLE");
    let has_flt = upper.contains("FLOAT");
    let has_s_char = upper.contains("SIGNED") && upper.contains("CHAR");
    let has_u_char = is_u && upper.contains("CHAR");
    if has_u_char { return CType::UChar; }
    if has_s_char { return CType::SChar; }
    if has_ld { return CType::LongDouble; }
    if has_dbl { return CType::Double; }
    if has_flt { return CType::Float; }
    if has_ll && is_u { return CType::ULongLong; }
    if has_ll { return CType::LongLong; }
    if has_l && is_u { return CType::ULong; }
    if has_l { return CType::Long; }
    if has_short && is_u { return CType::UShort; }
    if has_short { return CType::Short; }
    if is_u { return CType::UInt; }
    CType::Named(text.trim().to_string())
}

/// Map a Java type-specifier text to a `JavaType` variant.
pub(crate) fn java_type_from_text(text: &str) -> JavaType {
    let t = text.trim();
    if t.ends_with("[]") {
        return JavaType::Array(Box::new(java_type_from_text(&t[..t.len()-2])));
    }
    if let Some(idx) = t.find('<') {
        let base = t[..idx].trim().to_string();
        let inner_text = t.get(idx+1..).and_then(|s| s.strip_suffix('>'));
        if let Some(inner) = inner_text {
            return JavaType::Generic { base, args: vec![java_type_from_text(inner)] };
        }
        return JavaType::Object(base);
    }
    match t {
        "int" | "byte" | "short" | "long" | "char" | "float" | "double" | "boolean" => {
            JavaType::Primitive(t.to_string())
        }
        "void" => JavaType::Void,
        "null" => JavaType::Null,
        _ => JavaType::Object(t.to_string()),
    }
}

/// Map a Python annotation text to the closest `PyType` variant.
pub(crate) fn py_type_from_annotation(text: &str) -> PyType {
    let t = text.trim();
    match t {
        "int" => PyType::Int,
        "float" => PyType::Float,
        "str" => PyType::Str,
        "bool" => PyType::Bool,
        "None" | "NoneType" => PyType::None_,
        "bytes" => PyType::Bytes,
        "complex" => PyType::Complex,
        _ if t.starts_with("List") || t.starts_with("list") => PyType::List(None),
        _ if t.starts_with("Dict") || t.starts_with("dict") => {
            PyType::Dict { key: None, value: None }
        }
        _ if t.starts_with("Set") || t.starts_with("set") => PyType::Set(None),
        _ if t.starts_with("Tuple") || t.starts_with("tuple") => PyType::Tuple(Vec::new()),
        _ if t.starts_with("Optional") => PyType::Optional(Box::new(PyType::Unknown)),
        _ => PyType::Class(t.to_string()),
    }
}

/// C type inference: literal-level only. Populates `CppNodeMetadata.inferred_type`
/// for every literal AST node in a C compilation unit.
pub(crate) fn infer_c_types(cpg: &mut Cpg) {
    // Pass 1: literals
    let ids: Vec<NodeId> = cpg.ast.keys().copied().collect();
    for &node_id in &ids {
        let node = &cpg.ast[&node_id];
        let inferred: Option<CType> = match node.node_type.as_str() {
            "number_literal" => {
                let text = node.text.as_deref().unwrap_or("");
                Some(c_number_literal_type(text))
            }
            "string_literal" | "concatenated_string" => {
                Some(CType::Pointer(Box::new(CType::Char)))
            }
            "char_literal" => Some(CType::Char),
            // C99 _Bool via <stdbool.h> macros true/false; tree-sitter surfaces them as keywords
            "true" | "false" => Some(CType::Bool),
            // NULL is conventionally (void*)0; we record Pointer(Void)
            "null" => Some(CType::Pointer(Box::new(CType::Void))),
            _ => None,
        };
        if let Some(t) = inferred {
            let meta = cpg.cpp_meta_mut(node_id);
            if meta.inferred_type.is_none() {
                meta.inferred_type = Some(t);
            }
        }
    }

    // Pass 2: propagate from `declaration` type-specifier to declarator children
    // Collect (target_node_id, CType) first to avoid borrow conflicts.
    let decl_targets: Vec<(NodeId, CType)> = cpg.ast.iter()
        .filter(|(_, n)| n.node_type == "declaration")
        .flat_map(|(_, decl)| {
            let type_text: Option<String> = decl.children.iter().find_map(|&cid| {
                cpg.ast.get(&cid).and_then(|c| {
                    if matches!(c.node_type.as_str(),
                        "primitive_type" | "sized_type_specifier" | "type_qualifier") {
                        c.text.clone()
                    } else {
                        None
                    }
                })
            });
            let c_type = c_type_from_specifier(type_text.as_deref().unwrap_or("int"));
            let declarator_ids: Vec<NodeId> = decl.children.iter().filter_map(|&cid| {
                cpg.ast.get(&cid).and_then(|c| {
                    if matches!(c.node_type.as_str(),
                        "init_declarator" | "pointer_declarator" | "array_declarator") {
                        Some(cid)
                    } else {
                        None
                    }
                })
            }).collect();
            declarator_ids.into_iter().map(move |id| (id, c_type.clone()))
        })
        .collect();
    for (node_id, c_type) in decl_targets {
        let meta = cpg.cpp_meta_mut(node_id);
        if meta.inferred_type.is_none() {
            meta.inferred_type = Some(c_type);
        }
    }
}

/// C++ type inference: superset of C. Adds nullptr_t and delegates to
/// `infer_c_types` for shared literal kinds.
pub(crate) fn infer_cpp_types(cpg: &mut Cpg) {
    infer_c_types(cpg);
    let ids: Vec<NodeId> = cpg.ast.keys().copied().collect();
    for &node_id in &ids {
        let node = &cpg.ast[&node_id];
        // `true`/`false` are already handled by infer_c_types as Bool;
        // `nullptr` is C++-only: its type is std::nullptr_t.
        if node.node_type.as_str() == "nullptr" {
            let meta = cpg.cpp_meta_mut(node_id);
            if meta.inferred_type.is_none() {
                meta.inferred_type = Some(CType::NullptrT);
            }
        }
    }
}

/// Go type inference: propagates Go type annotations from type declarations and
/// function signatures into `GoNodeMetadata.inferred_type` for each node.
pub(crate) fn infer_go_types(cpg: &mut Cpg) {
    // Pass 1: literals and channel types
    // Note: imaginary_literal metadata must be set before the shared loop to avoid
    // a re-borrow of cpg inside the match body.
    let imaginary_ids: Vec<NodeId> = cpg.ast.iter()
        .filter(|(_, n)| n.node_type == "imaginary_literal")
        .map(|(id, _)| *id)
        .collect();
    for &node_id in &imaginary_ids {
        cpg.go_meta_mut(node_id).is_imaginary = true;
    }

    let ids: Vec<NodeId> = cpg.ast.keys().copied().collect();
    for &node_id in &ids {
        let node = &cpg.ast[&node_id];
        let inferred = match node.node_type.as_str() {
            "interpreted_string_literal" | "raw_string_literal" => {
                Some(GoType::Named("string".to_string()))
            }
            "int_literal" | "imaginary_literal" => Some(GoType::Named("int".to_string())),
            "float_literal" => Some(GoType::Named("float64".to_string())),
            "rune_literal" => Some(GoType::Named("rune".to_string())),
            "true" | "false" => Some(GoType::Named("bool".to_string())),
            "nil" => Some(GoType::Named("nil".to_string())),
            "channel_type" => {
                let dir = cpg.go_metadata.get(&node_id)
                    .and_then(|m| m.channel_direction)
                    .unwrap_or(crate::ChannelDirection::Bidi);
                Some(GoType::Chan { dir, elem: Box::new(GoType::Unknown) })
            }
            _ => None,
        };
        if let Some(t) = inferred {
            let meta = cpg.go_meta_mut(node_id);
            if meta.inferred_type.is_none() {
                meta.inferred_type = Some(t);
            }
        }
    }

    // Pass 2a: var_spec / const_spec with explicit type annotation
    // Walk each LocalDef node with a TypeRef child; annotate the identifier children.
    let var_spec_targets: Vec<(NodeId, GoType)> = cpg.ast.iter()
        .filter(|(_, n)| matches!(n.node_type.as_str(), "var_spec" | "const_spec"))
        .flat_map(|(_, spec)| {
            let type_text: Option<String> = spec.children.iter().find_map(|&cid| {
                cpg.ast.get(&cid).and_then(|c| {
                    if c.kind == IrNodeKind::TypeRef { c.text.clone() } else { None }
                })
            });
            let go_type = GoType::Named(type_text.unwrap_or_default());
            spec.children.iter().filter_map(|&cid| {
                cpg.ast.get(&cid).and_then(|c| {
                    if c.is_identifier() { Some((cid, go_type.clone())) } else { None }
                })
            }).collect::<Vec<_>>()
        })
        .collect();
    for (node_id, go_type) in var_spec_targets {
        let meta = cpg.go_meta_mut(node_id);
        if meta.inferred_type.is_none() {
            meta.inferred_type = Some(go_type);
        }
    }

    // Pass 2b: composite_literal — infer type from the type-prefix child.
    // e.g. `Point{x: 1, y: 2}` → annotate the composite_literal node as GoType::Named("Point").
    let composite_lit_ids: Vec<(NodeId, GoType)> = cpg.ast.iter()
        .filter(|(_, n)| n.kind == IrNodeKind::CompositeLit)
        .filter_map(|(&id, lit)| {
            let type_text: Option<String> = lit.children.first().and_then(|&cid| {
                cpg.ast.get(&cid)
                    .filter(|c| c.kind == IrNodeKind::TypeRef || c.is_identifier())
                    .and_then(|c| c.text.clone())
            });
            type_text.map(|t| (id, GoType::Named(t)))
        })
        .collect();
    for (node_id, go_type) in composite_lit_ids {
        let meta = cpg.go_meta_mut(node_id);
        if meta.inferred_type.is_none() {
            meta.inferred_type = Some(go_type);
        }
    }
}

/// Python type inference: infers types from literal expressions, builtin calls,
/// and type annotations. Populates `PythonNodeMetadata.inferred_type`.
pub(crate) fn infer_python_types(cpg: &mut Cpg) {
    // Pass 1: literals
    let ids: Vec<NodeId> = cpg.ast.keys().copied().collect();
    for &node_id in &ids {
        let node = &cpg.ast[&node_id];
        let inferred = match node.node_type.as_str() {
            "integer" => Some(PyType::Int),
            "float" => Some(PyType::Float),
            "string" | "concatenated_string" => Some(PyType::Str),
            "true" | "false" => Some(PyType::Bool),
            "none" => Some(PyType::None_),
            "list" => Some(PyType::List(None)),
            "tuple" => Some(PyType::Tuple(Vec::new())),
            "set" => Some(PyType::Set(None)),
            "dictionary" => Some(PyType::Dict { key: None, value: None }),
            _ => None,
        };
        if let Some(t) = inferred {
            let meta = cpg.python_meta_mut(node_id);
            if meta.inferred_type.is_none() {
                meta.inferred_type = Some(t);
            }
        }
    }

    // Pass 2: annotated assignments (`x: int = 1` → annotate the LHS identifier)
    // Tree-sitter node: "annotated_assignment" with children [identifier, type, value?]
    // The `type` child (IrNodeKind::TypeRef) holds the annotation text.
    let annot_targets: Vec<(NodeId, PyType)> = cpg.ast.iter()
        .filter(|(_, n)| n.node_type == "annotated_assignment")
        .flat_map(|(_, assign)| {
            let type_text: Option<String> = assign.children.iter().find_map(|&cid| {
                cpg.ast.get(&cid).and_then(|c| {
                    if c.kind == IrNodeKind::TypeRef { c.text.clone() } else { None }
                })
            });
            let py_type = py_type_from_annotation(type_text.as_deref().unwrap_or(""));
            assign.children.iter().filter_map(|&cid| {
                cpg.ast.get(&cid).and_then(|c| {
                    if c.is_identifier() { Some((cid, py_type.clone())) } else { None }
                })
            }).collect::<Vec<_>>()
        })
        .collect();
    for (node_id, py_type) in annot_targets {
        let meta = cpg.python_meta_mut(node_id);
        if meta.inferred_type.is_none() {
            meta.inferred_type = Some(py_type);
        }
    }

    // Pass 3: propagate function return annotations into `resolved_type` on MethodDef nodes.
    // `return_annotation` is already populated by the lifter into PythonNodeMetadata.
    let func_ids_with_ret: Vec<(NodeId, String)> = cpg.python_metadata.iter()
        .filter_map(|(&id, m)| m.return_annotation.clone().map(|r| (id, r)))
        .collect();
    for (node_id, ret_text) in func_ids_with_ret {
        let meta = cpg.python_meta_mut(node_id);
        if meta.resolved_type.is_none() {
            meta.resolved_type = Some(ret_text);
        }
    }
}

/// Java type inference: infers types from literal expressions and explicit
/// type declarations. Populates `JavaNodeMetadata.inferred_type`.
pub(crate) fn infer_java_types(cpg: &mut Cpg) {
    // Pass 1: literals and explicit type nodes
    let ids: Vec<NodeId> = cpg.ast.keys().copied().collect();
    for &node_id in &ids {
        let node = &cpg.ast[&node_id];
        let inferred = match node.node_type.as_str() {
            "decimal_integer_literal" | "hex_integer_literal"
            | "octal_integer_literal" | "binary_integer_literal" => {
                Some(JavaType::Primitive("int".to_string()))
            }
            "decimal_floating_point_literal" | "hex_floating_point_literal" => {
                Some(JavaType::Primitive("double".to_string()))
            }
            "string_literal" | "text_block" => Some(JavaType::Object("String".to_string())),
            "character_literal" => Some(JavaType::Primitive("char".to_string())),
            "true" | "false" => Some(JavaType::Primitive("boolean".to_string())),
            "null_literal" => Some(JavaType::Null),
            "void_type" => Some(JavaType::Void),
            "integral_type" => {
                let t = node.text.as_deref().unwrap_or("int").to_string();
                Some(JavaType::Primitive(t))
            }
            "floating_point_type" => {
                let t = node.text.as_deref().unwrap_or("double").to_string();
                Some(JavaType::Primitive(t))
            }
            "boolean_type" => Some(JavaType::Primitive("boolean".to_string())),
            _ => None,
        };
        if let Some(t) = inferred {
            let meta = cpg.java_meta_mut(node_id);
            if meta.inferred_type.is_none() {
                meta.inferred_type = Some(t);
            }
        }
    }

    // Pass 2: local_variable_declaration — propagate declared type to variable_declarator children.
    // Also handle `var` keyword (Java 10+) by copying from RHS literal inferred type.
    let decl_targets: Vec<(NodeId, JavaType)> = cpg.ast.iter()
        .filter(|(_, n)| n.node_type == "local_variable_declaration")
        .flat_map(|(_, decl)| {
            // The type child is typically the first child with kind TypeRef.
            let type_text: Option<String> = decl.children.iter().find_map(|&cid| {
                cpg.ast.get(&cid).and_then(|c| {
                    if c.kind == IrNodeKind::TypeRef { c.text.clone() } else { None }
                })
            });
            let java_type = java_type_from_text(type_text.as_deref().unwrap_or("Object"));
            // Collect variable_declarator children
            decl.children.iter().filter_map(|&cid| {
                cpg.ast.get(&cid).and_then(|c| {
                    if c.node_type == "variable_declarator" {
                        Some((cid, java_type.clone()))
                    } else {
                        None
                    }
                })
            }).collect::<Vec<_>>()
        })
        .collect();
    for (node_id, java_type) in decl_targets {
        let meta = cpg.java_meta_mut(node_id);
        if meta.inferred_type.is_none() {
            meta.inferred_type = Some(java_type);
        }
    }

    // Pass 3: collect generic type params from `type_arguments` children into parent metadata.
    let generic_targets: Vec<(NodeId, Vec<String>)> = cpg.ast.iter()
        .filter(|(_, n)| n.node_type == "type_arguments" || n.node_type == "generic_type")
        .filter_map(|(_, gn)| {
            let parent_id = gn.parent_id?;
            let args: Vec<String> = gn.children.iter().filter_map(|&cid| {
                cpg.ast.get(&cid).and_then(|c| {
                    if c.kind == IrNodeKind::TypeRef || c.is_identifier() {
                        c.text.clone()
                    } else {
                        None
                    }
                })
            }).collect();
            if args.is_empty() { None } else { Some((parent_id, args)) }
        })
        .collect();
    for (node_id, args) in generic_targets {
        let meta = cpg.java_meta_mut(node_id);
        if meta.generic_type_params.is_empty() {
            meta.generic_type_params = args;
        }
    }
}

/// JavaScript type inference: infers types from literal expressions.
/// Populates `JsNodeMetadata.inferred_type`.
pub(crate) fn infer_js_types(cpg: &mut Cpg) {
    // Pass 1: literals
    let ids: Vec<NodeId> = cpg.ast.keys().copied().collect();
    for &node_id in &ids {
        let node = &cpg.ast[&node_id];
        let inferred = match node.node_type.as_str() {
            "number" => Some(JsType::Number),
            "string" | "template_string" => Some(JsType::Str),
            "true" | "false" => Some(JsType::Boolean),
            "null" => Some(JsType::Null),
            "undefined" => Some(JsType::Undefined),
            "array" => Some(JsType::Array(None)),
            "object" => Some(JsType::Object),
            "regex" => Some(JsType::Object), // RegExp is an object
            _ => None,
        };
        if let Some(t) = inferred {
            let meta = cpg.js_meta_mut(node_id);
            if meta.inferred_type.is_none() {
                meta.inferred_type = Some(t);
            }
        }
    }

    // Pass 2: propagate from `variable_declarator` RHS literal to the LHS identifier.
    // Pattern: variable_declarator { children: [identifier, "=", literal] }
    // We copy the literal's already-inferred JsType to the identifier.
    let decl_targets: Vec<(NodeId, JsType)> = cpg.ast.iter()
        .filter(|(_, n)| n.node_type == "variable_declarator")
        .flat_map(|(_, decl)| {
            // LHS: first identifier child
            let lhs_id = decl.children.iter().find(|&&cid| {
                cpg.ast.get(&cid).map(|c| c.is_identifier()).unwrap_or(false)
            }).copied();
            // RHS: last literal child with an inferred type
            let rhs_type: Option<JsType> = decl.children.iter().rev().find_map(|&cid| {
                cpg.js_metadata.get(&cid).and_then(|m| m.inferred_type.clone())
            });
            match (lhs_id, rhs_type) {
                (Some(lhs), Some(t)) => vec![(lhs, t)],
                _ => vec![],
            }
        })
        .collect();
    for (node_id, js_type) in decl_targets {
        let meta = cpg.js_meta_mut(node_id);
        if meta.inferred_type.is_none() {
            meta.inferred_type = Some(js_type);
        }
    }
}

/// TypeScript type inference: propagates type annotations from `type_annotation`
/// and `type_identifier` nodes into `TsNodeMetadata.inferred_type`.
pub(crate) fn infer_ts_types(cpg: &mut Cpg) {
    // First run JS literal inference (TS is a superset of JS).
    let ids: Vec<NodeId> = cpg.ast.keys().copied().collect();
    for &node_id in &ids {
        let node = &cpg.ast[&node_id];
        let inferred = match node.node_type.as_str() {
            "number" => Some(TsType::Number),
            "string" | "template_string" => Some(TsType::Str),
            "true" | "false" => Some(TsType::Boolean),
            "null" => Some(TsType::Null),
            "undefined" => Some(TsType::Undefined),
            "array" => Some(TsType::Array(None)),
            "predefined_type" => {
                let name = node.text.as_deref().unwrap_or("any");
                Some(match name {
                    "any" => TsType::Any,
                    "unknown" => TsType::Unknown_,
                    "never" => TsType::Never,
                    "void" => TsType::Void,
                    "string" => TsType::Str,
                    "number" => TsType::Number,
                    "boolean" => TsType::Boolean,
                    "bigint" => TsType::BigInt,
                    "symbol" => TsType::Symbol,
                    "object" => TsType::Object,
                    "undefined" => TsType::Undefined,
                    "null" => TsType::Null,
                    _ => TsType::Named(name.to_string()),
                })
            }
            "type_identifier" => {
                let name = node.text.as_deref().unwrap_or("unknown").to_string();
                Some(TsType::Named(name))
            }
            _ => None,
        };
        if let Some(t) = inferred {
            let meta = cpg.ts_meta_mut(node_id);
            if meta.resolved_type.is_none() {
                meta.resolved_type = Some(t);
            }
        }
    }

    // Propagate type_annotation text into the annotated node's resolved_type.
    let annotation_ids: Vec<NodeId> = cpg.ast.iter()
        .filter(|(_, n)| n.node_type == "type_annotation")
        .map(|(id, _)| *id)
        .collect();
    for ann_id in annotation_ids {
        let ann_text = cpg.ast.get(&ann_id).and_then(|n| n.text.clone());
        if let Some(text) = ann_text {
            if let Some(parent_id) = cpg.ast.get(&ann_id).and_then(|n| n.parent_id) {
                let meta = cpg.ts_meta_mut(parent_id);
                if meta.type_annotation.is_none() {
                    meta.type_annotation = Some(text);
                }
            }
        }
    }

    // Pass 3: collect generic_type arguments into TsNodeMetadata.generic_constraints on parent.
    // e.g. `Array<string>` → parent gets generic_constraints = [("string", None)]
    let generic_targets: Vec<(NodeId, Vec<(String, Option<String>)>)> = cpg.ast.iter()
        .filter(|(_, n)| n.node_type == "type_arguments")
        .filter_map(|(_, gn)| {
            let parent_id = gn.parent_id?;
            let constraints: Vec<(String, Option<String>)> = gn.children.iter().filter_map(|&cid| {
                cpg.ast.get(&cid).and_then(|c| {
                    if c.kind == IrNodeKind::TypeRef || c.is_identifier() {
                        c.text.as_ref().map(|t| (t.clone(), None))
                    } else {
                        None
                    }
                })
            }).collect();
            if constraints.is_empty() { None } else { Some((parent_id, constraints)) }
        })
        .collect();
    for (node_id, constraints) in generic_targets {
        let meta = cpg.ts_meta_mut(node_id);
        if meta.generic_constraints.is_empty() {
            meta.generic_constraints = constraints;
        }
    }

    // Pass 4: propagate variable_declarator RHS literal type to LHS identifier (same as JS pass 2).
    let decl_targets: Vec<(NodeId, TsType)> = cpg.ast.iter()
        .filter(|(_, n)| n.node_type == "variable_declarator")
        .flat_map(|(_, decl)| {
            let lhs_id = decl.children.iter().find(|&&cid| {
                cpg.ast.get(&cid).map(|c| c.is_identifier()).unwrap_or(false)
            }).copied();
            let rhs_type: Option<TsType> = decl.children.iter().rev().find_map(|&cid| {
                cpg.ts_metadata.get(&cid).and_then(|m| m.resolved_type.clone())
            });
            match (lhs_id, rhs_type) {
                (Some(lhs), Some(t)) => vec![(lhs, t)],
                _ => vec![],
            }
        })
        .collect();
    for (node_id, ts_type) in decl_targets {
        let meta = cpg.ts_meta_mut(node_id);
        if meta.resolved_type.is_none() {
            meta.resolved_type = Some(ts_type);
        }
    }
}

/// Rust type inference: infers types from primitive literals and explicit type
/// annotations. Populates `RustNodeMetadata.inferred_type`.
pub(crate) fn infer_rust_types(cpg: &mut Cpg) {
    use crate::PrimKind;
    let ids: Vec<NodeId> = cpg.ast.keys().copied().collect();
    for &node_id in &ids {
        let node = &cpg.ast[&node_id];
        let inferred = match node.node_type.as_str() {
            "boolean_literal" => Some(RustType::Prim(PrimKind::Bool)),
            "char_literal" => Some(RustType::Prim(PrimKind::Char)),
            "string_literal" | "raw_string_literal" => Some(RustType::Str),
            "integer_literal" => {
                // Parse suffix if present: 42u8, 1i32, etc.
                let text = node.text.as_deref().unwrap_or("");
                let kind = if text.ends_with("u8") { PrimKind::U8 }
                    else if text.ends_with("u16") { PrimKind::U16 }
                    else if text.ends_with("u32") { PrimKind::U32 }
                    else if text.ends_with("u64") { PrimKind::U64 }
                    else if text.ends_with("u128") { PrimKind::U128 }
                    else if text.ends_with("usize") { PrimKind::Usize }
                    else if text.ends_with("i8") { PrimKind::I8 }
                    else if text.ends_with("i16") { PrimKind::I16 }
                    else if text.ends_with("i32") { PrimKind::I32 }
                    else if text.ends_with("i64") { PrimKind::I64 }
                    else if text.ends_with("i128") { PrimKind::I128 }
                    else if text.ends_with("isize") { PrimKind::Isize }
                    else { PrimKind::I32 }; // default integer type
                Some(RustType::Prim(kind))
            }
            "float_literal" => {
                let text = node.text.as_deref().unwrap_or("");
                let kind = if text.ends_with("f32") { PrimKind::F32 } else { PrimKind::F64 };
                Some(RustType::Prim(kind))
            }
            "primitive_type" => {
                let name = node.text.as_deref().unwrap_or("i32");
                let kind = match name {
                    "i8" => PrimKind::I8, "i16" => PrimKind::I16, "i32" => PrimKind::I32,
                    "i64" => PrimKind::I64, "i128" => PrimKind::I128, "isize" => PrimKind::Isize,
                    "u8" => PrimKind::U8, "u16" => PrimKind::U16, "u32" => PrimKind::U32,
                    "u64" => PrimKind::U64, "u128" => PrimKind::U128, "usize" => PrimKind::Usize,
                    "f32" => PrimKind::F32, "f64" => PrimKind::F64,
                    "bool" => PrimKind::Bool, "char" => PrimKind::Char,
                    _ => PrimKind::I32,
                };
                Some(RustType::Prim(kind))
            }
            "type_identifier" | "scoped_type_identifier" => {
                let name = node.text.as_deref().unwrap_or("").to_string();
                if !name.is_empty() { Some(RustType::Named(name)) } else { None }
            }
            _ => None,
        };
        if let Some(t) = inferred {
            let meta = cpg.rust_meta_mut(node_id);
            if meta.inferred_type.is_none() {
                meta.inferred_type = Some(t);
            }
        }
    }

    // Pass 2: let_declaration with explicit type annotation → annotate the pattern child.
    // Tree-sitter Rust: let_declaration { pattern, type: primitive_type/type_identifier, value? }
    let let_targets: Vec<(NodeId, RustType)> = cpg.ast.iter()
        .filter(|(_, n)| n.node_type == "let_declaration")
        .flat_map(|(_, let_decl)| {
            let rust_type: Option<RustType> = let_decl.children.iter().find_map(|&cid| {
                cpg.rust_metadata.get(&cid).and_then(|m| m.inferred_type.clone())
            });
            let rust_type = rust_type.unwrap_or(RustType::Unknown);
            // The pattern is typically the first identifier/pattern child
            let pattern_id = let_decl.children.iter().find(|&&cid| {
                cpg.ast.get(&cid).map(|c| {
                    c.is_identifier() || c.node_type == "identifier" || c.node_type == "pattern"
                }).unwrap_or(false)
            }).copied();
            match pattern_id {
                Some(pid) => vec![(pid, rust_type)],
                None => vec![],
            }
        })
        .collect();
    for (node_id, rust_type) in let_targets {
        let meta = cpg.rust_meta_mut(node_id);
        if meta.inferred_type.is_none() {
            meta.inferred_type = Some(rust_type);
        }
    }

    // Pass 3: initialize ownership_state = Owned for all LocalDef (let_declaration) identifier nodes.
    // The ownership analysis in DFG Phase 2 will then transition these states.
    let local_def_ids: Vec<NodeId> = cpg.ast.iter()
        .filter(|(_, n)| n.is_local_def())
        .map(|(id, _)| *id)
        .collect();
    for node_id in local_def_ids {
        let meta = cpg.rust_meta_mut(node_id);
        if meta.ownership_state.is_none() {
            meta.ownership_state = Some(crate::OwnershipState::Owned);
        }
    }
}

// ── Class hierarchy ────────────────────────────────────────────────────────────

/// Populate `Cpg::class_hierarchy` by walking ClassDef / TraitDef / ImplBlock nodes
/// and extracting declared supertypes from language-specific metadata and node text.
pub(crate) fn build_class_hierarchy(cpg: &mut Cpg) {
    // Collect (child_type_name, parent_type_names) pairs from AST nodes.
    let mut pairs: Vec<(String, Vec<String>)> = Vec::new();

    for (&node_id, node) in &cpg.ast {
        match node.kind {
            IrNodeKind::ClassDef => {
                let name = node.name.clone().or_else(|| node.text.clone());
                let name = match name { Some(n) => n, None => continue };
                let mut parents: Vec<String> = Vec::new();

                // C++ / Java: base_classes field on IrNode
                if let Some(ref bases) = node.base_classes {
                    parents.extend(bases.iter().cloned());
                }
                // Java metadata: extends_type + implements_types
                if let Some(meta) = cpg.java_metadata.get(&node_id) {
                    if let Some(ref ext) = meta.extends_type {
                        parents.push(ext.clone());
                    }
                    parents.extend(meta.implements_types.iter().cloned());
                }
                if !parents.is_empty() {
                    pairs.push((name, parents));
                }
            }
            IrNodeKind::ImplBlock => {
                // Rust impl blocks: `impl TraitName for TypeName`
                let self_type = cpg.rust_metadata.get(&node_id).and_then(|m| m.self_type.clone());
                let trait_type = cpg.rust_metadata.get(&node_id).and_then(|m| m.trait_type.clone());
                if let (Some(self_t), Some(trait_t)) = (self_type, trait_type) {
                    pairs.push((self_t, vec![trait_t]));
                }
            }
            _ => {}
        }
    }

    for (child, parents) in pairs {
        cpg.workspace.class_hierarchy.entry(child).or_default().extend(parents);
    }
}

// ── Class hierarchy (rewritten to avoid ptr::eq anti-pattern) ─────────────────

/// Populate `Cpg::class_hierarchy` — clears the above and uses ID-based lookup.
/// Runs after the first `build_class_hierarchy` call above to add Rust ImplBlock data.
pub(crate) fn build_class_hierarchy_rust(cpg: &mut Cpg) {
    let impl_ids: Vec<NodeId> = cpg.ast.iter()
        .filter(|(_, n)| n.kind == IrNodeKind::ImplBlock)
        .map(|(id, _)| *id)
        .collect();
    for id in impl_ids {
        let self_type = cpg.rust_metadata.get(&id).and_then(|m| m.self_type.clone());
        let trait_type = cpg.rust_metadata.get(&id).and_then(|m| m.trait_type.clone());
        if let (Some(self_t), Some(trait_t)) = (self_type, trait_type) {
            cpg.workspace.class_hierarchy.entry(self_t).or_default().push(trait_t);
        }
    }

    // Java: walk ClassDef nodes using Java metadata for extends/implements
    let class_ids: Vec<NodeId> = cpg.ast.iter()
        .filter(|(_, n)| n.kind == IrNodeKind::ClassDef)
        .map(|(id, _)| *id)
        .collect();
    for id in class_ids {
        let name = cpg.ast.get(&id).and_then(|n| n.name.clone());
        let name = match name { Some(n) => n, None => continue };
        let mut parents = Vec::new();
        // C++: base_classes in IrNode
        if let Some(bases) = cpg.ast.get(&id).and_then(|n| n.base_classes.clone()) {
            parents.extend(bases);
        }
        // Java metadata
        if let Some(meta) = cpg.java_metadata.get(&id) {
            if let Some(ref ext) = meta.extends_type {
                parents.push(ext.clone());
            }
            parents.extend(meta.implements_types.iter().cloned());
        }
        if !parents.is_empty() {
            cpg.workspace.class_hierarchy.entry(name).or_default().extend(parents);
        }
    }
}
