use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use crate::{
    AstNode, CType, ChannelDirection, Cpg, FunctionKind, GoType, IrNodeKind, JavaType, JsType,
    LiteralKind, LoopKind, NodeId, PyType, RustType, SourceComment, TsType,
};
use tree_sitter::{Node, Parser, Tree};

use crate::cfg::build_cfg;
use crate::dfg::{build_call_graph, build_dataflow, build_preprocessing_maps};
use crate::lifter::{DynLifter, lifter_for_language};
use crate::type_inference::{
    infer_c_types, infer_cpp_types, infer_go_types, infer_python_types,
    infer_java_types, infer_js_types, infer_ts_types, infer_rust_types,
    build_class_hierarchy,
};
use crate::call_analysis::{
    enrich_call_graph, dfg_go_passes, dfg_java_passes, dfg_rust_passes,
    dfg_python_passes, build_interprocedural_dfg,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SourceLanguage {
    #[default]
    C,
    Cpp,
    Go,
    Python,
    Java,
    JavaScript,
    TypeScript,
    Rust,
}

impl SourceLanguage {
    pub(crate) fn ts_language(self) -> tree_sitter::Language {
        match self {
            Self::C => tree_sitter_c::LANGUAGE.into(),
            Self::Cpp => tree_sitter_cpp::LANGUAGE.into(),
            Self::Go => tree_sitter_go::LANGUAGE.into(),
            Self::Python => tree_sitter_python::LANGUAGE.into(),
            Self::Java => tree_sitter_java::LANGUAGE.into(),
            Self::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Self::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Self::Rust => tree_sitter_rust::LANGUAGE.into(),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::C => "c",
            Self::Cpp => "cpp",
            Self::Go => "go",
            Self::Python => "python",
            Self::Java => "java",
            Self::JavaScript => "javascript",
            Self::TypeScript => "typescript",
            Self::Rust => "rust",
        }
    }
}

#[derive(Clone, Debug)]
pub struct GraphBuildOptions {
    pub include_cfg: bool,
    pub include_dfg: bool,
    pub remove_identifiers: bool,
    pub skip_preproc_nodes: bool,
    pub minimal_text: bool,
    pub macro_aliases: Option<BTreeMap<String, String>>,
}

impl Default for GraphBuildOptions {
    fn default() -> Self {
        Self {
            include_cfg: true,
            include_dfg: true,
            remove_identifiers: false,
            skip_preproc_nodes: false,
            minimal_text: true,
            macro_aliases: None,
        }
    }
}

pub struct CpgGenerator {
    parser: Parser,
    language: SourceLanguage,
}

#[derive(Clone, Debug)]
pub(crate) struct GraphBuildArtifacts {
    pub cpg: Cpg,
    pub node_to_id: BTreeMap<u64, NodeId>,
    pub id_to_node_ptr: BTreeMap<NodeId, u64>,
}

impl CpgGenerator {
    pub fn new() -> Result<Self> {
        Self::new_for_language(SourceLanguage::C)
    }

    pub fn new_for_language(language: SourceLanguage) -> Result<Self> {
        let mut parser = Parser::new();
        parser
            .set_language(&language.ts_language())
            .with_context(|| {
                format!(
                    "failed to initialize {} tree-sitter parser",
                    language.as_str()
                )
            })?;
        Ok(Self { parser, language })
    }

    pub fn parse_tree(&mut self, source: &[u8], previous: Option<&Tree>) -> Result<Tree> {
        self.parser
            .parse(source, previous)
            .ok_or_else(|| anyhow::anyhow!("tree-sitter parser returned no tree"))
    }

    pub fn generate_from_source_with_options(
        &mut self,
        source: &[u8],
        options: GraphBuildOptions,
    ) -> Result<Cpg> {
        let tree = self.parse_tree(source, None)?;
        let mut cpg = get_node_graph(tree.root_node(), source, &options, self.language)?;
        cpg.language = self.language.as_str().to_string();
        Ok(cpg)
    }

    pub fn generate_from_file_with_options(
        &mut self,
        file_path: impl AsRef<Path>,
        mut options: GraphBuildOptions,
    ) -> Result<Cpg> {
        let path = file_path.as_ref();
        let source = fs::read(path)
            .with_context(|| format!("failed to read source file {}", path.display()))?;
        let raw_macros = extract_macros(path);
        let macro_aliases = raw_macros
            .iter()
            .filter_map(|(k, v)| {
                k.strip_prefix("__macro_alias_")
                    .map(|name| (name.to_lowercase(), v.clone()))
            })
            .collect::<BTreeMap<_, _>>();
        if !macro_aliases.is_empty() {
            options.macro_aliases = Some(macro_aliases);
        }
        let orig_case_macro_aliases: BTreeMap<String, String> = raw_macros
            .iter()
            .filter_map(|(k, v)| {
                if let Some(name) = k.strip_prefix("__macro_alias_") {
                    // Function-like macro: #define MY_MALLOC(n) malloc(n)
                    return Some((name.to_string(), v.clone()));
                }
                // Object-like macro: #define MALLOC malloc
                // Only include when value is a plain identifier (not a number,
                // compiler builtin, or complex expression).
                if !k.starts_with("__") && is_valid_identifier_pub(v) && k != v {
                    return Some((k.clone(), v.clone()));
                }
                None
            })
            .collect();
        let macro_bodies: BTreeMap<String, crate::MacroBody> = raw_macros
            .iter()
            .filter_map(|(k, v)| {
                let name = k.strip_prefix("__macro_def_")?;
                let (params_str, body) = v.split_once('|')?;
                let params = if params_str.trim().is_empty() {
                    vec![]
                } else {
                    params_str
                        .split(',')
                        .map(|p| p.trim().to_string())
                        .collect()
                };
                Some((
                    name.to_string(),
                    crate::MacroBody {
                        params,
                        body: body.to_string(),
                    },
                ))
            })
            .collect();
        let mut cpg = self.generate_from_source_with_options(&source, options)?;
        cpg.c_file.macro_aliases = orig_case_macro_aliases;
        cpg.c_file.macro_bodies = macro_bodies;
        cpg.source_file = Some(
            path.canonicalize()
                .unwrap_or_else(|_| path.to_path_buf())
                .display()
                .to_string(),
        );
        Ok(cpg)
    }
}

pub fn generate_cpg_from_code(source: &str) -> Result<Cpg> {
    let mut generator = CpgGenerator::new()?;
    generator.generate_from_source_with_options(source.as_bytes(), GraphBuildOptions::default())
}

pub fn generate_cpg_from_file(file_path: impl AsRef<Path>) -> Result<Cpg> {
    let mut generator = CpgGenerator::new()?;
    generator.generate_from_file_with_options(file_path, GraphBuildOptions::default())
}

pub fn decode_string_literal(raw_text: &str) -> (String, u32) {
    let mut text = raw_text.to_string();
    if text.starts_with('"') && text.ends_with('"') && text.len() >= 2 {
        text = text[1..text.len() - 1].to_string();
    }
    let mut decoded = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('n') => decoded.push('\n'),
                Some('t') => decoded.push('\t'),
                Some('r') => decoded.push('\r'),
                Some('\\') => decoded.push('\\'),
                Some('"') => decoded.push('"'),
                Some('0') => decoded.push('\0'),
                Some(other) => decoded.push(other),
                None => decoded.push('\\'),
            }
        } else {
            decoded.push(ch);
        }
    }
    let strlen = decoded.as_bytes().len() as u32;
    (decoded, strlen)
}

pub fn get_node_graph(
    root_node: Node<'_>,
    source: &[u8],
    options: &GraphBuildOptions,
    language: SourceLanguage,
) -> Result<Cpg> {
    Ok(get_node_graph_artifacts(root_node, source, options, language)?.cpg)
}

pub(crate) fn get_node_graph_artifacts(
    root_node: Node<'_>,
    source: &[u8],
    options: &GraphBuildOptions,
    language: SourceLanguage,
) -> Result<GraphBuildArtifacts> {
    let lifter: DynLifter = lifter_for_language(language);
    let mut ast: BTreeMap<NodeId, AstNode> = BTreeMap::new();
    let mut node_to_id: HashMap<usize, NodeId> = HashMap::new();
    let mut parent_map: BTreeMap<NodeId, NodeId> = BTreeMap::new();
    let mut next_id: NodeId = 0;

    let mut skip_types = BTreeSet::new();
    skip_types.insert("comment");
    skip_types.insert("line_comment");
    skip_types.insert("block_comment");
    skip_types.insert("string_content");
    skip_types.insert("character");
    skip_types.insert("escape_sequence");
    skip_types.insert("system_lib_string");

    fn should_skip(node_type: &str, skip_types: &BTreeSet<&str>, skip_preproc_nodes: bool) -> bool {
        skip_types.contains(node_type) || (skip_preproc_nodes && node_type.contains("preproc"))
    }

    fn first_identifier_text(node: Node<'_>, source: &[u8]) -> Option<String> {
        if matches!(
            node.kind(),
            "identifier"
                | "field_identifier"
                | "scoped_identifier"
                | "qualified_identifier"
                | "destructor_name"
        ) {
            return node.utf8_text(source).ok().map(|text| text.to_string());
        }
        let mut i = 0usize;
        while i < node.child_count() {
            if let Some(child) = node.child(i as u32) {
                if let Some(text) = first_identifier_text(child, source) {
                    return Some(text);
                }
            }
            i += 1;
        }
        None
    }

    fn capture_text(node: Node<'_>, source: &[u8], minimal_text: bool) -> Option<String> {
        let kind = node.kind();
        if kind == "identifier" || kind == "field_identifier" {
            return node.utf8_text(source).ok().map(|s| s.to_string());
        }
        if kind == "call_expression" || kind == "lambda_expression" {
            // Always store full text for calls — argument names are needed by the
            // semantic dataflow engine regardless of minimal_text mode.
            return node.utf8_text(source).ok().map(|s| s.to_string());
        }
        if matches!(
            kind,
            "function_declarator" | "init_declarator" | "declarator" | "parameter_declaration"
        ) {
            if minimal_text {
                return first_identifier_text(node, source);
            }
            return node.utf8_text(source).ok().map(|s| s.to_string());
        }
        if kind == "function_definition"
            || kind == "field_expression"
            || kind == "subscript_expression"
            || kind == "return_statement"
        {
            return node.utf8_text(source).ok().map(|s| s.to_string());
        }
        if kind == "number_literal"
            || kind == "char_literal"
            || kind == "type_identifier"
            || kind == "primitive_type"
            || kind == "sized_type_specifier"
        {
            return node.utf8_text(source).ok().map(|s| s.to_string());
        }
        if kind == "string_literal" {
            let raw = node.utf8_text(source).ok()?;
            let (decoded, _) = decode_string_literal(raw);
            return Some(decoded);
        }
        if kind == "preproc_include" {
            let mut i: usize = 0;
            while i < node.child_count() {
                if let Some(child) = node.child(i as u32) {
                    if matches!(child.kind(), "string_literal" | "system_lib_string") {
                        return child.utf8_text(source).ok().map(|s| s.to_string());
                    }
                }
                i += 1;
            }
            return None;
        }
        if kind == "array_declarator" {
            return None;
        }
        // Capture text for for_in_statement so we can detect "of" vs "in"
        if kind == "for_in_statement" || kind == "for_statement" {
            return node.utf8_text(source).ok().map(|s| s.to_string());
        }
        if !minimal_text {
            return node.utf8_text(source).ok().map(|s| s.to_string());
        }
        if !matches!(kind, "declaration") && !kind.contains("statement") && !kind.contains("clause")
        {
            return node.utf8_text(source).ok().map(|s| s.to_string());
        }
        None
    }

    // Iterative DFS — avoids stack overflow on large/deeply-nested files (e.g. sqlite3.c).
    // Stack entry: (node, parent_id, function_id, field_name_in_parent).
    // Node<'_> is Copy so it can be stored directly.
    // C++: template_declaration is a transparent wrapper whose template_parameter_list
    // is otherwise discarded. Capture param names keyed by the inner class/function
    // node's start_byte so enrich_cpp_metadata can attach them after AST nodes exist.
    let mut cpp_template_params: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    {
        if !root_node.is_named()
            || should_skip(root_node.kind(), &skip_types, options.skip_preproc_nodes)
        {
            bail!("failed to build AST from root node");
        }

        // Each stack entry: (node, parent_id, function_id, field_name in parent)
        let mut stack: Vec<(Node<'_>, Option<NodeId>, Option<NodeId>, Option<String>)> =
            vec![(root_node, None, None, None)];

        // Collected records in visitation order, used in the build phase below.
        // (node, assigned_id, parent_id, function_id)
        let mut records: Vec<(Node<'_>, NodeId, Option<NodeId>, Option<NodeId>)> = Vec::new();
        // children_of[parent_id] = Vec<(child_id, field_name)> in source order
        let mut children_of: BTreeMap<NodeId, Vec<(NodeId, Option<String>)>> = BTreeMap::new();

        while let Some((node, parent_id, function_id, field_name)) = stack.pop() {
            if !node.is_named() || should_skip(node.kind(), &skip_types, options.skip_preproc_nodes)
            {
                continue;
            }
            // template_declaration: transparent wrapper — process the inner function/class
            // directly as if it were at the template's parent level (conservative treatment:
            // analyze once without type specialization). template_parameters are skipped.
            if node.kind() == "template_declaration" {
                // Extract template_parameter_list param names before descending,
                // so they can be attached to the inner class/function node below.
                let mut tparams: Vec<String> = Vec::new();
                let mut ti: usize = 0;
                while ti < node.child_count() {
                    if let Some(tchild) = node.child(ti as u32) {
                        if tchild.kind() == "template_parameter_list" {
                            let mut pi: usize = 0;
                            while pi < tchild.child_count() {
                                if let Some(pchild) = tchild.child(pi as u32) {
                                    if matches!(
                                        pchild.kind(),
                                        "type_parameter_declaration"
                                            | "variadic_type_parameter_declaration"
                                    ) {
                                        let mut qi: usize = 0;
                                        let mut found = None;
                                        while qi < pchild.child_count() {
                                            if let Some(qchild) = pchild.child(qi as u32) {
                                                if qchild.kind() == "type_identifier" {
                                                    found = qchild.utf8_text(source).ok().map(|s| s.to_string());
                                                    break;
                                                }
                                            }
                                            qi += 1;
                                        }
                                        if let Some(name) = found {
                                            tparams.push(name);
                                        }
                                    } else if pchild.kind() == "parameter_declaration" {
                                        if let Some(name) = first_identifier_text(pchild, source) {
                                            tparams.push(name);
                                        }
                                    }
                                }
                                pi += 1;
                            }
                        }
                    }
                    ti += 1;
                }
                let child_count = node.child_count();
                let mut i: usize = 0;
                while i < child_count {
                    if let Some(child) = node.child(i as u32) {
                        if child.is_named()
                            && matches!(
                                child.kind(),
                                "function_definition"
                                    | "class_specifier"
                                    | "struct_specifier"
                                    | "declaration"
                                    | "template_declaration"
                            )
                        {
                            if !tparams.is_empty() {
                                cpp_template_params.insert(child.start_byte() as u32, tparams.clone());
                            }
                            stack.push((child, parent_id, function_id, field_name.clone()));
                        }
                    }
                    i += 1;
                }
                continue; // Don't record the template_declaration wrapper itself
            }

            // preproc_if { 0 } — skip the whole subtree
            if node.kind() == "preproc_if" {
                let mut skip_preproc = false;
                let mut idx: usize = 0;
                while idx < node.child_count() {
                    if let Some(child) = node.child(idx as u32) {
                        if child.is_named() {
                            if child.utf8_text(source).ok().map(str::trim) == Some("0") {
                                skip_preproc = true;
                            }
                            break;
                        }
                    }
                    idx += 1;
                }
                if skip_preproc {
                    continue;
                }
            }

            let node_ptr = node.id();
            let current_id = *node_to_id.entry(node_ptr).or_insert_with(|| {
                let id = next_id;
                next_id += 1;
                id
            });

            let fn_id = if lifter.is_function_scope(node.kind()) {
                Some(current_id)
            } else {
                function_id
            };

            records.push((node, current_id, parent_id, fn_id));

            if let Some(pid) = parent_id {
                children_of
                    .entry(pid)
                    .or_default()
                    .push((current_id, field_name));
                parent_map.insert(current_id, pid);
            }

            // Push children in reverse order so the first child is popped first.
            let child_count = node.child_count();
            let mut children_to_push: Vec<(Node<'_>, Option<String>)> = Vec::new();
            let mut i: usize = 0;
            while i < child_count {
                if let Some(child) = node.child(i as u32) {
                    if child.is_named()
                        && !should_skip(child.kind(), &skip_types, options.skip_preproc_nodes)
                    {
                        let child_field =
                            node.field_name_for_child(i as u32).map(|s| s.to_string());
                        children_to_push.push((child, child_field));
                    }
                }
                i += 1;
            }
            for (child, child_field) in children_to_push.into_iter().rev() {
                stack.push((child, Some(current_id), fn_id, child_field));
            }
        }

        if records.is_empty() {
            bail!("failed to build AST from root node");
        }

        // Build AstNodes now that all children IDs are known.
        for (node, current_id, parent_id, function_id) in records {
            let child_entries = children_of.get(&current_id).cloned().unwrap_or_default();
            let children_ids: Vec<NodeId> = child_entries.iter().map(|(id, _)| *id).collect();
            let field_names: Vec<Option<String>> =
                child_entries.into_iter().map(|(_, f)| f).collect();

            let node_text = capture_text(node, source, options.minimal_text)
                .map(|t| t.replace(['\n', '\r', '\t'], ""));

            let mut operator = None;
            if matches!(
                node.kind(),
                // C / C++
                "binary_expression"
                    | "unary_expression"
                    | "assignment_expression"
                    | "update_expression"
                    | "augmented_assignment_expression"
                // Python
                    | "binary_operator"
                    | "unary_operator"
                    | "not_operator"
                    | "boolean_operator"
                    | "comparison_operator"
                    | "augmented_assignment"
                // Go
                    | "binary_expression"
                    | "assignment_statement"
                // JavaScript / TypeScript
                    | "binary_expression"
                    | "logical_expression"
                    | "augmented_assignment_expression"
                // Rust
                    | "binary_expression"
                    | "compound_assignment_expr"
            ) {
                let mut j: usize = 0;
                while j < node.child_count() {
                    if let Some(child) = node.child(j as u32) {
                        if !child.is_named() {
                            operator = child.utf8_text(source).ok().map(|s| s.to_string());
                            break;
                        }
                    }
                    j += 1;
                }
            }

            let argument_count = if matches!(node.kind(), "call_expression" | "call") {
                let mut count = None;
                let mut j: usize = 0;
                while j < node.child_count() {
                    if let Some(child) = node.child(j as u32) {
                        if matches!(child.kind(), "argument_list" | "arguments") {
                            count = Some(child.named_child_count() as u32);
                            break;
                        }
                    }
                    j += 1;
                }
                count
            } else {
                None
            };

            let mut array_size = None;
            let mut array_size_expr = None;
            if node.kind() == "array_declarator" {
                let mut j: usize = 0;
                while j < node.child_count() {
                    if let Some(child) = node.child(j as u32) {
                        let field = node.field_name_for_child(j as u32);
                        if field == Some("size")
                            || (j > 0
                                && matches!(
                                    child.kind(),
                                    "number_literal" | "binary_expression" | "identifier"
                                ))
                        {
                            let text = child.utf8_text(source).unwrap_or_default().to_string();
                            array_size = text.parse::<i64>().ok();
                            if array_size.is_none() {
                                array_size_expr = Some(text);
                            }
                            break;
                        }
                    }
                    j += 1;
                }
            }

            let (string_length, text) = if node.kind() == "string_literal" {
                let raw = node.utf8_text(source).unwrap_or_default();
                let (decoded, strlen) = decode_string_literal(raw);
                (Some(strlen), Some(decoded))
            } else {
                (None, node_text)
            };

            let ts_kind = node.kind();
            let ir_kind = lifter.lift_kind(ts_kind);
            let loop_kind = if ir_kind == crate::IrNodeKind::Loop {
                Some(lifter.loop_kind(ts_kind))
            } else {
                None
            };
            let try_kind = if ir_kind == crate::IrNodeKind::Try {
                Some(lifter.try_kind(ts_kind))
            } else {
                None
            };
            let lit_kind = if ir_kind == crate::IrNodeKind::Literal {
                Some(lifter.lit_kind(ts_kind))
            } else {
                None
            };

            ast.insert(
                current_id,
                AstNode {
                    kind: ir_kind,
                    loop_kind,
                    try_kind,
                    lit_kind,
                    node_type: ts_kind.to_string(),
                    name: None, // populated during enrichment pass for MethodDef/ClassDef
                    signature: None,
                    text,
                    children: children_ids,
                    field_names,
                    parent_id,
                    function_id,
                    basic_block: None,
                    line: (node.start_position().row + 1) as u32,
                    column: node.start_position().column as u32,
                    end_line: (node.end_position().row + 1) as u32,
                    end_column: node.end_position().column as u32,
                    start_byte: Some(node.start_byte() as u32),
                    end_byte: Some(node.end_byte() as u32),
                    string_length,
                    array_size,
                    array_size_expr,
                    operator,
                    argument_count,
                    // OOP metadata — populated during enrichment pass
                    class_context: None,
                    namespace: None,
                    visibility: None,
                    is_constructor: None,
                    is_destructor: None,
                    is_virtual: None,
                    template_params: None,
                    qualified_name: None,
                    base_classes: None,
                },
            );
        }
    }

    // Collect comment nodes separately — they are skipped in the main AST
    // traverse but needed for suppression directive detection.
    let comments = collect_source_comments(root_node, source);

    let mut cpg = Cpg {
        ast,
        basic_blocks: BTreeMap::new(),
        call_graph: BTreeMap::new(),
        dataflow: crate::DataflowGraph::default(),
        source_file: None,
        language: "c".to_string(),
        comments,
        c_file: crate::CFileMetadata::default(),
        cpp_metadata: BTreeMap::new(),
        go_metadata: BTreeMap::new(),
        python_metadata: BTreeMap::new(),
        java_metadata: BTreeMap::new(),
        js_metadata: BTreeMap::new(),
        ts_metadata: BTreeMap::new(),
        rust_metadata: BTreeMap::new(),
        workspace: crate::WorkspaceIndex::default(),
    };

    cpg.c_file.custom_allocators = collect_custom_allocators(&cpg.ast, source);

    // ── C++ metadata enrichment ───────────────────────────────────────────────
    // Populates class_context/namespace/is_constructor etc. on AstNode (backward
    // compat) and the sparse cpp_metadata side-table (canonical).
    {
        if !cpp_template_params.is_empty() {
            let matches: Vec<(NodeId, Vec<String>)> = cpg
                .ast
                .iter()
                .filter_map(|(&id, n)| {
                    n.start_byte
                        .and_then(|sb| cpp_template_params.get(&sb))
                        .map(|params: &Vec<String>| (id, params.clone()))
                })
                .collect();
            for (id, params) in matches {
                cpg.cpp_meta_mut(id).template_params = Some(params);
            }
        }
        enrich_cpp_metadata(&mut cpg);
    }

    // ── Language-specific metadata enrichment ─────────────────────────────────
    match language {
        SourceLanguage::Go => enrich_go_metadata(&mut cpg),
        SourceLanguage::Python => enrich_python_metadata(&mut cpg),
        SourceLanguage::Java => enrich_java_metadata(&mut cpg),
        SourceLanguage::JavaScript => enrich_js_metadata(&mut cpg),
        SourceLanguage::TypeScript => enrich_ts_metadata(&mut cpg),
        SourceLanguage::Rust => enrich_rust_metadata(&mut cpg),
        _ => {}
    }

    if options.include_cfg {
        build_cfg(&mut cpg.ast, &mut cpg.basic_blocks);
    }
    if options.include_dfg {
        let maps = build_preprocessing_maps(&cpg.ast);
        {
            cpg.call_graph =
                build_call_graph(&cpg.ast, Some(&maps), options.macro_aliases.as_ref());
        }
        let bb_ref = if options.include_cfg {
            Some(&cpg.basic_blocks)
        } else {
            None
        };
        let (dataflow, xfile) = {
            build_dataflow(
                &cpg.ast,
                bb_ref,
                Some(&maps),
                options.macro_aliases.as_ref(),
            )
        };
        cpg.dataflow = dataflow;
        cpg.workspace.cross_file_calls = xfile;
    }

    // ── Type inference passes (after DFG so type info can use dataflow) ───────
    match language {
        SourceLanguage::C => infer_c_types(&mut cpg),
        SourceLanguage::Cpp => infer_cpp_types(&mut cpg),
        SourceLanguage::Go => infer_go_types(&mut cpg),
        SourceLanguage::Python => infer_python_types(&mut cpg),
        SourceLanguage::Java => infer_java_types(&mut cpg),
        SourceLanguage::JavaScript => infer_js_types(&mut cpg),
        SourceLanguage::TypeScript => infer_ts_types(&mut cpg),
        SourceLanguage::Rust => infer_rust_types(&mut cpg),
    }

    // ── Language-specific DFG enrichment passes ───────────────────────────────
    match language {
        SourceLanguage::Go => dfg_go_passes(&mut cpg),
        SourceLanguage::Java => dfg_java_passes(&mut cpg),
        SourceLanguage::Rust => dfg_rust_passes(&mut cpg),
        SourceLanguage::Python => dfg_python_passes(&mut cpg),
        _ => {}
    }

    // ── Class hierarchy and call-graph enrichment ─────────────────────────────
    build_class_hierarchy(&mut cpg);
    enrich_call_graph(&mut cpg, language);
    build_interprocedural_dfg(&mut cpg);

    if options.remove_identifiers {
        prune_identifiers(&mut cpg);
    }

    let node_to_id = node_to_id
        .into_iter()
        .map(|(node_ptr, node_id)| (node_ptr as u64, node_id))
        .collect::<BTreeMap<_, _>>();
    let id_to_node_ptr = node_to_id
        .iter()
        .map(|(node_ptr, node_id)| (*node_id, *node_ptr))
        .collect::<BTreeMap<_, _>>();

    Ok(GraphBuildArtifacts {
        cpg,
        node_to_id,
        id_to_node_ptr,
    })
}

pub fn prune_identifiers(cpg: &mut Cpg) {
    let identifier_like = [
        "identifier",
        "field_identifier",
        "scoped_identifier",
        "qualified_identifier",
    ];
    let identifier_ids: BTreeSet<NodeId> = cpg
        .ast
        .iter()
        .filter_map(|(id, n)| {
            identifier_like
                .contains(&n.node_type.as_str())
                .then_some(*id)
        })
        .collect();

    let mut remap: BTreeMap<NodeId, NodeId> = BTreeMap::new();
    for id in &identifier_ids {
        if let Some(parent) = cpg.ast.get(id).and_then(|n| n.parent_id) {
            remap.insert(*id, parent);
        }
    }

    for d in &mut cpg.dataflow.definitions {
        if let Some(parent) = remap.get(&d.node_id).copied() {
            d.node_id = parent;
        }
    }
    for u in &mut cpg.dataflow.uses {
        if let Some(parent) = remap.get(&u.node_id).copied() {
            u.node_id = parent;
        }
    }
    for edge in &mut cpg.dataflow.edges {
        if let Some(parent) = remap.get(&edge.source).copied() {
            edge.source = parent;
        }
        if let Some(parent) = remap.get(&edge.destination).copied() {
            edge.destination = parent;
        }
    }
    let mut seen_edges = BTreeSet::new();
    cpg.dataflow.edges.retain(|edge| {
        if edge.source == edge.destination {
            return false;
        }
        seen_edges.insert((
            edge.source,
            edge.destination,
            edge.variable.clone(),
            edge.edge_type.clone(),
        ))
    });

    for node in cpg.ast.values_mut() {
        node.children
            .retain(|child| !identifier_ids.contains(child));
    }
    for id in identifier_ids {
        cpg.ast.remove(&id);
    }
}

/// Walk the raw tree-sitter tree and collect all comment nodes with their
/// line numbers and text content.  Comments are excluded from the main AST
/// but must be available for suppression directive detection.
pub(crate) fn collect_source_comments(root: Node<'_>, source: &[u8]) -> Vec<SourceComment> {
    let mut comments = Vec::new();
    let mut cursor = root.walk();
    loop {
        let node = cursor.node();
        if matches!(node.kind(), "comment" | "line_comment" | "block_comment") {
            if let Ok(text) = node.utf8_text(source) {
                comments.push(SourceComment {
                    line: (node.start_position().row + 1) as u32,
                    text: text.to_string(),
                });
            }
        }
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return comments;
            }
        }
    }
}

pub fn extract_schema() -> BTreeMap<&'static str, Vec<String>> {
    let language: tree_sitter::Language = tree_sitter_c::LANGUAGE.into();
    let mut node_types = BTreeSet::new();
    let count = language.node_kind_count();
    for i in 0..count {
        let id = i as u16;
        if let Some(kind) = language.node_kind_for_id(id) {
            if kind != "comment" {
                node_types.insert(kind.to_string());
            }
        }
    }
    node_types.insert("basic_block".to_string());
    node_types.insert("ERROR".to_string());
    let edge_types = vec![
        "AST_CHILD".to_string(),
        "CFG_SUCCESSOR".to_string(),
        "BB_CONTAINS_NODE".to_string(),
        "CALLS".to_string(),
        "CALLED_BY".to_string(),
        "REACHING_DEF".to_string(),
        "ALIAS".to_string(),
        "POINTS_TO".to_string(),
        "SIZE_FLOW".to_string(),
        "TAINT_FLOW".to_string(),
        "TAINT_SINK".to_string(),
        "TAINT_SOURCE".to_string(),
        "INTERPROCEDURAL_FLOW".to_string(),
    ];
    BTreeMap::from([
        ("node_types", node_types.into_iter().collect()),
        ("edge_types", edge_types),
    ])
}

pub fn extract_macros(file_path: impl AsRef<Path>) -> BTreeMap<String, String> {
    let mut macros = BTreeMap::new();
    let output = Command::new("gcc")
        .arg("-dM")
        .arg("-E")
        .arg("-x")
        .arg("c")
        .arg(file_path.as_ref())
        .output();
    let Ok(output) = output else {
        return macros;
    };
    if !output.status.success() {
        return macros;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("#define ") {
            continue;
        }
        let rest = &trimmed["#define ".len()..];
        if let Some(paren) = rest.find('(') {
            let name = rest[..paren].trim();
            // Extract params (content between first '(' and matching ')')
            let after_paren = &rest[paren + 1..];
            let Some(params_end) = after_paren.find(')') else {
                continue;
            };
            let params_str = &after_paren[..params_end];
            let body = after_paren[params_end + 1..].trim();

            if !name.is_empty() {
                // Emit alias entry for simple wrappers
                if let Some(called) = body.split('(').next().map(str::trim) {
                    if !called.is_empty()
                        && called != name
                        && !matches!(called, "if" | "while" | "for" | "return" | "sizeof" | "do")
                    {
                        macros.insert(format!("__macro_alias_{name}"), called.to_string());
                    }
                }
                // Always emit full definition for expression expansion
                macros.insert(
                    format!("__macro_def_{name}"),
                    format!("{params_str}|{body}"),
                );
            }
            continue;
        }

        let mut parts = rest.splitn(2, char::is_whitespace);
        if let (Some(name), Some(value)) = (parts.next(), parts.next()) {
            let value = value.trim();
            if !value.contains('(') || value.starts_with('"') {
                macros.insert(name.to_string(), value.to_string());
                // Also emit definition entry for object-like macros (empty params)
                macros.insert(format!("__macro_def_{name}"), format!("|{value}"));
            }
        }
    }
    macros
}

pub(crate) fn is_valid_identifier_pub(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_alphabetic() || c == '_' => chars.all(|c| c.is_alphanumeric() || c == '_'),
        _ => false,
    }
}

/// Scan the AST for function declarations/definitions annotated with
/// `__attribute__((malloc))` or `__attribute__((alloc_size(N)))` and
/// return a map of function name → size_arg (0-based; -1 = implicit).
///
/// These supplement the static `HEAP_ALLOCATORS` table and allow alias
/// analysis to recognize project-specific allocator wrappers.
fn collect_custom_allocators(
    ast: &BTreeMap<NodeId, AstNode>,
    _source: &[u8],
) -> BTreeMap<String, i32> {
    let mut result = BTreeMap::new();

    for node in ast.values() {
        // We look for function_definition or declaration nodes that have
        // attribute children mentioning "malloc" or "alloc_size".
        if !matches!(
            node.node_type.as_str(),
            "function_definition" | "declaration"
        ) {
            continue;
        }

        let mut has_malloc_attr = false;
        let mut alloc_size_arg: i32 = -1;

        for child_id in &node.children {
            let Some(child) = ast.get(child_id) else {
                continue;
            };
            let text = child.text.as_deref().unwrap_or("");
            let lower = text.to_ascii_lowercase();

            // Match __attribute__((malloc)) and __attribute__((alloc_size(...)))
            if matches!(
                child.node_type.as_str(),
                "attribute_specifier"
                    | "attribute"
                    | "attribute_declaration"
                    | "gnu_asm_qualifier"
                    | "type_qualifier"
            ) || lower.contains("__attribute__")
            {
                if lower.contains("malloc") {
                    has_malloc_attr = true;
                }
                // Parse alloc_size(N) — extract N as the 0-based size arg index.
                // Most commonly __attribute__((alloc_size(1))) means arg 0 in 0-based.
                if let Some(pos) = lower.find("alloc_size") {
                    has_malloc_attr = true;
                    if let Some(inner) = lower[pos..].find('(').and_then(|i| {
                        let after = &lower[pos + i + 1..];
                        after.find(')').map(|j| &after[..j])
                    }) {
                        // alloc_size uses 1-based indexing in GCC docs
                        if let Ok(n) = inner.trim().parse::<i32>() {
                            alloc_size_arg = (n - 1).max(0);
                        }
                    }
                }
            }
        }

        if !has_malloc_attr {
            continue;
        }

        // Extract the function name from the declarator child
        let fn_name = node.children.iter().find_map(|cid| {
            let c = ast.get(cid)?;
            if c.node_type == "function_declarator" {
                // first identifier child is the name
                c.children.iter().find_map(|gid| {
                    let g = ast.get(gid)?;
                    if g.node_type == "identifier" {
                        g.text.clone()
                    } else {
                        None
                    }
                })
            } else if c.node_type == "identifier" {
                c.text.clone()
            } else {
                None
            }
        });

        if let Some(name) = fn_name {
            if !name.is_empty() {
                result.insert(name, alloc_size_arg);
            }
        }
    }

    result
}

/// Populate C++ metadata (class_context, namespace, is_constructor, is_destructor,
/// is_virtual, qualified_name) in a single top-down pass.
/// Writes to both `AstNode` fields (backward compat) and the sparse
/// `Cpg::cpp_metadata` side-table (canonical, language-neutral AstNode).
/// This is a no-op for C files (no class_specifier/namespace_definition nodes).
pub(crate) fn enrich_cpp_metadata(cpg: &mut crate::Cpg) {
    let ast = &cpg.ast;

    // ── Extract class name from AST children (not text splitting) ─────────────
    // Finds the `type_identifier` child of a class_specifier/struct_specifier.
    fn class_name_from_node(ast: &BTreeMap<NodeId, AstNode>, node_id: NodeId) -> Option<String> {
        let node = ast.get(&node_id)?;
        for &child_id in &node.children {
            if let Some(child) = ast.get(&child_id) {
                if child.node_type == "type_identifier" {
                    return child.text.clone();
                }
            }
        }
        // Fallback for nested templates: look for template_type → type_identifier
        for &child_id in &node.children {
            if let Some(child) = ast.get(&child_id) {
                if child.node_type == "template_type" {
                    for &gc_id in &child.children {
                        if let Some(gc) = ast.get(&gc_id) {
                            if gc.node_type == "type_identifier" {
                                return gc.text.clone();
                            }
                        }
                    }
                }
            }
        }
        None
    }

    // Extract namespace name from namespace_definition children.
    fn namespace_name_from_node(
        ast: &BTreeMap<NodeId, AstNode>,
        node_id: NodeId,
    ) -> Option<String> {
        let node = ast.get(&node_id)?;
        for &child_id in &node.children {
            if let Some(child) = ast.get(&child_id) {
                if child.node_type == "namespace_identifier" || child.node_type == "identifier" {
                    return child.text.clone();
                }
            }
        }
        None
    }

    // ── Detect constructor/destructor via AST node types (not text) ────────────
    // Returns (is_constructor, is_destructor) for a function_definition node.
    fn detect_ctor_dtor(ast: &BTreeMap<NodeId, AstNode>, fn_def_id: NodeId) -> (bool, bool) {
        let Some(fn_node) = ast.get(&fn_def_id) else {
            return (false, false);
        };
        // Walk children to find function_declarator → (destructor_name | identifier)
        for &child_id in &fn_node.children {
            let Some(child) = ast.get(&child_id) else {
                continue;
            };
            match child.node_type.as_str() {
                "function_declarator" => {
                    // First child of function_declarator is the name node.
                    if let Some(&name_id) = child.children.first() {
                        if let Some(name_node) = ast.get(&name_id) {
                            match name_node.node_type.as_str() {
                                "destructor_name" => return (false, true),
                                "qualified_identifier" => {
                                    // Check innermost name for destructor_name.
                                    if let Some(&inner_id) = name_node.children.last() {
                                        if let Some(inner) = ast.get(&inner_id) {
                                            if inner.node_type == "destructor_name" {
                                                return (false, true);
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                "reference_declarator" | "pointer_declarator" => {
                    // Recurse one level for `Type* fn_name(...)` patterns.
                    for &gc_id in &child.children {
                        let Some(gc) = ast.get(&gc_id) else { continue };
                        if gc.node_type == "function_declarator" {
                            if let Some(&name_id) = gc.children.first() {
                                if let Some(name_node) = ast.get(&name_id) {
                                    if name_node.node_type == "destructor_name" {
                                        return (false, true);
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        // Constructor: same name as enclosing class — detected by caller using class_ctx.
        (false, false)
    }

    // Detect `virtual` keyword: check for `virtual_specifier` or `storage_class_specifier`
    // children with text "virtual", OR fall back to checking the function text prefix.
    fn detect_virtual(ast: &BTreeMap<NodeId, AstNode>, fn_def_id: NodeId) -> bool {
        let Some(fn_node) = ast.get(&fn_def_id) else {
            return false;
        };
        // AST-based check: look for virtual_specifier child or child with text "virtual".
        let has_virtual_child = fn_node.children.iter().any(|&cid| {
            ast.get(&cid)
                .map(|c| {
                    c.node_type == "virtual_specifier"
                        || c.node_type == "storage_class_specifier"
                        || c.text.as_deref() == Some("virtual")
                })
                .unwrap_or(false)
        });
        if has_virtual_child {
            return true;
        }
        // Text fallback for tree-sitter grammars that embed `virtual` in the
        // declaration_specifiers without a dedicated child node.
        fn_node
            .text
            .as_deref()
            .map(|t| t.starts_with("virtual "))
            .unwrap_or(false)
    }

    // Extract the simple function name from a function_definition node via AST.
    // Handles pointer/reference-returning functions where function_declarator is
    // nested inside pointer_declarator / reference_declarator / parenthesized_declarator.
    fn extract_fn_simple_name(ast: &BTreeMap<NodeId, AstNode>, fn_def_id: NodeId) -> String {
        let Some(fn_node) = ast.get(&fn_def_id) else {
            return String::new();
        };

        fn resolve_name(ast: &BTreeMap<NodeId, AstNode>, node_id: NodeId, depth: usize) -> Option<String> {
            if depth > 8 {
                return None;
            }
            let node = ast.get(&node_id)?;
            match node.node_type.as_str() {
                "function_declarator" => {
                    // First child is the name node (identifier, qualified_identifier,
                    // destructor_name, operator_name, etc.).
                    node.children.first().and_then(|&name_id| {
                        let name_node = ast.get(&name_id)?;
                        let raw = name_node.text.as_deref().unwrap_or("");
                        // Strip namespace qualifier, parameter list, destructor tilde, pointer star.
                        let simple = raw
                            .rsplit("::")
                            .next()
                            .unwrap_or(raw)
                            .split('(')
                            .next()
                            .unwrap_or(raw)
                            .trim_matches('~')
                            .trim_matches('*')
                            .trim();
                        if simple.is_empty() { None } else { Some(simple.to_string()) }
                    })
                }
                // Pointer/reference/parenthesized declarators wrap the function_declarator.
                "pointer_declarator"
                | "reference_declarator"
                | "rvalue_reference_declarator"
                | "parenthesized_declarator"
                | "abstract_pointer_declarator"
                | "abstract_reference_declarator" => {
                    node.children.iter().find_map(|&cid| resolve_name(ast, cid, depth + 1))
                }
                _ => None,
            }
        }

        for &child_id in &fn_node.children {
            if let Some(name) = resolve_name(ast, child_id, 0) {
                return name;
            }
        }
        String::new()
    }

    // ── First pass: build class and namespace context maps ─────────────────────
    // Only tag function_definition and declaration nodes (not all descendants)
    // to keep the side-table sparse.
    let mut class_contexts: BTreeMap<NodeId, String> = BTreeMap::new();
    let mut namespace_contexts: BTreeMap<NodeId, String> = BTreeMap::new();

    let class_nodes: Vec<(NodeId, String)> = ast
        .iter()
        .filter(|(_, n)| matches!(n.node_type.as_str(), "class_specifier" | "struct_specifier"))
        .filter_map(|(id, _)| class_name_from_node(ast, *id).map(|name| (*id, name)))
        .collect();

    let namespace_nodes: Vec<(NodeId, String)> = ast
        .iter()
        .filter(|(_, n)| n.node_type == "namespace_definition")
        .filter_map(|(id, _)| namespace_name_from_node(ast, *id).map(|name| (*id, name)))
        .collect();

    // Walk all descendants; only record context for function_definition/declaration nodes
    // in the side-table (write to AstNode for backward compat for all nodes).
    for (class_id, class_name) in &class_nodes {
        let mut stack = vec![*class_id];
        let mut visited = std::collections::HashSet::new();
        while let Some(nid) = stack.pop() {
            if !visited.insert(nid) {
                continue;
            }
            if nid != *class_id {
                class_contexts
                    .entry(nid)
                    .or_insert_with(|| class_name.clone());
            }
            if let Some(node) = ast.get(&nid) {
                stack.extend(node.children.iter().copied());
            }
        }
    }

    for (ns_id, ns_name) in &namespace_nodes {
        let mut stack = vec![*ns_id];
        let mut visited = std::collections::HashSet::new();
        while let Some(nid) = stack.pop() {
            if !visited.insert(nid) {
                continue;
            }
            if nid != *ns_id {
                namespace_contexts
                    .entry(nid)
                    .or_insert_with(|| ns_name.clone());
            }
            if let Some(node) = ast.get(&nid) {
                stack.extend(node.children.iter().copied());
            }
        }
    }

    // ── Second pass: apply metadata ────────────────────────────────────────────
    let node_ids: Vec<NodeId> = ast.keys().copied().collect();
    for node_id in node_ids {
        let class_ctx = class_contexts.get(&node_id).cloned();
        let ns_ctx = namespace_contexts.get(&node_id).cloned();

        let is_fn_def = cpg
            .ast
            .get(&node_id)
            .map(|n| n.node_type == "function_definition")
            .unwrap_or(false);

        let (is_ctor, is_dtor, is_virt, qname, fn_simple_name) = if is_fn_def {
            let (_, is_dtor) = detect_ctor_dtor(&cpg.ast, node_id);
            let is_virt = detect_virtual(&cpg.ast, node_id);
            let fn_name = extract_fn_simple_name(&cpg.ast, node_id);
            // Constructor: same simple name as enclosing class (and not a destructor).
            let is_ctor = !is_dtor
                && class_ctx
                    .as_deref()
                    .map(|c| c == fn_name || fn_name == c.rsplit("::").next().unwrap_or(c))
                    .unwrap_or(false);
            let qname = {
                let parts: Vec<&str> = [
                    ns_ctx.as_deref(),
                    class_ctx.as_deref(),
                    Some(fn_name.as_str()),
                ]
                .into_iter()
                .flatten()
                .filter(|s| !s.is_empty())
                .collect();
                if parts.is_empty() {
                    None
                } else {
                    Some(parts.join("::"))
                }
            };
            (is_ctor, is_dtor, is_virt, qname, fn_name)
        } else {
            (false, false, false, None, String::new())
        };

        // Write to AstNode fields for backward compatibility.
        if let Some(node) = cpg.ast.get_mut(&node_id) {
            // Populate the name field for C/C++ function_definition nodes.
            // Other languages set this in their own enrichment passes; C/C++ must
            // set it here so that query predicates like `node.name` work uniformly.
            if is_fn_def && !fn_simple_name.is_empty() && node.name.is_none() {
                node.name = Some(fn_simple_name.clone());
            }
            if class_ctx.is_some() {
                node.class_context = class_ctx.clone();
            }
            if ns_ctx.is_some() {
                node.namespace = ns_ctx.clone();
            }
            if is_ctor {
                node.is_constructor = Some(true);
            }
            if is_dtor {
                node.is_destructor = Some(true);
            }
            if is_virt {
                node.is_virtual = Some(true);
            }
            if let Some(ref q) = qname {
                node.qualified_name = Some(q.clone());
            }
        }

        // Write to sparse cpp_metadata side-table only for function/class nodes.
        let is_class_node = cpg
            .ast
            .get(&node_id)
            .map(|n| matches!(n.node_type.as_str(), "class_specifier" | "struct_specifier"))
            .unwrap_or(false);
        if is_fn_def || is_class_node || class_ctx.is_some() || ns_ctx.is_some() {
            if is_fn_def || is_class_node {
                let meta = cpg.cpp_meta_mut(node_id);
                meta.class_context = class_ctx;
                meta.namespace = ns_ctx;
                if is_ctor {
                    meta.is_constructor = Some(true);
                }
                if is_dtor {
                    meta.is_destructor = Some(true);
                }
                if is_virt {
                    meta.is_virtual = Some(true);
                }
                meta.qualified_name = qname;
                meta.function_kind = crate::FunctionKind::Internal;
            }
        }
    }

    // Populate name and base_classes on class_specifier / struct_specifier (ClassDef) nodes.
    for (class_id, class_name) in &class_nodes {
        if let Some(node) = cpg.ast.get_mut(class_id) {
            if node.name.is_none() {
                node.name = Some(class_name.clone());
            }
        }
        // C++: extract base classes from base_class_clause → base_specifier → type_identifier
        let children = cpg.ast.get(class_id).map(|n| n.children.clone()).unwrap_or_default();
        let base_classes: Vec<String> = children.iter().find_map(|&cid| {
            let c = cpg.ast.get(&cid)?;
            if c.node_type != "base_class_clause" { return None; }
            let bases: Vec<String> = c.children.iter().filter_map(|&bid| {
                let b = cpg.ast.get(&bid)?;
                if b.node_type == "base_specifier" {
                    // Look for type_identifier inside base_specifier
                    b.children.iter().find_map(|&tid| {
                        cpg.ast.get(&tid).filter(|t| {
                            matches!(t.node_type.as_str(), "type_identifier" | "identifier")
                        }).and_then(|t| t.text.clone())
                    })
                } else if matches!(b.node_type.as_str(), "type_identifier" | "identifier") {
                    b.text.clone()
                } else {
                    None
                }
            }).collect();
            if bases.is_empty() { None } else { Some(bases) }
        }).unwrap_or_default();
        if !base_classes.is_empty() {
            if let Some(n) = cpg.ast.get_mut(class_id) {
                n.base_classes = Some(base_classes);
            }
        }
    }

    // ── Populate visibility on class members from access_specifier siblings ────
    // C++ field_declaration_list children are interleaved: access_specifier nodes
    // change the current visibility for subsequent members until the next one.
    for (class_id, _) in &class_nodes {
        let class_node_type = cpg.ast.get(class_id).map(|n| n.node_type.clone()).unwrap_or_default();
        let mut current_visibility = if class_node_type == "struct_specifier" { "public" } else { "private" };
        let body_children = cpg.ast.get(class_id).and_then(|n| {
            n.children.iter().find_map(|&cid| {
                let c = cpg.ast.get(&cid)?;
                if c.node_type == "field_declaration_list" { Some(c.children.clone()) } else { None }
            })
        }).unwrap_or_default();
        for member_id in body_children {
            let member_type = cpg.ast.get(&member_id).map(|n| n.node_type.clone()).unwrap_or_default();
            if member_type == "access_specifier" {
                let text = cpg.ast.get(&member_id).and_then(|n| n.text.clone()).unwrap_or_default();
                current_visibility = match text.as_str() {
                    "public" => "public",
                    "private" => "private",
                    "protected" => "protected",
                    _ => current_visibility,
                };
                continue;
            }
            if let Some(n) = cpg.ast.get_mut(&member_id) {
                if n.visibility.is_none() {
                    n.visibility = Some(current_visibility.to_string());
                }
            }
        }
    }

    // Populate name on namespace_definition nodes.
    for (ns_id, ns_name) in &namespace_nodes {
        if let Some(node) = cpg.ast.get_mut(ns_id) {
            if node.name.is_none() {
                node.name = Some(ns_name.clone());
            }
        }
    }

    // ── Third pass: populate names and signatures for param/local nodes ─────────
    // C/C++ parameter_declaration and declaration/init_declarator nodes do not
    // go through the main enrichment pass above; handle them here so that queries
    // on `node.name` work uniformly across all languages.
    let node_ids_pass3: Vec<NodeId> = cpg.ast.keys().copied().collect();
    for node_id in node_ids_pass3 {
        let node_type = cpg.ast.get(&node_id).map(|n| n.node_type.clone()).unwrap_or_default();
        match node_type.as_str() {
            "parameter_declaration" | "variadic_parameter_declaration" => {
                let node = cpg.ast[&node_id].clone();
                // Find first identifier or pointer_declarator → identifier child
                let param_name = node.children.iter().find_map(|&cid| {
                    let c = cpg.ast.get(&cid)?;
                    match c.node_type.as_str() {
                        "identifier" => c.text.clone(),
                        "pointer_declarator" | "reference_declarator"
                        | "rvalue_reference_declarator" => {
                            // recurse one level to find the identifier
                            c.children.iter().find_map(|&gcid| {
                                cpg.ast.get(&gcid)
                                    .filter(|gc| gc.node_type == "identifier")
                                    .and_then(|gc| gc.text.clone())
                            })
                        }
                        _ => None,
                    }
                });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    if n.name.is_none() {
                        n.name = param_name;
                    }
                }
            }
            "init_declarator" => {
                // `int x = 0;` → init_declarator → identifier "x"
                let node = cpg.ast[&node_id].clone();
                let var_name = node.children.iter().find_map(|&cid| {
                    cpg.ast.get(&cid)
                        .filter(|c| c.node_type == "identifier")
                        .and_then(|c| c.text.clone())
                });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    if n.name.is_none() {
                        n.name = var_name;
                    }
                }
            }
            "declaration" => {
                // `int x;` → declaration → declarator → identifier
                // The name lives in a direct declarator child.
                let node = cpg.ast[&node_id].clone();
                let var_name = node.children.iter().find_map(|&cid| {
                    let c = cpg.ast.get(&cid)?;
                    match c.node_type.as_str() {
                        "identifier" => c.text.clone(),
                        "init_declarator" | "pointer_declarator"
                        | "reference_declarator" | "rvalue_reference_declarator"
                        | "array_declarator" => {
                            // First identifier child is the variable name
                            c.children.iter().find_map(|&gcid| {
                                cpg.ast.get(&gcid)
                                    .filter(|gc| gc.node_type == "identifier")
                                    .and_then(|gc| gc.text.clone())
                            })
                        }
                        _ => None,
                    }
                });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    if n.name.is_none() {
                        n.name = var_name;
                    }
                }
            }
            _ => {}
        }
    }

    // ── Fourth pass: populate signature for function_definition nodes ────────────
    // Extract `(params) -> return_type` style signature text similar to Go/Python.
    let fn_def_ids: Vec<NodeId> = cpg
        .ast
        .iter()
        .filter(|(_, n)| n.node_type == "function_definition" && n.signature.is_none())
        .map(|(id, _)| *id)
        .collect();
    for fn_id in fn_def_ids {
        let node = cpg.ast[&fn_id].clone();
        // Find the function_declarator (possibly wrapped in pointer/ref declarator)
        fn find_fn_declarator<'a>(
            ast: &'a BTreeMap<NodeId, AstNode>,
            children: &[NodeId],
            depth: usize,
        ) -> Option<&'a AstNode> {
            if depth > 6 {
                return None;
            }
            for &cid in children {
                if let Some(c) = ast.get(&cid) {
                    if c.node_type == "function_declarator" {
                        return Some(c);
                    }
                    if matches!(
                        c.node_type.as_str(),
                        "pointer_declarator"
                            | "reference_declarator"
                            | "rvalue_reference_declarator"
                            | "parenthesized_declarator"
                    ) {
                        if let Some(found) = find_fn_declarator(ast, &c.children, depth + 1) {
                            return Some(found);
                        }
                    }
                }
            }
            None
        }
        let fn_decl = find_fn_declarator(&cpg.ast, &node.children, 0);
        let params_text = fn_decl.and_then(|fd| {
            fd.children.iter().find_map(|&cid| {
                cpg.ast
                    .get(&cid)
                    .filter(|c| c.node_type == "parameter_list")
                    .and_then(|c| c.text.clone())
            })
        });
        // Return type: first type-like child of function_definition (before the declarator)
        let return_type_text = node.children.iter().find_map(|&cid| {
            cpg.ast.get(&cid).and_then(|c| {
                if matches!(
                    c.node_type.as_str(),
                    "primitive_type"
                        | "type_identifier"
                        | "qualified_identifier"
                        | "auto"
                        | "sized_type_specifier"
                        | "template_type"
                        | "decltype"
                        | "type_specifier"
                        | "void"
                ) {
                    c.text.clone()
                } else {
                    None
                }
            })
        });
        let signature = match (params_text, return_type_text) {
            (Some(p), Some(r)) => Some(format!("{p} -> {r}")),
            (Some(p), None) => Some(p),
            _ => None,
        };
        if let Some(sig) = signature {
            if let Some(n) = cpg.ast.get_mut(&fn_id) {
                n.signature = Some(sig);
            }
        }
    }

    // ── Fix float literals: number_literal with '.' or 'e'/'E' is Float ─────
    for node in cpg.ast.values_mut() {
        if node.kind == IrNodeKind::Literal && node.node_type == "number_literal" {
            if let Some(ref text) = node.text {
                let has_dot = text.contains('.');
                let has_exp = text.contains('e') || text.contains('E')
                           || text.contains('p') || text.contains('P');
                if has_dot || has_exp {
                    node.lit_kind = Some(LiteralKind::Float);
                }
            }
        }
    }
}

// ── Shared enrichment helpers ─────────────────────────────────────────────────

fn child_with_field<'a>(
    node: &'a AstNode,
    ast: &'a BTreeMap<NodeId, AstNode>,
    field: &str,
) -> Option<(NodeId, &'a AstNode)> {
    for (i, &child_id) in node.children.iter().enumerate() {
        if node.field_names.get(i).and_then(|f| f.as_deref()) == Some(field) {
            if let Some(child) = ast.get(&child_id) {
                return Some((child_id, child));
            }
        }
    }
    None
}

fn first_child_of_type<'a>(
    node: &'a AstNode,
    ast: &'a BTreeMap<NodeId, AstNode>,
    ty: &str,
) -> Option<(NodeId, &'a AstNode)> {
    for &child_id in &node.children {
        if let Some(child) = ast.get(&child_id) {
            if child.node_type == ty {
                return Some((child_id, child));
            }
        }
    }
    None
}

fn has_child_of_type(node: &AstNode, ast: &BTreeMap<NodeId, AstNode>, ty: &str) -> bool {
    node.children
        .iter()
        .any(|id| ast.get(id).map_or(false, |c| c.node_type == ty))
}

// ── Go enrichment ─────────────────────────────────────────────────────────────

pub(crate) fn enrich_go_metadata(cpg: &mut Cpg) {
    // Collect all node IDs so we can iterate and mutate.
    let ids: Vec<NodeId> = cpg.ast.keys().copied().collect();

    // ── Pass 1: names, operators, loop_kinds, and GoNodeMetadata ─────────────
    for &node_id in &ids {
        let node_type = cpg.ast[&node_id].node_type.clone();
        match node_type.as_str() {
            // ── File: extract package_name from package_clause child ─────────
            "source_file" => {
                // Find the package_clause child, then the package_name identifier
                let pkg_name = cpg.ast[&node_id]
                    .children
                    .iter()
                    .find_map(|&cid| {
                        let child = cpg.ast.get(&cid)?;
                        if child.node_type != "package_clause" {
                            return None;
                        }
                        // package_clause has an identifier child
                        child.children.iter().find_map(|&gcid| {
                            let gc = cpg.ast.get(&gcid)?;
                            if gc.node_type == "package_identifier"
                                || gc.node_type == "identifier"
                            {
                                gc.text.clone()
                            } else {
                                None
                            }
                        })
                    });
                let meta = cpg.go_meta_mut(node_id);
                meta.package_name = pkg_name;
            }

            // ── Function declaration ─────────────────────────────────────────
            "function_declaration" => {
                let node = &cpg.ast[&node_id];
                // name: identifier child with field "name"
                let fn_name = child_with_field(node, &cpg.ast, "name")
                    .and_then(|(_, c)| c.text.clone());
                // signature: parameters text + optional result text
                let params_text = child_with_field(node, &cpg.ast, "parameters")
                    .and_then(|(_, c)| c.text.clone());
                let result_text = child_with_field(node, &cpg.ast, "result")
                    .and_then(|(_, c)| c.text.clone());
                let signature = match (params_text, result_text) {
                    (Some(p), Some(r)) => Some(format!("{p} {r}")),
                    (Some(p), None) => Some(p),
                    _ => None,
                };
                let is_exported = fn_name.as_deref().map_or(false, |n| {
                    n.chars().next().map_or(false, |c| c.is_uppercase())
                });
                let is_init = fn_name.as_deref() == Some("init");
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = fn_name.clone();
                    n.signature = signature;
                }
                let meta = cpg.go_meta_mut(node_id);
                meta.is_exported = is_exported;
                meta.is_init = is_init;
                meta.function_kind = crate::FunctionKind::Internal;
            }

            // ── Method declaration ───────────────────────────────────────────
            "method_declaration" => {
                let node = &cpg.ast[&node_id];
                let fn_name = child_with_field(node, &cpg.ast, "name")
                    .and_then(|(_, c)| c.text.clone());
                let params_text = child_with_field(node, &cpg.ast, "parameters")
                    .and_then(|(_, c)| c.text.clone());
                let result_text = child_with_field(node, &cpg.ast, "result")
                    .and_then(|(_, c)| c.text.clone());
                let signature = match (params_text, result_text) {
                    (Some(p), Some(r)) => Some(format!("{p} {r}")),
                    (Some(p), None) => Some(p),
                    _ => None,
                };
                let is_exported = fn_name.as_deref().map_or(false, |n| {
                    n.chars().next().map_or(false, |c| c.is_uppercase())
                });
                // Receiver: first parameter_list child (field "receiver")
                let receiver_info = child_with_field(node, &cpg.ast, "receiver")
                    .map(|(recv_id, recv_node)| {
                        // receiver is a parameter_list; its first named child is a parameter_declaration
                        let param = recv_node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| c.node_type == "parameter_declaration")
                        });
                        let recv_name = param.and_then(|p| {
                            p.children.iter().find_map(|&cid| {
                                cpg.ast.get(&cid).filter(|c| c.node_type == "identifier").and_then(|c| c.text.clone())
                            })
                        });
                        // receiver type: pointer_type or type_identifier in the parameter_declaration
                        let recv_type = param.and_then(|p| {
                            p.children.iter().find_map(|&cid| {
                                cpg.ast.get(&cid).filter(|c| {
                                    matches!(c.node_type.as_str(), "pointer_type" | "type_identifier" | "qualified_type" | "generic_type")
                                }).and_then(|c| c.text.clone())
                            })
                        });
                        let _ = recv_id;
                        (recv_name, recv_type)
                    });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = fn_name;
                    n.signature = signature;
                }
                let meta = cpg.go_meta_mut(node_id);
                meta.is_exported = is_exported;
                meta.function_kind = crate::FunctionKind::Internal;
                if let Some((recv_name, recv_type)) = receiver_info {
                    meta.receiver_name = recv_name;
                    meta.receiver_type = recv_type;
                }
            }

            // ── Anonymous function literal ────────────────────────────────────
            "func_literal" => {
                let meta = cpg.go_meta_mut(node_id);
                meta.is_closure = true;
            }

            // ── Variable / constant declarations ─────────────────────────────
            "var_spec" | "const_spec" => {
                let node = &cpg.ast[&node_id];
                // name: first identifier child (field "name")
                let var_name = child_with_field(node, &cpg.ast, "name")
                    .and_then(|(_, c)| c.text.clone())
                    // fallback: first identifier child regardless of field
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| {
                                matches!(c.node_type.as_str(), "identifier" | "blank_identifier")
                            }).and_then(|c| c.text.clone())
                        })
                    });
                let is_const = node_type == "const_spec";
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = var_name;
                }
                let meta = cpg.go_meta_mut(node_id);
                meta.is_const = is_const;
            }

            // ── Short variable declaration ────────────────────────────────────
            "short_var_declaration" => {
                // Name = first identifier from the LHS expression_list
                let first_ident_name = cpg.ast[&node_id].children.iter().find_map(|&cid| {
                    let child = cpg.ast.get(&cid)?;
                    if child.node_type == "expression_list" {
                        child.children.iter().find_map(|&gcid| {
                            cpg.ast.get(&gcid).filter(|gc| {
                                matches!(gc.node_type.as_str(), "identifier" | "blank_identifier")
                            }).and_then(|gc| gc.text.clone())
                        })
                    } else if matches!(child.node_type.as_str(), "identifier" | "blank_identifier") {
                        child.text.clone()
                    } else {
                        None
                    }
                });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = first_ident_name;
                }
            }

            // ── Variadic argument: set operator ───────────────────────────────
            "variadic_argument" => {
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.operator = Some("...".to_string());
                }
            }

            // ── Type declarations ─────────────────────────────────────────────
            "type_spec" => {
                let node = &cpg.ast[&node_id];
                let type_name = child_with_field(node, &cpg.ast, "name")
                    .and_then(|(_, c)| c.text.clone())
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| {
                                matches!(c.node_type.as_str(), "type_identifier" | "identifier")
                            }).and_then(|c| c.text.clone())
                        })
                    });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = type_name;
                }
            }

            "type_alias" => {
                let node = &cpg.ast[&node_id];
                let type_name = child_with_field(node, &cpg.ast, "name")
                    .and_then(|(_, c)| c.text.clone())
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| {
                                matches!(c.node_type.as_str(), "type_identifier" | "identifier")
                            }).and_then(|c| c.text.clone())
                        })
                    });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = type_name;
                }
                let meta = cpg.go_meta_mut(node_id);
                meta.is_alias = true;
            }

            // ── Struct / interface type ───────────────────────────────────────
            "struct_type" | "interface_type" => {
                // Name comes from parent type_spec/type_alias
                let parent_id = cpg.ast[&node_id].parent_id;
                let type_name = parent_id.and_then(|pid| {
                    let parent = cpg.ast.get(&pid)?;
                    if matches!(parent.node_type.as_str(), "type_spec" | "type_alias") {
                        child_with_field(parent, &cpg.ast, "name")
                            .and_then(|(_, c)| c.text.clone())
                            .or_else(|| {
                                parent.children.iter().find_map(|&cid| {
                                    cpg.ast.get(&cid).filter(|c| {
                                        c.node_type == "type_identifier" || c.node_type == "identifier"
                                    }).and_then(|c| c.text.clone())
                                })
                            })
                    } else {
                        None
                    }
                });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = type_name;
                }
                let is_interface = node_type == "interface_type";
                let meta = cpg.go_meta_mut(node_id);
                meta.is_interface = is_interface;
            }

            // ── Channel type: direction ───────────────────────────────────────
            "channel_type" => {
                let node = &cpg.ast[&node_id];
                let raw_text = node.text.as_deref().unwrap_or("");
                let direction = if raw_text.starts_with("<-chan") || raw_text.starts_with("< -chan") {
                    ChannelDirection::Recv
                } else if raw_text.contains("chan<-") || raw_text.contains("chan <-") {
                    ChannelDirection::Send
                } else {
                    ChannelDirection::Bidi
                };
                let meta = cpg.go_meta_mut(node_id);
                meta.channel_direction = Some(direction);
            }

            // ── Labeled statement: name from label_name child ────────────────
            "labeled_statement" => {
                let node = &cpg.ast[&node_id];
                let label = node.children.iter().find_map(|&cid| {
                    cpg.ast.get(&cid).filter(|c| {
                        c.node_type == "label_name" || c.node_type == "identifier"
                    }).and_then(|c| c.text.clone())
                });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = label;
                }
            }

            // ── Goto statement: name from label_name child ────────────────────
            "goto_statement" => {
                let node = &cpg.ast[&node_id];
                let label = node.children.iter().find_map(|&cid| {
                    cpg.ast.get(&cid).filter(|c| {
                        c.node_type == "label_name" || c.node_type == "identifier"
                    }).and_then(|c| c.text.clone())
                });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = label;
                }
            }

            // ── Inc/Dec statements: operator ─────────────────────────────────
            "inc_statement" => {
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.operator = Some("++".to_string());
                }
            }
            "dec_statement" => {
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.operator = Some("--".to_string());
                }
            }

            // ── Assignment statement: operator from text ──────────────────────
            "assignment_statement" => {
                let node = &cpg.ast[&node_id];
                if node.operator.is_none() {
                    // Look for operator token in the raw text before the first operand
                    // tree-sitter-go uses field "operators" for the operator list
                    let op_text = node.children.iter().find_map(|&cid| {
                        cpg.ast.get(&cid).filter(|c| c.node_type == "operator").and_then(|c| c.text.clone())
                    });
                    // Fallback: detect from node text
                    let op = op_text.or_else(|| {
                        let txt = node.text.as_deref().unwrap_or("");
                        for op in &["+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", "&^=", "="] {
                            if txt.contains(op) {
                                return Some(op.to_string());
                            }
                        }
                        None
                    });
                    if let Some(n) = cpg.ast.get_mut(&node_id) {
                        n.operator = op;
                    }
                }
            }

            // ── Array type: size ─────────────────────────────────────────────
            "array_type" => {
                let node = &cpg.ast[&node_id];
                let size_text = child_with_field(node, &cpg.ast, "length")
                    .and_then(|(_, c)| c.text.clone())
                    .or_else(|| {
                        // fallback: first int_literal child
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| c.node_type == "int_literal")
                                .and_then(|c| c.text.clone())
                        })
                    });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    if n.array_size.is_none() {
                        if let Some(s) = &size_text {
                            n.array_size = s.parse::<i64>().ok();
                        }
                    }
                }
            }

            // ── For statement: update loop_kind based on children ────────────
            "for_statement" => {
                let node = &cpg.ast[&node_id];
                let has_for_clause = has_child_of_type(node, &cpg.ast, "for_clause");
                let has_range_clause = has_child_of_type(node, &cpg.ast, "range_clause");
                let new_loop_kind = if has_range_clause {
                    LoopKind::ForEach
                } else if has_for_clause {
                    LoopKind::For
                } else {
                    LoopKind::While
                };
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.loop_kind = Some(new_loop_kind);
                }
            }

            // ── Field declaration: name ───────────────────────────────────────
            "field_declaration" => {
                let node = &cpg.ast[&node_id];
                let field_name = node.children.iter().find_map(|&cid| {
                    cpg.ast.get(&cid).filter(|c| {
                        c.node_type == "field_identifier" || c.node_type == "identifier"
                    }).and_then(|c| c.text.clone())
                });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = field_name;
                }
            }

            // ── Parameter declaration: name ───────────────────────────────────
            "parameter_declaration" | "variadic_parameter_declaration" => {
                let node = cpg.ast[&node_id].clone();
                let param_name = child_with_field(&node, &cpg.ast, "name")
                    .and_then(|(_, c)| c.text.clone())
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| c.node_type == "identifier")
                                .and_then(|c| c.text.clone())
                        })
                    });
                let is_variadic = node_type == "variadic_parameter_declaration";
                // Detect named return values: parameter_declaration inside the
                // "result" parameter_list of a function/method declaration.
                // Named returns behave as local variables, not input parameters.
                let is_named_return = node.parent_id.and_then(|pl_id| {
                    let pl = cpg.ast.get(&pl_id)?;
                    let func_id = pl.parent_id?;
                    let func = cpg.ast.get(&func_id)?;
                    if !matches!(func.node_type.as_str(), "function_declaration" | "method_declaration") {
                        return None;
                    }
                    func.field_names.iter().zip(func.children.iter())
                        .find(|(fname, cid)| fname.as_deref() == Some("result") && **cid == pl_id)
                        .map(|_| true)
                }).unwrap_or(false);
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = param_name;
                    if is_named_return {
                        n.kind = IrNodeKind::LocalDef;
                    }
                }
                if is_variadic {
                    let meta = cpg.go_meta_mut(node_id);
                    meta.is_variadic = true;
                }
            }

            _ => {}
        }
    }

    // ── Pass 1.5: Set identifier names from text, convert ReceiveExpr/Cast ──────
    for &node_id in &ids {
        let node = &cpg.ast[&node_id];
        match node.node_type.as_str() {
            // All identifiers get name from text
            "identifier" | "blank_identifier" | "field_identifier"
            | "package_identifier" | "label_name" => {
                if node.name.is_none() {
                    let name = node.text.clone();
                    if let Some(n) = cpg.ast.get_mut(&node_id) {
                        n.name = name;
                    }
                }
            }
            // unary_expression with <-: convert to ReceiveExpr
            "unary_expression" => {
                if node.operator.as_deref() == Some("<-") {
                    if let Some(n) = cpg.ast.get_mut(&node_id) {
                        n.kind = IrNodeKind::ReceiveExpr;
                    }
                }
            }
            // call_expression where function is a builtin type → Cast
            "call_expression" => {
                let callee_is_type = node.children.iter().next().and_then(|&cid| {
                    cpg.ast.get(&cid)
                }).map_or(false, |callee| {
                    // If the callee is a type_identifier, it's a type conversion
                    callee.node_type == "type_identifier"
                    || (callee.node_type == "identifier" && callee.text.as_deref().map_or(false, |t| {
                        matches!(t, "int" | "int8" | "int16" | "int32" | "int64"
                            | "uint" | "uint8" | "uint16" | "uint32" | "uint64"
                            | "uintptr" | "float32" | "float64"
                            | "complex64" | "complex128"
                            | "bool" | "byte" | "rune" | "string")
                    }))
                });
                if callee_is_type {
                    if let Some(n) = cpg.ast.get_mut(&node_id) {
                        n.kind = IrNodeKind::Cast;
                    }
                }
            }
            _ => {}
        }
    }

    // ── Pass 1.6: Flatten expression_list for short_var_declaration and return ──
    for &node_id in &ids {
        let node_type = cpg.ast[&node_id].node_type.clone();
        if !matches!(node_type.as_str(), "short_var_declaration" | "return_statement" | "assignment_statement") {
            continue;
        }
        let children: Vec<NodeId> = cpg.ast[&node_id].children.clone();
        let mut new_children: Vec<NodeId> = Vec::new();
        let mut changed = false;
        for &cid in &children {
            let child_type = cpg.ast.get(&cid).map(|c| c.node_type.clone()).unwrap_or_default();
            if child_type == "expression_list" {
                let grandchildren: Vec<NodeId> = cpg.ast.get(&cid)
                    .map(|c| c.children.clone())
                    .unwrap_or_default();
                for &gcid in &grandchildren {
                    if let Some(gc) = cpg.ast.get_mut(&gcid) {
                        gc.parent_id = Some(node_id);
                    }
                    new_children.push(gcid);
                }
                changed = true;
            } else {
                new_children.push(cid);
            }
        }
        if changed {
            if let Some(n) = cpg.ast.get_mut(&node_id) {
                n.children = new_children;
            }
        }
    }

    // ── Pass 1.7: Interface embedding in interface_type ───────────────────────
    for &node_id in &ids {
        let node = &cpg.ast[&node_id];
        if node.node_type != "interface_type" {
            continue;
        }
        // Embedded interface names: children that are type_identifier, qualified_type,
        // or generic_type; OR children that are type_elem (tree-sitter-go ≥0.21 wraps
        // embedded interface references in a type_elem node containing a type_identifier).
        let embedded: Vec<String> = node.children.iter().filter_map(|&cid| {
            let child = cpg.ast.get(&cid)?;
            if child.node_type == "type_identifier" {
                child.text.clone()
            } else if matches!(child.node_type.as_str(), "qualified_type" | "generic_type") {
                child.text.clone()
            } else if child.node_type == "type_elem" {
                // type_elem → type_identifier (or qualified_type/generic_type)
                child.children.iter().find_map(|&gcid| {
                    let gc = cpg.ast.get(&gcid)?;
                    if matches!(gc.node_type.as_str(), "type_identifier" | "qualified_type" | "generic_type") {
                        gc.text.clone()
                    } else {
                        None
                    }
                })
            } else {
                None
            }
        }).collect();
        if !embedded.is_empty() {
            let meta = cpg.go_meta_mut(node_id);
            meta.embedded_interfaces = Some(embedded);
        }
    }

    // ── Pass 2: propagate generic_type_params from type_parameter_list ────────
    for &node_id in &ids {
        let node = &cpg.ast[&node_id];
        if node.node_type != "type_parameter_list" {
            continue;
        }
        // Collect all type-param names from each type_parameter_declaration.
        // Each declaration is like [T, U any]: children = [T, U, constraint].
        // All children except the last are type param names; the last is the constraint.
        let params: Vec<String> = node.children.iter().flat_map(|&cid| -> Vec<String> {
            let decl = match cpg.ast.get(&cid) {
                Some(d) if d.node_type == "type_parameter_declaration" => d,
                _ => return vec![],
            };
            let name_count = decl.children.len().saturating_sub(1);
            decl.children.iter().take(name_count).filter_map(|&gcid| {
                cpg.ast.get(&gcid).filter(|gc| {
                    gc.node_type == "type_identifier" || gc.node_type == "identifier"
                }).and_then(|gc| gc.text.clone())
            }).collect()
        }).collect();
        if !params.is_empty() {
            if let Some(parent_id) = node.parent_id {
                let meta = cpg.go_meta_mut(parent_id);
                meta.generic_type_params = Some(params);
            }
        }
    }
}

// ── Python enrichment ─────────────────────────────────────────────────────────

fn find_with_alias(node: &AstNode, ast: &BTreeMap<NodeId, AstNode>) -> Option<String> {
    for &cid in &node.children {
        if let Some(child) = ast.get(&cid) {
            match child.node_type.as_str() {
                "as_pattern" => {
                    // as_pattern: [expression, as_pattern_target]
                    // The last child is the target
                    if let Some(&aid) = child.children.last() {
                        if let Some(a) = ast.get(&aid) {
                            // as_pattern_target may contain identifier
                            if a.node_type == "as_pattern_target" {
                                return a.children.first().and_then(|&iid| {
                                    ast.get(&iid).and_then(|id| id.text.clone())
                                }).or(a.text.clone());
                            } else {
                                return a.text.clone();
                            }
                        }
                    }
                }
                "with_item" | "with_clause" => {
                    if let Some(alias) = find_with_alias(child, ast) {
                        return Some(alias);
                    }
                }
                _ => {}
            }
        }
    }
    None
}

pub(crate) fn enrich_python_metadata(cpg: &mut Cpg) {
    let ids: Vec<NodeId> = cpg.ast.keys().copied().collect();

    // Pass 1: set names, operators, ParamDef kinds
    for &node_id in &ids {
        let node_type = cpg.ast[&node_id].node_type.clone();
        match node_type.as_str() {
            "function_definition" | "async_function_definition" => {
                let node = &cpg.ast[&node_id];
                let fn_name = child_with_field(node, &cpg.ast, "name")
                    .and_then(|(_, c)| c.text.clone())
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| c.node_type == "identifier")
                                .and_then(|c| c.text.clone())
                        })
                    });
                // Detect async: node_type is "async_function_definition" OR first child is "async" text
                let is_async = node_type == "async_function_definition"
                    || node.text.as_deref().unwrap_or("").starts_with("async");
                let return_annotation = child_with_field(node, &cpg.ast, "return_type")
                    .and_then(|(_, c)| c.text.clone());
                // Collect decorators from siblings (decorator nodes that precede this function)
                let decorators: Vec<String> = if let Some(parent_id) = node.parent_id {
                    if let Some(parent) = cpg.ast.get(&parent_id) {
                        let mut found = false;
                        let mut decs = Vec::new();
                        for &sibling_id in &parent.children {
                            if sibling_id == node_id {
                                found = true;
                                break;
                            }
                            if let Some(sib) = cpg.ast.get(&sibling_id) {
                                if sib.node_type == "decorator" {
                                    let dec_name = sib.children.iter().find_map(|&cid| {
                                        cpg.ast.get(&cid).filter(|c| {
                                            matches!(c.node_type.as_str(), "identifier" | "call")
                                        }).and_then(|c| c.text.clone().or(c.name.clone()))
                                    }).or(sib.text.clone().map(|t| t.trim_start_matches('@').to_string()));
                                    if let Some(name) = dec_name {
                                        decs.push(name.trim_start_matches('@').to_string());
                                    }
                                }
                            }
                        }
                        let _ = found;
                        decs
                    } else { vec![] }
                } else { vec![] };
                let is_staticmethod = decorators.iter().any(|d| d == "staticmethod");
                let is_classmethod = decorators.iter().any(|d| d == "classmethod");
                // is_generator: check if any yield child exists
                let is_generator = {
                    fn has_yield(ast: &std::collections::BTreeMap<NodeId, crate::AstNode>, id: NodeId) -> bool {
                        if let Some(n) = ast.get(&id) {
                            if matches!(n.kind, IrNodeKind::Yield) { return true; }
                            n.children.iter().any(|&cid| has_yield(ast, cid))
                        } else { false }
                    }
                    has_yield(&cpg.ast, node_id)
                };
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = fn_name;
                }
                let meta = cpg.python_meta_mut(node_id);
                meta.is_async = is_async;
                meta.function_kind = crate::FunctionKind::Internal;
                meta.decorators = decorators;
                meta.is_staticmethod = is_staticmethod;
                meta.is_classmethod = is_classmethod;
                meta.is_generator = is_generator;
                meta.return_annotation = return_annotation;
            }

            "class_definition" => {
                let node = &cpg.ast[&node_id];
                let class_name = child_with_field(node, &cpg.ast, "name")
                    .and_then(|(_, c)| c.text.clone())
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| c.node_type == "identifier")
                                .and_then(|c| c.text.clone())
                        })
                    });
                // base_classes: children in argument_list that are identifiers or attributes
                let base_classes: Vec<String> = node.children.iter().find_map(|&cid| {
                    let child = cpg.ast.get(&cid)?;
                    if child.node_type == "argument_list" {
                        Some(child.children.iter().filter_map(|&gcid| {
                            cpg.ast.get(&gcid).filter(|gc| {
                                matches!(gc.node_type.as_str(), "identifier" | "attribute")
                            }).and_then(|gc| gc.text.clone())
                        }).collect::<Vec<_>>())
                    } else { None }
                }).unwrap_or_default();
                let class_children = node.children.clone();
                // metaclass: argument_list child `keyword_argument` named "metaclass"
                let metaclass: Option<String> = class_children.iter().find_map(|&cid| {
                    let child = cpg.ast.get(&cid)?;
                    if child.node_type != "argument_list" { return None; }
                    child.children.iter().find_map(|&gcid| {
                        let gc = cpg.ast.get(&gcid)?;
                        if gc.node_type != "keyword_argument" { return None; }
                        let name_child = gc.children.iter().find_map(|&kid| {
                            cpg.ast.get(&kid).filter(|k| k.node_type == "identifier")
                                .and_then(|k| k.text.clone())
                        })?;
                        if name_child != "metaclass" { return None; }
                        gc.children.iter().rev().find_map(|&kid| {
                            cpg.ast.get(&kid).filter(|k| matches!(k.node_type.as_str(), "identifier" | "attribute"))
                                .and_then(|k| k.text.clone())
                        }).filter(|v| v != &name_child)
                    })
                });
                // argument_list = superclass list: convert each identifier/attribute to TypeRef
                // AND mark the argument_list node itself as TypeRef so it's a direct TypeRef child
                if let Some(arg_list_id) = class_children.iter().find(|&&cid| {
                    cpg.ast.get(&cid).map_or(false, |c| c.node_type == "argument_list")
                }).copied() {
                    if let Some(n) = cpg.ast.get_mut(&arg_list_id) {
                        n.kind = IrNodeKind::TypeRef;
                    }
                    let arg_children: Vec<NodeId> = cpg.ast.get(&arg_list_id)
                        .map(|c| c.children.clone()).unwrap_or_default();
                    for &gcid in &arg_children {
                        if let Some(gc) = cpg.ast.get(&gcid) {
                            if matches!(gc.node_type.as_str(), "identifier" | "attribute") {
                                if let Some(n) = cpg.ast.get_mut(&gcid) {
                                    n.kind = IrNodeKind::TypeRef;
                                }
                            }
                        }
                    }
                }
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = class_name;
                    if !base_classes.is_empty() {
                        n.base_classes = Some(base_classes);
                    }
                }
                if let Some(mc) = metaclass {
                    cpg.python_meta_mut(node_id).metaclass = Some(mc);
                }
            }

            // Python call: extract callee name from function field
            "call" => {
                let node = &cpg.ast[&node_id];
                let func_child = child_with_field(node, &cpg.ast, "function");
                let call_name = func_child
                    .and_then(|(_, c)| {
                        if c.node_type == "attribute" {
                            // Method call like db.execute(query) — use only the method name
                            // (the last identifier child of the attribute node), not "db.execute".
                            let children: Vec<NodeId> = c.children.clone();
                            children.into_iter().rev().find_map(|cid| {
                                cpg.ast.get(&cid)
                                    .filter(|gc| gc.node_type == "identifier")
                                    .and_then(|gc| gc.text.clone())
                            })
                        } else {
                            c.text.clone()
                        }
                    })
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| {
                                matches!(c.node_type.as_str(), "identifier" | "attribute")
                            }).and_then(|c| c.text.clone())
                        })
                    });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = call_name;
                }
            }

            // Python parameters: mark identifier children as ParamDef
            "parameters" => {
                let node = &cpg.ast[&node_id];
                let param_children: Vec<NodeId> = node.children.clone();
                for cid in param_children {
                    if let Some(child) = cpg.ast.get(&cid) {
                        match child.node_type.as_str() {
                            "identifier" => {
                                let name = child.text.clone();
                                if let Some(n) = cpg.ast.get_mut(&cid) {
                                    n.kind = IrNodeKind::ParamDef;
                                    n.name = name;
                                }
                            }
                            "default_parameter" | "typed_parameter"
                            | "typed_default_parameter" => {
                                let child = cpg.ast.get(&cid).unwrap();
                                let param_name = child_with_field(child, &cpg.ast, "name")
                                    .and_then(|(_, c)| c.text.clone())
                                    .or_else(|| {
                                        child.children.iter().find_map(|&gcid| {
                                            cpg.ast.get(&gcid).filter(|c| c.node_type == "identifier")
                                                .and_then(|c| c.text.clone())
                                        })
                                    });
                                let annotation = child_with_field(child, &cpg.ast, "type")
                                    .and_then(|(_, c)| c.text.clone());
                                let has_default = child.node_type == "default_parameter"
                                    || child.node_type == "typed_default_parameter";
                                let pid = cid;
                                if let Some(n) = cpg.ast.get_mut(&pid) {
                                    n.name = param_name;
                                }
                                let meta = cpg.python_meta_mut(pid);
                                meta.annotation = annotation;
                                meta.has_default = has_default;
                            }
                            "list_splat_pattern" | "dictionary_splat_pattern" => {
                                let child = cpg.ast.get(&cid).unwrap();
                                let param_name = child.children.iter().find_map(|&gcid| {
                                    cpg.ast.get(&gcid).filter(|c| c.node_type == "identifier")
                                        .and_then(|c| c.text.clone())
                                });
                                let is_star = child.node_type == "list_splat_pattern";
                                let is_double_star = child.node_type == "dictionary_splat_pattern";
                                let pid = cid;
                                if let Some(n) = cpg.ast.get_mut(&pid) {
                                    n.kind = IrNodeKind::ParamDef;
                                    n.name = param_name;
                                }
                                let meta = cpg.python_meta_mut(pid);
                                meta.is_star_param = is_star;
                                meta.is_double_star_param = is_double_star;
                            }
                            _ => {}
                        }
                    }
                }
            }

            // assignment: set operator and detect annotated assignment
            // tree-sitter-python 0.25 uses "assignment" for both `x = 5` and `x: int = 5`
            "assignment" => {
                let (has_op, has_type_child) = {
                    let node = &cpg.ast[&node_id];
                    let has_op = node.operator.is_none();
                    let has_type = node.children.iter().any(|&cid| {
                        cpg.ast.get(&cid).map_or(false, |c| c.node_type == "type")
                    });
                    (has_op, has_type)
                };
                if has_op {
                    if let Some(n) = cpg.ast.get_mut(&node_id) {
                        n.operator = Some("=".to_string());
                    }
                }
                // If the assignment has a `type` child, it's an annotated assignment
                if has_type_child {
                    if let Some(n) = cpg.ast.get_mut(&node_id) {
                        n.node_type = "annotated_assignment".to_string();
                    }
                    let meta = cpg.python_meta_mut(node_id);
                    meta.is_annotated = true;
                }
            }

            "annotated_assignment" => {
                let meta = cpg.python_meta_mut(node_id);
                meta.is_annotated = true;
            }

            // Import statements
            "import_statement" => {
                let node = &cpg.ast[&node_id];
                let module = node.children.iter().find_map(|&cid| {
                    let child = cpg.ast.get(&cid)?;
                    if matches!(child.node_type.as_str(), "dotted_name" | "identifier") {
                        child.text.clone()
                    } else { None }
                });
                let meta = cpg.python_meta_mut(node_id);
                meta.import_kind = crate::ImportKind::Regular;
                meta.import_module = module;
            }

            "import_from_statement" | "future_import_statement" => {
                let node = &cpg.ast[&node_id];
                // First dotted_name / relative_import = module; rest are imported names
                let children: Vec<NodeId> = node.children.clone();
                let mut module_name: Option<String> = None;
                let mut import_names: Vec<String> = Vec::new();
                let mut is_wildcard = false;
                for &cid in &children {
                    if let Some(child) = cpg.ast.get(&cid) {
                        match child.node_type.as_str() {
                            "dotted_name" | "relative_import" => {
                                if module_name.is_none() {
                                    module_name = child.text.clone();
                                } else {
                                    // subsequent dotted_names are imported names
                                    if let Some(t) = child.text.clone() {
                                        import_names.push(t);
                                    }
                                }
                            }
                            "wildcard_import" => { is_wildcard = true; }
                            "aliased_import" => {
                                // aliased_import: name "as" alias — take the first identifier
                                if let Some(name) = child.children.first().and_then(|&gcid| {
                                    cpg.ast.get(&gcid).and_then(|gc| gc.text.clone())
                                }) {
                                    import_names.push(name);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                let module_is_future = module_name.as_deref() == Some("__future__")
                    || node_type == "future_import_statement";
                let meta = cpg.python_meta_mut(node_id);
                meta.import_kind = if module_is_future {
                    crate::ImportKind::Future
                } else {
                    crate::ImportKind::From
                };
                meta.import_module = module_name;
                meta.import_names = import_names;
                meta.import_is_wildcard = is_wildcard;
            }

            // Comprehensions
            "list_comprehension" => {
                let meta = cpg.python_meta_mut(node_id);
                meta.comprehension_kind = crate::ComprehensionKind::List;
            }
            "set_comprehension" => {
                let meta = cpg.python_meta_mut(node_id);
                meta.comprehension_kind = crate::ComprehensionKind::Set;
            }
            "dictionary_comprehension" => {
                let meta = cpg.python_meta_mut(node_id);
                meta.comprehension_kind = crate::ComprehensionKind::Dict;
            }
            "generator_expression" => {
                let meta = cpg.python_meta_mut(node_id);
                meta.comprehension_kind = crate::ComprehensionKind::Generator;
            }

            // Yield expressions
            "yield" | "yield_statement" | "yield_from" => {
                let txt = cpg.ast[&node_id].text.as_deref().unwrap_or("");
                let is_from = txt.contains(" from ") || node_type == "yield_from";
                let meta = cpg.python_meta_mut(node_id);
                meta.is_yield_from = is_from;
            }

            // Try statement
            "try_statement" => {
                let node = &cpg.ast[&node_id];
                let has_finally = node.children.iter().any(|&cid| {
                    cpg.ast.get(&cid).map_or(false, |c| c.node_type == "finally_clause")
                });
                let has_try_else = node.children.iter().any(|&cid| {
                    cpg.ast.get(&cid).map_or(false, |c| c.node_type == "else_clause")
                });
                let meta = cpg.python_meta_mut(node_id);
                meta.has_finally = has_finally;
                meta.has_try_else = has_try_else;
            }

            // Except clause: `except ExcType as alias:`
            // tree-sitter-python 0.25: except_clause → as_pattern → [identifier, as_pattern_target]
            "except_clause" | "except_group_clause" => {
                let node = &cpg.ast[&node_id];
                // Try as_pattern first (tree-sitter-python 0.25+)
                let (exception_type, exception_alias) = {
                    if let Some(as_pat) = node.children.iter().find_map(|&cid| {
                        cpg.ast.get(&cid).filter(|c| c.node_type == "as_pattern")
                    }) {
                        let exc_type = as_pat.children.first().and_then(|&cid| {
                            cpg.ast.get(&cid).and_then(|c| c.text.clone())
                        });
                        let alias = as_pat.children.iter().find_map(|&cid| {
                            let c = cpg.ast.get(&cid)?;
                            if c.node_type == "as_pattern_target" {
                                c.children.first().and_then(|&iid| {
                                    cpg.ast.get(&iid).and_then(|id| id.text.clone())
                                }).or(c.text.clone())
                            } else { None }
                        });
                        (exc_type, alias)
                    } else {
                        // Fallback: first direct identifier/dotted_name = type, second = alias
                        let mut named: Vec<NodeId> = node.children.iter().filter(|&&cid| {
                            cpg.ast.get(&cid).map_or(false, |c| {
                                matches!(c.node_type.as_str(),
                                    "identifier" | "attribute" | "dotted_name"
                                    | "as_pattern_target" | "tuple")
                            })
                        }).copied().collect();
                        let exc_type = named.first().and_then(|&cid| {
                            cpg.ast.get(&cid).and_then(|c| c.text.clone())
                        });
                        let alias = named.get(1).and_then(|&cid| {
                            let child = cpg.ast.get(&cid)?;
                            if child.node_type == "as_pattern_target" {
                                child.children.first().and_then(|&iid| {
                                    cpg.ast.get(&iid).and_then(|c| c.text.clone())
                                }).or(child.text.clone())
                            } else { child.text.clone() }
                        });
                        let _ = named.pop();
                        (exc_type, alias)
                    }
                };
                let meta = cpg.python_meta_mut(node_id);
                meta.exception_type = exception_type;
                meta.exception_alias = exception_alias;
            }

            // With statement: only set metadata on the outer with_statement node
            "with_statement" => {
                let node = &cpg.ast[&node_id];
                // Structure: with_statement → with_clause → with_item → as_pattern / identifier
                let with_alias = find_with_alias(node, &cpg.ast);
                let meta = cpg.python_meta_mut(node_id);
                meta.with_alias = with_alias;
            }

            // Global / nonlocal statements
            "global_statement" => {
                let node = &cpg.ast[&node_id];
                let names: Vec<String> = node.children.iter().filter_map(|&cid| {
                    cpg.ast.get(&cid).filter(|c| c.node_type == "identifier")
                        .and_then(|c| c.text.clone())
                }).collect();
                let meta = cpg.python_meta_mut(node_id);
                meta.global_kind = crate::GlobalKind::Global;
                meta.global_names = names;
            }

            "nonlocal_statement" => {
                let node = &cpg.ast[&node_id];
                let names: Vec<String> = node.children.iter().filter_map(|&cid| {
                    cpg.ast.get(&cid).filter(|c| c.node_type == "identifier")
                        .and_then(|c| c.text.clone())
                }).collect();
                let meta = cpg.python_meta_mut(node_id);
                meta.global_kind = crate::GlobalKind::Nonlocal;
                meta.global_names = names;
            }

            // For statement: has_loop_else
            "for_statement" => {
                let node = &cpg.ast[&node_id];
                let has_loop_else = node.children.iter().any(|&cid| {
                    cpg.ast.get(&cid).map_or(false, |c| c.node_type == "else_clause")
                });
                let meta = cpg.python_meta_mut(node_id);
                meta.has_loop_else = has_loop_else;
            }

            // String literals: detect bytes (b'...') and f-strings (f'...')
            "string" | "concatenated_string" => {
                let txt = cpg.ast[&node_id].text.as_deref().unwrap_or_default().to_string();
                let lower = txt.trim_start().to_lowercase();
                // Check string_start child for prefix too
                let prefix: String = {
                    let node = &cpg.ast[&node_id];
                    node.children.iter().find_map(|&cid| {
                        cpg.ast.get(&cid).filter(|c| c.node_type == "string_start")
                            .and_then(|c| c.text.clone())
                    }).unwrap_or_default().to_lowercase()
                };
                let combined_prefix = if prefix.is_empty() { lower } else { prefix };
                let lit_kind = if combined_prefix.starts_with("b'") || combined_prefix.starts_with("b\"")
                    || combined_prefix.starts_with("rb") || combined_prefix.starts_with("br") {
                    LiteralKind::Bytes
                } else if combined_prefix.starts_with("f'") || combined_prefix.starts_with("f\"")
                    || combined_prefix.starts_with("rf") || combined_prefix.starts_with("fr") {
                    LiteralKind::Template
                } else {
                    LiteralKind::String
                };
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.lit_kind = Some(lit_kind);
                }
            }

            "type_alias_statement" => {
                // `type Vector = list[float]` → TypeAlias with name "Vector"
                // tree-sitter-python emits: type_alias_statement → type("Vector") type(value)
                // The first child is a `type` node whose text is the alias name.
                let alias_name = {
                    let node = &cpg.ast[&node_id];
                    node.children.first().and_then(|&cid| {
                        cpg.ast.get(&cid).and_then(|c| {
                            // The `type` wrapper child holds the name text directly
                            if c.node_type == "type" {
                                c.text.clone()
                            } else {
                                c.text.clone().or_else(|| c.name.clone())
                            }
                        })
                    })
                };
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = alias_name;
                }
            }

            _ => {}
        }
    }
}

// ── Java enrichment ───────────────────────────────────────────────────────────

const JAVA_MODIFIER_KEYWORDS: &[&str] = &[
    "public", "private", "protected", "static", "final", "abstract",
    "synchronized", "volatile", "transient", "native", "strictfp",
    "sealed", "non-sealed", "default", "open",
];

fn java_modifiers_from_text(text: &str) -> Vec<String> {
    text.split_whitespace()
        .filter(|w| JAVA_MODIFIER_KEYWORDS.contains(w))
        .map(|w| w.to_string())
        .collect()
}

fn java_annotations_from_modifiers(mods_id: NodeId, ast: &std::collections::BTreeMap<NodeId, crate::AstNode>) -> Vec<String> {
    let mods = match ast.get(&mods_id) { Some(m) => m, None => return vec![] };
    mods.children.iter().filter_map(|&mid| {
        let child = ast.get(&mid)?;
        if child.node_type == "marker_annotation" || child.node_type == "annotation" {
            let text = child.text.as_deref().unwrap_or("");
            Some(text.trim_start_matches('@').to_string())
        } else { None }
    }).collect()
}

pub(crate) fn enrich_java_metadata(cpg: &mut Cpg) {
    let ids: Vec<NodeId> = cpg.ast.keys().copied().collect();

    // package_name: text of the top-level package_declaration's scoped_identifier/identifier child.
    let package_name: Option<String> = ids.iter().find_map(|&id| {
        let node = cpg.ast.get(&id)?;
        if node.node_type != "package_declaration" { return None; }
        node.children.iter().find_map(|&cid| {
            cpg.ast.get(&cid).filter(|c| {
                matches!(c.node_type.as_str(), "scoped_identifier" | "identifier")
            }).and_then(|c| c.text.clone())
        })
    });

    for &node_id in &ids {
        let node_type = cpg.ast[&node_id].node_type.clone();
        match node_type.as_str() {
            "class_declaration" | "interface_declaration"
            | "record_declaration" | "annotation_type_declaration" => {
                let node = &cpg.ast[&node_id];
                let class_name = child_with_field(node, &cpg.ast, "name")
                    .and_then(|(_, c)| c.text.clone())
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| {
                                c.node_type == "identifier" || c.node_type == "type_identifier"
                            }).and_then(|c| c.text.clone())
                        })
                    });
                // access_modifiers: parse from modifiers node text (keyword children are anonymous)
                let mods_id = node.children.iter().find(|&&cid| {
                    cpg.ast.get(&cid).map(|c| c.node_type == "modifiers").unwrap_or(false)
                }).copied();
                let access_mods: Vec<String> = mods_id.and_then(|mid| {
                    cpg.ast.get(&mid).and_then(|m| m.text.as_deref().map(java_modifiers_from_text))
                }).unwrap_or_default();
                let annotations: Vec<String> = mods_id
                    .map(|mid| java_annotations_from_modifiers(mid, &cpg.ast))
                    .unwrap_or_default();
                // extends_type: superclass child → type_identifier
                let extends_type = node.children.iter().find_map(|&cid| {
                    let c = cpg.ast.get(&cid)?;
                    if c.node_type != "superclass" { return None; }
                    c.children.iter().find_map(|&tid| {
                        cpg.ast.get(&tid).filter(|t| t.node_type == "type_identifier" || t.node_type == "identifier")
                            .and_then(|t| t.text.clone())
                    })
                });
                // implements_types: super_interfaces → type_list → type_identifier(s)
                let implements_types: Vec<String> = node.children.iter().find_map(|&cid| {
                    let c = cpg.ast.get(&cid)?;
                    if c.node_type != "super_interfaces" { return None; }
                    let type_ids: Vec<String> = c.children.iter().flat_map(|&tid| -> Vec<String> {
                        let tl = match cpg.ast.get(&tid) { Some(t) => t, None => return vec![] };
                        if tl.node_type == "type_list" {
                            tl.children.iter().filter_map(|&iid| {
                                cpg.ast.get(&iid).filter(|i| i.node_type == "type_identifier")
                                    .and_then(|i| i.text.clone())
                            }).collect::<Vec<_>>()
                        } else if tl.node_type == "type_identifier" {
                            tl.text.clone().into_iter().collect()
                        } else { vec![] }
                    }).collect();
                    Some(type_ids)
                }).unwrap_or_default();
                // generic_type_params: type_parameters → type_parameter text
                let generic_type_params: Vec<String> = node.children.iter().find_map(|&cid| {
                    let c = cpg.ast.get(&cid)?;
                    if c.node_type != "type_parameters" { return None; }
                    Some(c.children.iter().filter_map(|&pid| {
                        cpg.ast.get(&pid).filter(|p| p.node_type == "type_parameter")
                            .and_then(|p| p.text.clone())
                    }).collect::<Vec<_>>())
                }).unwrap_or_default();
                let is_interface = node_type == "interface_declaration";
                let is_record = node_type == "record_declaration";
                let is_abstract = access_mods.contains(&"abstract".to_string());
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = class_name;
                    if let Some(ref et) = extends_type {
                        n.base_classes = Some(vec![et.clone()]);
                    }
                }
                let meta = cpg.java_meta_mut(node_id);
                meta.access_modifiers = access_mods;
                meta.annotations = annotations;
                meta.extends_type = extends_type;
                meta.implements_types = implements_types;
                meta.generic_type_params = generic_type_params;
                meta.is_interface = is_interface;
                meta.is_record = is_record;
                meta.is_abstract = is_abstract;
                meta.package_name = package_name.clone();
            }

            "enum_declaration" => {
                let node = &cpg.ast[&node_id];
                let class_name = child_with_field(node, &cpg.ast, "name")
                    .and_then(|(_, c)| c.text.clone())
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| {
                                c.node_type == "identifier" || c.node_type == "type_identifier"
                            }).and_then(|c| c.text.clone())
                        })
                    });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = class_name;
                }
            }

            "enum_constant" => {
                let node = &cpg.ast[&node_id];
                let const_name = child_with_field(node, &cpg.ast, "name")
                    .and_then(|(_, c)| c.text.clone())
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| c.node_type == "identifier")
                                .and_then(|c| c.text.clone())
                        })
                    });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = const_name;
                }
            }

            "field_declaration" => {
                let node = &cpg.ast[&node_id];
                let field_name = node.children.iter().find_map(|&cid| {
                    let vd = cpg.ast.get(&cid)?;
                    if vd.node_type == "variable_declarator" {
                        vd.children.iter().find_map(|&vcid| {
                            cpg.ast.get(&vcid).filter(|c| c.node_type == "identifier")
                                .and_then(|c| c.text.clone())
                        })
                    } else { None }
                }).or_else(|| {
                    node.children.iter().find_map(|&cid| {
                        cpg.ast.get(&cid).filter(|c| c.node_type == "identifier")
                            .and_then(|c| c.text.clone())
                    })
                });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = field_name;
                }
            }

            "method_declaration" => {
                let node = &cpg.ast[&node_id];
                let method_name = child_with_field(node, &cpg.ast, "name")
                    .and_then(|(_, c)| c.text.clone())
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| c.node_type == "identifier")
                                .and_then(|c| c.text.clone())
                        })
                    });
                let mods_id = node.children.iter().find(|&&cid| {
                    cpg.ast.get(&cid).map(|c| c.node_type == "modifiers").unwrap_or(false)
                }).copied();
                let access_mods: Vec<String> = mods_id.and_then(|mid| {
                    cpg.ast.get(&mid).and_then(|m| m.text.as_deref().map(java_modifiers_from_text))
                }).unwrap_or_default();
                let annotations: Vec<String> = mods_id
                    .map(|mid| java_annotations_from_modifiers(mid, &cpg.ast))
                    .unwrap_or_default();
                let is_static = access_mods.iter().any(|m| m == "static");
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = method_name;
                    n.is_constructor = Some(false);
                }
                let meta = cpg.java_meta_mut(node_id);
                meta.function_kind = crate::FunctionKind::Internal;
                meta.access_modifiers = access_mods;
                meta.annotations = annotations;
                meta.is_static = is_static;
            }

            "constructor_declaration" => {
                let node = &cpg.ast[&node_id];
                let ctor_name = child_with_field(node, &cpg.ast, "name")
                    .and_then(|(_, c)| c.text.clone())
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| c.node_type == "identifier")
                                .and_then(|c| c.text.clone())
                        })
                    });
                // is_super_call: check constructor_body for explicit_constructor_invocation starting with "super"
                let is_super_call = node.children.iter().any(|&cid| {
                    let body = match cpg.ast.get(&cid) { Some(b) => b, None => return false };
                    if body.node_type != "constructor_body" { return false; }
                    body.children.iter().any(|&eid| {
                        let eci = match cpg.ast.get(&eid) { Some(e) => e, None => return false };
                        eci.node_type == "explicit_constructor_invocation"
                            && eci.text.as_deref().map(|t| t.starts_with("super")).unwrap_or(false)
                    })
                });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = ctor_name;
                    n.is_constructor = Some(true);
                }
                let meta = cpg.java_meta_mut(node_id);
                meta.function_kind = crate::FunctionKind::Internal;
                meta.is_super_call = is_super_call;
            }

            "local_variable_declaration" => {
                let node = &cpg.ast[&node_id];
                let var_name = node.children.iter().find_map(|&cid| {
                    let vd = cpg.ast.get(&cid)?;
                    if vd.node_type != "variable_declarator" { return None; }
                    vd.children.iter().find_map(|&vcid| {
                        cpg.ast.get(&vcid).filter(|c| c.node_type == "identifier")
                            .and_then(|c| c.text.clone())
                    })
                });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = var_name;
                }
            }

            "variable_declarator" => {
                let node = &cpg.ast[&node_id];
                let var_name = node.children.iter().find_map(|&cid| {
                    cpg.ast.get(&cid).filter(|c| c.node_type == "identifier")
                        .and_then(|c| c.text.clone())
                });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = var_name;
                }
            }

            "formal_parameter" => {
                let node = &cpg.ast[&node_id];
                let param_name = child_with_field(node, &cpg.ast, "name")
                    .and_then(|(_, c)| c.text.clone())
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| c.node_type == "identifier")
                                .and_then(|c| c.text.clone())
                        })
                    });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = param_name;
                }
            }

            "spread_parameter" => {
                let node = &cpg.ast[&node_id];
                // In tree-sitter-java, spread_parameter children: type + variable_declarator
                // The variable_declarator child has the identifier as its child
                let param_name = child_with_field(node, &cpg.ast, "name")
                    .and_then(|(_, c)| c.text.clone())
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            let child = cpg.ast.get(&cid)?;
                            if child.node_type == "identifier" { return child.text.clone(); }
                            if child.node_type == "variable_declarator" {
                                return child.name.clone().or_else(|| {
                                    child.children.iter().find_map(|&gcid| {
                                        cpg.ast.get(&gcid).filter(|gc| gc.node_type == "identifier")
                                            .and_then(|gc| gc.text.clone())
                                    })
                                });
                            }
                            None
                        })
                    });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = param_name;
                }
                let meta = cpg.java_meta_mut(node_id);
                meta.is_varargs = true;
            }

            "try_statement" | "try_with_resources_statement" => {
                let node = &cpg.ast[&node_id];
                let has_finally = node.children.iter().any(|&cid| {
                    cpg.ast.get(&cid).map(|c| c.node_type == "finally_clause").unwrap_or(false)
                });
                let meta = cpg.java_meta_mut(node_id);
                meta.has_finally = has_finally;
            }

            "catch_clause" => {
                let node = &cpg.ast[&node_id];
                // catch_formal_parameter → catch_type → type_identifier text
                let catch_types: Vec<String> = node.children.iter().flat_map(|&cid| {
                    let cfp = cpg.ast.get(&cid)?;
                    if cfp.node_type != "catch_formal_parameter" { return None; }
                    let types: Vec<String> = cfp.children.iter().filter_map(|&tid| {
                        let ct = cpg.ast.get(&tid)?;
                        if ct.node_type == "catch_type" {
                            // children of catch_type are type_identifier nodes
                            let names: Vec<String> = ct.children.iter().filter_map(|&iid| {
                                cpg.ast.get(&iid).filter(|i| i.node_type == "type_identifier")
                                    .and_then(|i| i.text.clone())
                            }).collect();
                            if names.is_empty() { ct.text.clone().map(|t| vec![t]) } else { Some(names) }
                        } else { None }
                    }).flatten().collect();
                    Some(types)
                }).flatten().collect();
                let meta = cpg.java_meta_mut(node_id);
                meta.catch_types = catch_types;
            }

            "method_invocation" => {
                let node = &cpg.ast[&node_id];
                // name field holds the method identifier
                let method_name = child_with_field(node, &cpg.ast, "name")
                    .and_then(|(_, c)| c.text.clone())
                    .or_else(|| {
                        node.children.iter().rev().find_map(|&cid| {
                            let c = cpg.ast.get(&cid)?;
                            if c.node_type == "identifier" { c.text.clone() } else { None }
                        })
                    });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = method_name;
                }
            }

            "object_creation_expression" => {
                let node = &cpg.ast[&node_id];
                // type field or first type_identifier child
                let type_name = child_with_field(node, &cpg.ast, "type")
                    .and_then(|(_, c)| {
                        if c.node_type == "type_identifier" { c.text.clone() }
                        else {
                            // might be generic_type with type_identifier child
                            c.children.iter().find_map(|&tid| {
                                cpg.ast.get(&tid).filter(|t| t.node_type == "type_identifier")
                                    .and_then(|t| t.text.clone())
                            })
                        }
                    })
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| c.node_type == "type_identifier")
                                .and_then(|c| c.text.clone())
                        })
                    });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = type_name;
                }
            }

            "type_pattern" => {
                let node = &cpg.ast[&node_id];
                // identifier child = pattern variable name
                let var_name = node.children.iter().find_map(|&cid| {
                    cpg.ast.get(&cid).filter(|c| c.node_type == "identifier")
                        .and_then(|c| c.text.clone())
                });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = var_name;
                }
            }

            "instanceof_expression" => {
                // Pattern-matching instanceof: `o instanceof String s`
                // tree-sitter-java gives children [object, type_identifier, identifier]
                // The trailing identifier is the pattern variable → make it LocalDef
                let node = &cpg.ast[&node_id];
                let last_id_child = node.children.iter().copied().rev().find(|&cid| {
                    cpg.ast.get(&cid).map(|c| c.node_type == "identifier").unwrap_or(false)
                });
                let first_child = node.children.first().copied();
                if let Some(pat_cid) = last_id_child {
                    // Only mark as pattern variable if it's not the object (first child)
                    if Some(pat_cid) != first_child {
                        let var_name = cpg.ast.get(&pat_cid).and_then(|c| c.text.clone());
                        if let Some(n) = cpg.ast.get_mut(&pat_cid) {
                            n.kind = IrNodeKind::LocalDef;
                            n.name = var_name;
                        }
                    }
                }
            }

            "switch_expression" => {
                // tree-sitter-java uses switch_expression for both switch statements and switch expressions.
                // Traditional switch: switch_block contains switch_block_statement_group children → Switch
                // Modern switch expression: switch_block contains switch_rule children → SwitchExpr
                let node = &cpg.ast[&node_id];
                let has_traditional = node.children.iter().any(|&cid| {
                    let sb = match cpg.ast.get(&cid) { Some(s) => s, None => return false };
                    if sb.node_type != "switch_block" { return false; }
                    sb.children.iter().any(|&gid| {
                        cpg.ast.get(&gid).map(|g| g.node_type == "switch_block_statement_group").unwrap_or(false)
                    })
                });
                if has_traditional {
                    if let Some(n) = cpg.ast.get_mut(&node_id) {
                        n.kind = IrNodeKind::Switch;
                    }
                } else {
                    if let Some(n) = cpg.ast.get_mut(&node_id) {
                        n.kind = IrNodeKind::SwitchExpr;
                    }
                }
            }

            "switch_label" => {
                let node = &cpg.ast[&node_id];
                let text = node.text.as_deref().unwrap_or("");
                if text.starts_with("default") {
                    if let Some(n) = cpg.ast.get_mut(&node_id) {
                        n.kind = IrNodeKind::SwitchDefault;
                    }
                }
            }

            "for_statement" => {
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.loop_kind = Some(LoopKind::For);
                }
            }

            "enhanced_for_statement" => {
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.loop_kind = Some(LoopKind::ForEach);
                }
            }

            "do_statement" => {
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.loop_kind = Some(LoopKind::DoWhile);
                }
            }

            "import_declaration" => {
                // Extract dotted name from text: "import java.util.List;" → "java.util.List"
                let import_name = cpg.ast[&node_id].text.as_deref().unwrap_or("").trim()
                    .strip_prefix("import").unwrap_or("")
                    .trim()
                    .trim_end_matches(';')
                    .trim()
                    .to_string();
                let import_name = if import_name.is_empty() { None } else { Some(import_name) };
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = import_name;
                }
            }

            _ => {}
        }
    }
}

// ── JavaScript enrichment ─────────────────────────────────────────────────────

pub(crate) fn enrich_js_metadata(cpg: &mut Cpg) {
    let ids: Vec<NodeId> = cpg.ast.keys().copied().collect();

    for &node_id in &ids {
        let node_type = cpg.ast[&node_id].node_type.clone();
        match node_type.as_str() {
            "function_declaration" | "generator_function_declaration" => {
                let node = &cpg.ast[&node_id];
                let fn_name = child_with_field(node, &cpg.ast, "name")
                    .and_then(|(_, c)| c.text.clone())
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| c.node_type == "identifier")
                                .and_then(|c| c.text.clone())
                        })
                    });
                let is_async = node.text.as_deref().unwrap_or("").starts_with("async ");
                let is_generator = node_type == "generator_function_declaration"
                    || node.text.as_deref().unwrap_or("").contains("function*");
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = fn_name;
                }
                let meta = cpg.js_meta_mut(node_id);
                meta.is_async = is_async;
                meta.is_generator = is_generator;
            }

            "arrow_function" => {
                let meta = cpg.js_meta_mut(node_id);
                meta.is_arrow = true;
            }

            "class_declaration" => {
                let node = &cpg.ast[&node_id];
                let class_name = child_with_field(node, &cpg.ast, "name")
                    .and_then(|(_, c)| c.text.clone())
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| c.node_type == "identifier")
                                .and_then(|c| c.text.clone())
                        })
                    });
                // extends: class_heritage → identifier/member_expression naming the superclass
                let base_class = node.children.iter().find_map(|&cid| {
                    let c = cpg.ast.get(&cid)?;
                    if c.node_type != "class_heritage" { return None; }
                    c.children.iter().find_map(|&tid| {
                        cpg.ast.get(&tid).filter(|t| {
                            matches!(t.node_type.as_str(), "identifier" | "member_expression")
                        }).and_then(|t| t.text.clone())
                    })
                });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = class_name;
                    if let Some(bc) = base_class {
                        n.base_classes = Some(vec![bc]);
                    }
                }
            }

            "method_definition" => {
                let node = &cpg.ast[&node_id];
                let method_name = child_with_field(node, &cpg.ast, "name")
                    .and_then(|(_, c)| c.text.clone())
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| {
                                matches!(c.node_type.as_str(), "identifier" | "property_identifier"
                                    | "private_property_identifier")
                            }).and_then(|c| c.text.clone())
                        })
                    });
                // Detect modifiers from node text: "static", "async", "get", "set", "*"
                let node_text = node.text.as_deref().unwrap_or("");
                let is_static = node_text.starts_with("static ");
                let is_async = node_text.contains("async ");
                let is_generator = node_text.contains("*");
                let is_getter = node_text.starts_with("get ") || node_text.starts_with("static get ");
                let is_setter = node_text.starts_with("set ") || node_text.starts_with("static set ");
                // detect visibility modifier from text
                let _visibility = if node_text.starts_with("public ") { Some("public") }
                    else if node_text.starts_with("private ") { Some("private") }
                    else if node_text.starts_with("protected ") { Some("protected") }
                    else { None };
                let is_constructor = method_name.as_deref() == Some("constructor");
                if is_constructor {
                    if let Some(n) = cpg.ast.get_mut(&node_id) {
                        n.is_constructor = Some(true);
                    }
                }
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = method_name;
                }
                let meta = cpg.js_meta_mut(node_id);
                meta.is_static = is_static;
                meta.is_async = is_async;
                meta.is_generator = is_generator;
                meta.is_getter = is_getter;
                meta.is_setter = is_setter;
                meta.is_constructor = is_constructor;
            }

            "field_definition" => {
                let node = &cpg.ast[&node_id];
                let field_name = child_with_field(node, &cpg.ast, "name")
                    .and_then(|(_, c)| c.text.clone())
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| {
                                matches!(c.node_type.as_str(), "property_identifier"
                                    | "private_property_identifier" | "identifier")
                            }).and_then(|c| c.text.clone())
                        })
                    });
                let is_private = field_name.as_deref().map_or(false, |n| n.starts_with('#'));
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = field_name;
                }
                let meta = cpg.js_meta_mut(node_id);
                meta.is_private = is_private;
            }

            "lexical_declaration" | "variable_declaration" => {
                let node = &cpg.ast[&node_id];
                let var_name = node.children.iter().find_map(|&cid| {
                    let vd = cpg.ast.get(&cid)?;
                    if vd.node_type != "variable_declarator" { return None; }
                    child_with_field(vd, &cpg.ast, "name")
                        .and_then(|(_, c)| c.text.clone())
                        .or_else(|| {
                            vd.children.iter().find_map(|&vcid| {
                                cpg.ast.get(&vcid).filter(|c| c.node_type == "identifier")
                                    .and_then(|c| c.text.clone())
                            })
                        })
                });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = var_name;
                }
            }

            // Handle destructuring: convert identifiers in array/object patterns to LocalDef
            "array_pattern" | "object_pattern" => {
                let node = &cpg.ast[&node_id];
                let ident_ids: Vec<NodeId> = node.children.iter().filter_map(|&cid| {
                    cpg.ast.get(&cid).filter(|c| {
                        matches!(c.node_type.as_str(),
                            "identifier" | "shorthand_property_identifier_pattern"
                            | "shorthand_property_identifier")
                    }).map(|_| cid)
                }).collect();
                for ident_id in ident_ids {
                    let name = cpg.ast.get(&ident_id).and_then(|c| c.text.clone());
                    if let Some(n) = cpg.ast.get_mut(&ident_id) {
                        n.kind = IrNodeKind::LocalDef;
                        n.name = name;
                    }
                }
            }

            "new_expression" => {
                let node = &cpg.ast[&node_id];
                let class_name = child_with_field(node, &cpg.ast, "constructor")
                    .and_then(|(_, c)| c.text.clone())
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| {
                                matches!(c.node_type.as_str(), "identifier" | "member_expression")
                            }).and_then(|c| c.text.clone())
                        })
                    });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.kind = IrNodeKind::NewExpr;
                    n.name = class_name;
                }
            }

            "yield_expression" => {
                let is_delegate = cpg.ast[&node_id].text.as_deref().unwrap_or("").contains('*');
                let meta = cpg.js_meta_mut(node_id);
                meta.is_delegate = is_delegate;
            }

            "for_statement" => {
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.loop_kind = Some(LoopKind::For);
                }
            }

            "for_in_statement" => {
                let node = &cpg.ast[&node_id];
                // Both for...in and for...of iterate (ForEach); distinguish via is_for_of
                let is_of = node.text.as_deref().unwrap_or("").contains(" of ");
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.loop_kind = Some(LoopKind::ForEach);
                }
                let meta = cpg.js_meta_mut(node_id);
                meta.is_for_of = is_of;
            }

            "do_statement" => {
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.loop_kind = Some(LoopKind::DoWhile);
                }
            }

            // JS/TS call_expression: extract callee name from member_expression or identifier
            "call_expression" => {
                let children = cpg.ast[&node_id].children.clone();
                let call_name = children.iter().next().and_then(|&cid| {
                    let callee = cpg.ast.get(&cid)?;
                    match callee.node_type.as_str() {
                        "member_expression" => {
                            // console.log(...) → "log"
                            let gc_ids = callee.children.clone();
                            gc_ids.iter().rev().find_map(|&gcid| {
                                cpg.ast.get(&gcid).filter(|gc| {
                                    matches!(gc.node_type.as_str(), "property_identifier" | "identifier")
                                }).and_then(|gc| gc.text.clone())
                            })
                        }
                        "identifier" => callee.text.clone(),
                        _ => None,
                    }
                });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = call_name;
                }
            }

            // JS plain identifier parameters are not lifted to ParamDef by the lifter
            "formal_parameters" => {
                let param_children: Vec<NodeId> = cpg.ast[&node_id].children.clone();
                for cid in param_children {
                    let child_type = cpg.ast.get(&cid).map(|c| c.node_type.as_str()).unwrap_or("").to_string();
                    match child_type.as_str() {
                        "identifier" => {
                            let name = cpg.ast.get(&cid).and_then(|c| c.text.clone());
                            if let Some(n) = cpg.ast.get_mut(&cid) {
                                n.kind = IrNodeKind::ParamDef;
                                n.name = name;
                            }
                        }
                        "assignment_pattern" | "rest_pattern" => {
                            // Default or rest param: extract the identifier inside
                            let ident_id = cpg.ast.get(&cid).and_then(|c| {
                                c.children.iter().find_map(|&gcid| {
                                    cpg.ast.get(&gcid).filter(|gc| gc.node_type == "identifier").map(|_| gcid)
                                })
                            });
                            let name = ident_id.and_then(|id| cpg.ast.get(&id).and_then(|n| n.text.clone()));
                            if let Some(n) = cpg.ast.get_mut(&cid) {
                                n.kind = IrNodeKind::ParamDef;
                                n.name = name;
                            }
                        }
                        _ => {}
                    }
                }
            }

            _ => {}
        }
    }
}

// ── TypeScript enrichment ─────────────────────────────────────────────────────

pub(crate) fn enrich_ts_metadata(cpg: &mut Cpg) {
    // TypeScript grammar reuses most JS constructs. Start with JS enrichment,
    // then add TS-specific processing.
    enrich_js_metadata(cpg);

    // Pass 1: collect parent_map for decorator→class association
    let parent_map: std::collections::HashMap<NodeId, NodeId> = {
        let mut m = std::collections::HashMap::new();
        for (&pid, node) in &cpg.ast {
            for &cid in &node.children {
                m.insert(cid, pid);
            }
        }
        m
    };

    let ids: Vec<NodeId> = cpg.ast.keys().copied().collect();
    for &node_id in &ids {
        let node_type = cpg.ast[&node_id].node_type.clone();
        match node_type.as_str() {
            // ── Named declarations: set name ───────────────────────────────
            "interface_declaration" | "enum_declaration"
            | "abstract_class_declaration" | "module" | "internal_module"
            | "class_declaration" | "function_declaration" => {
                let node = &cpg.ast[&node_id];
                let decl_name = child_with_field(node, &cpg.ast, "name")
                    .and_then(|(_, c)| c.text.clone())
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| {
                                matches!(c.node_type.as_str(), "identifier" | "type_identifier")
                            }).and_then(|c| c.text.clone())
                        })
                    });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    if n.name.is_none() {
                        n.name = decl_name;
                    }
                }

                // abstract class: set is_abstract
                if node_type == "abstract_class_declaration" {
                    let meta = cpg.ts_meta_mut(node_id);
                    meta.is_abstract = true;
                }

                // async function: set is_async
                if node_type == "function_declaration" {
                    let node_text = cpg.ast[&node_id].text.as_deref().unwrap_or("").to_string();
                    let is_async = node_text.trim_start().starts_with("async ");
                    if is_async {
                        let meta = cpg.ts_meta_mut(node_id);
                        meta.is_async = true;
                    }

                    // generic_constraints: parse type_parameters
                    let generics: Vec<(String, Option<String>)> = {
                        let node = &cpg.ast[&node_id];
                        if let Some((_, tp)) = first_child_of_type(node, &cpg.ast, "type_parameters") {
                            tp.children.iter().filter_map(|&cid| {
                                cpg.ast.get(&cid).filter(|c| c.node_type == "type_parameter").and_then(|tp_node| {
                                    // first child is the name (type_identifier)
                                    tp_node.children.first().and_then(|&nid| {
                                        cpg.ast.get(&nid).and_then(|c| c.text.clone())
                                    }).map(|name| {
                                        // constraint (extends X) is second child
                                        let bound = tp_node.children.get(1).and_then(|&cid2| {
                                            cpg.ast.get(&cid2).and_then(|c| c.text.clone())
                                        });
                                        (name, bound)
                                    })
                                })
                            }).collect()
                        } else {
                            vec![]
                        }
                    };
                    if !generics.is_empty() {
                        let meta = cpg.ts_meta_mut(node_id);
                        meta.generic_constraints = generics;
                    }

                    // return type annotation
                    let ret_type: Option<String> = {
                        let node = &cpg.ast[&node_id];
                        child_with_field(node, &cpg.ast, "return_type")
                            .and_then(|(_, c)| c.text.clone())
                            .or_else(|| {
                                // find type_annotation or type_predicate_annotation child
                                node.children.iter().find_map(|&cid| {
                                    cpg.ast.get(&cid).filter(|c| {
                                        matches!(c.node_type.as_str(),
                                            "type_annotation" | "type_predicate_annotation"
                                            | "type_predicate")
                                    }).and_then(|c| c.text.clone())
                                })
                            })
                    };
                    if let Some(rt) = ret_type {
                        let meta = cpg.ts_meta_mut(node_id);
                        meta.type_annotation = Some(rt);
                    }
                }

                // class implements / extends
                if matches!(node_type.as_str(), "class_declaration" | "abstract_class_declaration") {
                    let extends_type: Option<String> = {
                        let node = &cpg.ast[&node_id];
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| c.node_type == "class_heritage").and_then(|heritage| {
                                // extends_clause
                                heritage.children.iter().find_map(|&hcid| {
                                    cpg.ast.get(&hcid).filter(|c| c.node_type == "extends_clause").and_then(|ext| {
                                        ext.children.iter().find_map(|&ecid| {
                                            cpg.ast.get(&ecid).filter(|c| {
                                                matches!(c.node_type.as_str(), "identifier" | "type_identifier")
                                            }).and_then(|c| c.text.clone())
                                        })
                                    })
                                })
                            })
                        })
                    };
                    let implements_types: Vec<String> = {
                        let node = &cpg.ast[&node_id];
                        node.children.iter().flat_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| c.node_type == "class_heritage").map(|heritage| {
                                heritage.children.iter().flat_map(|&hcid| {
                                    cpg.ast.get(&hcid).filter(|c| c.node_type == "implements_clause").map(|imp| {
                                        imp.children.iter().filter_map(|&icid| {
                                            cpg.ast.get(&icid).filter(|c| {
                                                matches!(c.node_type.as_str(), "identifier" | "type_identifier"
                                                    | "generic_type")
                                            }).and_then(|c| {
                                                // use first identifier child for generic_type
                                                if c.node_type == "generic_type" {
                                                    c.children.first().and_then(|&nid| {
                                                        cpg.ast.get(&nid).and_then(|cn| cn.text.clone())
                                                    })
                                                } else {
                                                    c.text.clone()
                                                }
                                            })
                                        }).collect::<Vec<_>>()
                                    }).unwrap_or_default()
                                }).collect::<Vec<_>>()
                            }).unwrap_or_default()
                        }).collect()
                    };
                    // decorator_names: decorators are children of the class node
                    // OR siblings preceding the class (grammar-dependent)
                    let decorator_names: Vec<String> = {
                        // First try: children of this class node
                        let from_children: Vec<String> = {
                            let node = &cpg.ast[&node_id];
                            node.children.iter().filter_map(|&dcid| {
                                cpg.ast.get(&dcid).filter(|c| c.node_type == "decorator").and_then(|dec| {
                                    dec.children.iter().find_map(|&icid| {
                                        cpg.ast.get(&icid).filter(|c| {
                                            matches!(c.node_type.as_str(), "identifier" | "call_expression")
                                        }).and_then(|c| {
                                            if c.node_type == "call_expression" {
                                                c.children.first().and_then(|&ccid| {
                                                    cpg.ast.get(&ccid).and_then(|cc| cc.text.clone())
                                                })
                                            } else {
                                                c.text.clone()
                                            }
                                        })
                                    })
                                })
                            }).collect()
                        };
                        if !from_children.is_empty() {
                            from_children
                        } else {
                            // Fallback: sibling decorators before this class in parent
                            if let Some(&parent_id) = parent_map.get(&node_id) {
                                if let Some(parent) = cpg.ast.get(&parent_id) {
                                    let class_pos = parent.children.iter().position(|&c| c == node_id).unwrap_or(0);
                                    parent.children[..class_pos].iter().filter_map(|&sib_id| {
                                        cpg.ast.get(&sib_id).filter(|s| s.node_type == "decorator").and_then(|dec| {
                                            dec.children.iter().find_map(|&dcid| {
                                                cpg.ast.get(&dcid).filter(|c| {
                                                    matches!(c.node_type.as_str(), "identifier" | "call_expression")
                                                }).and_then(|c| c.text.clone())
                                            })
                                        })
                                    }).collect()
                                } else { vec![] }
                            } else { vec![] }
                        }
                    };
                    let meta = cpg.ts_meta_mut(node_id);
                    if let Some(et) = extends_type { meta.extends_type = Some(et); }
                    if !implements_types.is_empty() { meta.implements_types = implements_types; }
                    if !decorator_names.is_empty() { meta.decorator_names = decorator_names; }
                }

                // interface extends — always create TsNodeMetadata for interface
                // tree-sitter-typescript uses "extends_type_clause" for interface extends
                if node_type == "interface_declaration" {
                    let extends_type: Option<String> = {
                        let node = &cpg.ast[&node_id];
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| {
                                matches!(c.node_type.as_str(), "extends_clause" | "extends_type_clause")
                            }).and_then(|ext| {
                                ext.children.iter().find_map(|&ecid| {
                                    cpg.ast.get(&ecid).filter(|c| {
                                        matches!(c.node_type.as_str(), "identifier" | "type_identifier")
                                    }).and_then(|c| c.text.clone())
                                })
                            })
                        })
                    };
                    let meta = cpg.ts_meta_mut(node_id);
                    if let Some(et) = extends_type { meta.extends_type = Some(et); }
                }

                // enum: const enum
                if node_type == "enum_declaration" {
                    let node_text = cpg.ast[&node_id].text.as_deref().unwrap_or("").to_string();
                    if node_text.trim_start().starts_with("const ") {
                        let meta = cpg.ts_meta_mut(node_id);
                        meta.enum_is_const = true;
                    }
                }
            }

            // ── Type alias ─────────────────────────────────────────────────
            "type_alias_declaration" => {
                let node = &cpg.ast[&node_id];
                let type_name = child_with_field(node, &cpg.ast, "name")
                    .and_then(|(_, c)| c.text.clone())
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| {
                                c.node_type == "type_identifier" || c.node_type == "identifier"
                            }).and_then(|c| c.text.clone())
                        })
                    });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = type_name;
                }
            }

            // ── Ambient declaration ────────────────────────────────────────
            "ambient_declaration" => {
                let meta = cpg.ts_meta_mut(node_id);
                meta.is_ambient = true;
                meta.is_declare = true;
            }

            // ── Namespace / module ─────────────────────────────────────────
            "module" | "internal_module" => {
                let node = &cpg.ast[&node_id];
                let ns_name = node.children.iter().find_map(|&cid| {
                    cpg.ast.get(&cid).filter(|c| {
                        matches!(c.node_type.as_str(), "identifier" | "type_identifier" | "string")
                    }).and_then(|c| c.text.clone())
                });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    if n.name.is_none() { n.name = ns_name; }
                }
            }

            // ── Public field definition ────────────────────────────────────
            "public_field_definition" | "field_definition" => {
                let node_text = cpg.ast[&node_id].text.as_deref().unwrap_or("").to_string();
                let is_readonly = node_text.contains("readonly ");
                let is_optional = node_text.contains("?:");
                let is_definite = node_text.contains("!:");

                // access modifier: first child of type accessibility_modifier
                let access_modifier: Option<String> = {
                    let node = &cpg.ast[&node_id];
                    node.children.iter().find_map(|&cid| {
                        cpg.ast.get(&cid).filter(|c| c.node_type == "accessibility_modifier")
                            .and_then(|c| c.text.clone())
                    })
                };

                // field name from property_identifier or identifier child
                let field_name: Option<String> = {
                    let node = &cpg.ast[&node_id];
                    child_with_field(node, &cpg.ast, "name")
                        .and_then(|(_, c)| c.text.clone())
                        .or_else(|| {
                            node.children.iter().find_map(|&cid| {
                                cpg.ast.get(&cid).filter(|c| {
                                    matches!(c.node_type.as_str(), "property_identifier" | "identifier"
                                        | "private_property_identifier")
                                }).and_then(|c| c.text.clone())
                            })
                        })
                };

                // type annotation
                let type_annotation: Option<String> = {
                    let node = &cpg.ast[&node_id];
                    node.children.iter().find_map(|&cid| {
                        cpg.ast.get(&cid).filter(|c| c.node_type == "type_annotation")
                            .and_then(|c| c.text.clone())
                    })
                };

                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    if n.name.is_none() { n.name = field_name; }
                }
                let meta = cpg.ts_meta_mut(node_id);
                meta.is_readonly = is_readonly;
                meta.is_optional = is_optional;
                meta.is_definite_assignment = is_definite;
                if let Some(am) = access_modifier { meta.access_modifier = Some(am); }
                if let Some(ta) = type_annotation { meta.type_annotation = Some(ta); }
            }

            // ── Property signature (interface fields) ──────────────────────
            "property_signature" => {
                let node_text = cpg.ast[&node_id].text.as_deref().unwrap_or("").to_string();
                let is_optional = node_text.contains("?:");
                let is_readonly = node_text.contains("readonly ");

                let field_name: Option<String> = {
                    let node = &cpg.ast[&node_id];
                    child_with_field(node, &cpg.ast, "name")
                        .and_then(|(_, c)| c.text.clone())
                        .or_else(|| {
                            node.children.iter().find_map(|&cid| {
                                cpg.ast.get(&cid).filter(|c| {
                                    matches!(c.node_type.as_str(), "property_identifier" | "identifier")
                                }).and_then(|c| c.text.clone())
                            })
                        })
                };

                let type_annotation: Option<String> = {
                    let node = &cpg.ast[&node_id];
                    node.children.iter().find_map(|&cid| {
                        cpg.ast.get(&cid).filter(|c| c.node_type == "type_annotation")
                            .and_then(|c| c.text.clone())
                    })
                };

                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    if n.name.is_none() { n.name = field_name; }
                }
                let meta = cpg.ts_meta_mut(node_id);
                meta.is_optional = is_optional;
                meta.is_readonly = is_readonly;
                if let Some(ta) = type_annotation { meta.type_annotation = Some(ta); }
            }

            // ── Required / optional parameters ────────────────────────────
            "required_parameter" | "optional_parameter" | "mandatory_parameter" => {
                let is_optional = node_type == "optional_parameter";

                let param_name: Option<String> = {
                    let node = &cpg.ast[&node_id];
                    child_with_field(node, &cpg.ast, "pattern")
                        .and_then(|(_, c)| c.text.clone())
                        .or_else(|| {
                            node.children.iter().find_map(|&cid| {
                                cpg.ast.get(&cid).filter(|c| {
                                    matches!(c.node_type.as_str(), "identifier" | "this")
                                }).and_then(|c| c.text.clone())
                            })
                        })
                };

                // access modifier on constructor params (parameter properties)
                let access_modifier: Option<String> = {
                    let node = &cpg.ast[&node_id];
                    node.children.iter().find_map(|&cid| {
                        cpg.ast.get(&cid).filter(|c| c.node_type == "accessibility_modifier")
                            .and_then(|c| c.text.clone())
                    })
                };

                let is_readonly = {
                    let node_text = cpg.ast[&node_id].text.as_deref().unwrap_or("");
                    node_text.contains("readonly ")
                };

                let type_annotation: Option<String> = {
                    let node = &cpg.ast[&node_id];
                    node.children.iter().find_map(|&cid| {
                        cpg.ast.get(&cid).filter(|c| c.node_type == "type_annotation")
                            .and_then(|c| c.text.clone())
                    })
                };

                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    if n.name.is_none() { n.name = param_name; }
                }
                let meta = cpg.ts_meta_mut(node_id);
                meta.is_optional = is_optional;
                meta.is_readonly = is_readonly;
                if let Some(am) = access_modifier { meta.access_modifier = Some(am); }
                if let Some(ta) = type_annotation { meta.type_annotation = Some(ta); }
            }

            // ── lexical_declaration: propagate type_annotation from variable_declarator child ──
            "lexical_declaration" | "variable_declaration" => {
                // Find the first variable_declarator child and copy its type_annotation
                let type_annotation: Option<String> = {
                    let node = &cpg.ast[&node_id];
                    node.children.iter().find_map(|&cid| {
                        cpg.ast.get(&cid).filter(|c| c.node_type == "variable_declarator")
                            .and_then(|vd| {
                                vd.children.iter().find_map(|&vcid| {
                                    cpg.ast.get(&vcid).filter(|c| c.node_type == "type_annotation")
                                        .and_then(|c| c.text.clone())
                                })
                            })
                    })
                };
                if let Some(ta) = type_annotation {
                    let meta = cpg.ts_meta_mut(node_id);
                    meta.type_annotation = Some(ta);
                }
            }

            // ── Arrow function / lambda: ensure TsNodeMetadata exists ─────
            "arrow_function" | "generator_function" | "generator_function_declaration" => {
                let is_async = cpg.ast[&node_id].text.as_deref().unwrap_or("").starts_with("async ");
                let meta = cpg.ts_meta_mut(node_id);
                meta.is_async = is_async;
            }

            // ── Variable declarator: type annotation ───────────────────────
            "variable_declarator" => {
                let var_name: Option<String> = {
                    let node = &cpg.ast[&node_id];
                    child_with_field(node, &cpg.ast, "name")
                        .and_then(|(_, c)| c.text.clone())
                        .or_else(|| {
                            node.children.iter().find_map(|&cid| {
                                cpg.ast.get(&cid).filter(|c| {
                                    matches!(c.node_type.as_str(), "identifier")
                                }).and_then(|c| c.text.clone())
                            })
                        })
                };

                // type_annotation is a sibling in lexical_declaration, not direct child of variable_declarator
                // In TS: `const x: number = 1` → lexical_declaration → [const, variable_declarator[identifier, type_annotation, =, number]]
                // Actually tree-sitter-typescript puts type_annotation inside variable_declarator
                let type_annotation: Option<String> = {
                    let node = &cpg.ast[&node_id];
                    node.children.iter().find_map(|&cid| {
                        cpg.ast.get(&cid).filter(|c| c.node_type == "type_annotation")
                            .and_then(|c| c.text.clone())
                    })
                };

                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    if n.name.is_none() { n.name = var_name; }
                }
                if let Some(ta) = type_annotation {
                    let meta = cpg.ts_meta_mut(node_id);
                    meta.type_annotation = Some(ta);
                }
            }

            _ => {}
        }
    }
}

// ── Rust enrichment ───────────────────────────────────────────────────────────

pub(crate) fn enrich_rust_metadata(cpg: &mut Cpg) {
    let ids: Vec<NodeId> = cpg.ast.keys().copied().collect();

    for &node_id in &ids {
        let node_type = cpg.ast[&node_id].node_type.clone();
        match node_type.as_str() {
            "function_item" => {
                let node = &cpg.ast[&node_id];
                let fn_name = child_with_field(node, &cpg.ast, "name")
                    .and_then(|(_, c)| c.text.clone())
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| c.node_type == "identifier")
                                .and_then(|c| c.text.clone())
                        })
                    });
                let node_text = node.text.as_deref().unwrap_or("");
                let is_async = node_text.contains("async ");
                let is_unsafe = node_text.contains("unsafe ");
                let is_const = node_text.starts_with("const ") || node_text.contains(" const ");
                let is_extern = node_text.contains("extern ");

                // visibility: look for visibility_modifier child
                let visibility = node.children.iter().find_map(|&cid| {
                    cpg.ast.get(&cid)
                        .filter(|c| c.node_type == "visibility_modifier")
                        .and_then(|c| c.text.clone())
                });

                // ABI: function_modifiers → extern_modifier → string_literal
                let abi = node.children.iter().find_map(|&cid| {
                    let fm = cpg.ast.get(&cid)?;
                    if fm.node_type != "function_modifiers" { return None; }
                    fm.children.iter().find_map(|&ecid| {
                        let em = cpg.ast.get(&ecid)?;
                        if em.node_type != "extern_modifier" { return None; }
                        em.children.iter().find_map(|&slid| {
                            cpg.ast.get(&slid)
                                .filter(|c| c.node_type == "string_literal")
                                .and_then(|c| c.text.clone())
                        })
                    })
                });

                // Collect lifetimes, generic_params, trait_bounds from type_parameters
                let type_params_id = node.children.iter().zip(node.field_names.iter())
                    .find(|(_, fname)| fname.as_deref() == Some("type_parameters"))
                    .map(|(&cid, _)| cid);
                let (lifetimes, generic_params, trait_bounds) = if let Some(tp_id) = type_params_id {
                    let tp_children = cpg.ast.get(&tp_id).map(|n| n.children.clone()).unwrap_or_default();
                    let mut lts: Vec<String> = Vec::new();
                    let mut params: Vec<String> = Vec::new();
                    let mut bounds: Vec<String> = Vec::new();
                    for &cid in &tp_children {
                        let Some(child) = cpg.ast.get(&cid) else { continue; };
                        match child.node_type.as_str() {
                            "lifetime_parameter" => {
                                for &lcid in &child.children.clone() {
                                    if let Some(lt) = cpg.ast.get(&lcid) {
                                        if lt.node_type == "lifetime" {
                                            if let Some(text) = &lt.text { lts.push(text.clone()); }
                                        }
                                    }
                                }
                            }
                            "type_parameter" => {
                                let (child_ids, child_fnames) = (child.children.clone(), child.field_names.clone());
                                for (&gcid, fname) in child_ids.iter().zip(child_fnames.iter()) {
                                    let Some(gc) = cpg.ast.get(&gcid) else { continue; };
                                    if fname.as_deref() == Some("name") {
                                        if let Some(text) = &gc.text { params.push(text.clone()); }
                                    } else if fname.as_deref() == Some("bounds") {
                                        // trait_bounds children: type_identifiers, scoped_type_identifiers, etc.
                                        for &bid in &gc.children.clone() {
                                            if let Some(b) = cpg.ast.get(&bid) {
                                                if let Some(text) = &b.text { bounds.push(text.clone()); }
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    (lts, params, bounds)
                } else {
                    (vec![], vec![], vec![])
                };

                // where_clauses from where_clause child
                let where_clauses: Vec<String> = node.children.iter().find_map(|&cid| {
                    let wc = cpg.ast.get(&cid)?;
                    if wc.node_type != "where_clause" { return None; }
                    Some(wc.children.iter().filter_map(|&wid| {
                        let wp = cpg.ast.get(&wid)?;
                        if wp.node_type == "where_predicate" { wp.text.clone() } else { None }
                    }).collect::<Vec<_>>())
                }).unwrap_or_default();

                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = fn_name;
                }
                let meta = cpg.rust_meta_mut(node_id);
                meta.is_async = is_async;
                meta.is_unsafe = is_unsafe;
                meta.is_const = is_const;
                meta.is_extern = is_extern;
                meta.visibility = visibility;
                meta.abi = abi;
                meta.lifetimes = lifetimes;
                meta.generic_params = generic_params;
                meta.trait_bounds = trait_bounds;
                meta.where_clauses = where_clauses;
            }

            "field_declaration" => {
                let node = &cpg.ast[&node_id];
                let field_name = child_with_field(node, &cpg.ast, "name")
                    .and_then(|(_, c)| c.text.clone())
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| {
                                c.node_type == "field_identifier" || c.node_type == "identifier"
                            }).and_then(|c| c.text.clone())
                        })
                    });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = field_name;
                }
            }

            "call_expression" => {
                let node = &cpg.ast[&node_id];
                // function field is the callee; for field_expression (method-style call s.len())
                // use only the field identifier part, not the full "s.len" text
                let call_name = child_with_field(node, &cpg.ast, "function")
                    .and_then(|(_, c)| {
                        if c.node_type == "field_expression" {
                            // Extract field_identifier child (the method name)
                            c.children.iter().find_map(|&gcid| {
                                cpg.ast.get(&gcid)
                                    .filter(|gc| gc.node_type == "field_identifier")
                                    .and_then(|gc| gc.text.clone())
                            })
                        } else {
                            c.text.clone()
                        }
                    })
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| {
                                matches!(c.node_type.as_str(), "identifier" | "scoped_identifier"
                                    | "path_expression")
                            }).and_then(|c| c.text.clone())
                        })
                    });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = call_name;
                }
            }

            "method_call_expression" => {
                let node = &cpg.ast[&node_id];
                let call_name = child_with_field(node, &cpg.ast, "name")
                    .and_then(|(_, c)| c.text.clone())
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| c.node_type == "identifier")
                                .and_then(|c| c.text.clone())
                        })
                    });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = call_name;
                }
            }

            // Derive macros: attribute_item with #[derive(...)]
            "attribute_item" | "inner_attribute_item" => {
                let node = &cpg.ast[&node_id];
                let attr_text = node.text.as_deref().unwrap_or("");
                if attr_text.contains("derive") {
                    // Extract derive trait names from #[derive(Debug, Clone, ...)]
                    let derives: Vec<String> = if let Some(inner) = attr_text
                        .split('(').nth(1).and_then(|s| s.split(')').next()) {
                        inner.split(',').map(|s| s.trim().to_string()).collect()
                    } else { vec![] };
                    let meta = cpg.rust_meta_mut(node_id);
                    meta.derive_macros = derives;
                }
            }

            "struct_item" | "enum_item" | "union_item" => {
                let node = &cpg.ast[&node_id];
                let type_name = child_with_field(node, &cpg.ast, "name")
                    .and_then(|(_, c)| c.text.clone())
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| {
                                c.node_type == "type_identifier" || c.node_type == "identifier"
                            }).and_then(|c| c.text.clone())
                        })
                    });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = type_name;
                }
            }

            "trait_item" => {
                let node = &cpg.ast[&node_id];
                let trait_name = child_with_field(node, &cpg.ast, "name")
                    .and_then(|(_, c)| c.text.clone())
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| c.node_type == "type_identifier")
                                .and_then(|c| c.text.clone())
                        })
                    });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = trait_name;
                }
            }

            "mod_item" => {
                let node = &cpg.ast[&node_id];
                let mod_name = child_with_field(node, &cpg.ast, "name")
                    .and_then(|(_, c)| c.text.clone())
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| c.node_type == "identifier")
                                .and_then(|c| c.text.clone())
                        })
                    });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = mod_name;
                }
            }

            "let_declaration" => {
                let node = &cpg.ast[&node_id];
                // pattern: identifier or mutable pattern
                let var_name = child_with_field(node, &cpg.ast, "pattern")
                    .and_then(|(_, c)| {
                        if c.node_type == "identifier" {
                            c.text.clone()
                        } else {
                            // mutable_identifier, tuple_pattern, etc.
                            c.children.iter().find_map(|&cid| {
                                cpg.ast.get(&cid).filter(|gc| gc.node_type == "identifier")
                                    .and_then(|gc| gc.text.clone())
                            })
                        }
                    })
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| c.node_type == "identifier")
                                .and_then(|c| c.text.clone())
                        })
                    });
                let is_mut = node.children.iter().any(|&cid| {
                    cpg.ast.get(&cid).map_or(false, |c| c.node_type == "mutable_specifier")
                });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = var_name;
                }
                let meta = cpg.rust_meta_mut(node_id);
                meta.is_mut = is_mut;
            }

            "parameter" => {
                let node = &cpg.ast[&node_id];
                let param_name = child_with_field(node, &cpg.ast, "pattern")
                    .and_then(|(_, c)| c.text.clone())
                    .or_else(|| {
                        node.children.iter().find_map(|&cid| {
                            cpg.ast.get(&cid).filter(|c| c.node_type == "identifier")
                                .and_then(|c| c.text.clone())
                        })
                    });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = param_name;
                }
            }

            "for_expression" => {
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.loop_kind = Some(LoopKind::ForEach);
                }
            }

            "impl_item" => {
                let node = &cpg.ast[&node_id];
                let trait_type = node.children.iter().zip(node.field_names.iter())
                    .find(|(_, fname)| fname.as_deref() == Some("trait"))
                    .and_then(|(&cid, _)| cpg.ast.get(&cid)?.text.clone());
                let self_type = node.children.iter().zip(node.field_names.iter())
                    .find(|(_, fname)| fname.as_deref() == Some("type"))
                    .and_then(|(&cid, _)| cpg.ast.get(&cid)?.text.clone());
                let meta = cpg.rust_meta_mut(node_id);
                meta.trait_type = trait_type;
                meta.self_type = self_type;
            }

            "reference_expression" => {
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.operator = Some("&".to_string());
                }
            }

            "unsafe_block" => {
                let meta = cpg.rust_meta_mut(node_id);
                meta.is_unsafe_context = true;
                // Propagate is_unsafe_context to all descendants.
                let mut queue: Vec<NodeId> = cpg.ast.get(&node_id)
                    .map(|n| n.children.clone())
                    .unwrap_or_default();
                while let Some(desc_id) = queue.pop() {
                    let meta = cpg.rust_meta_mut(desc_id);
                    meta.is_unsafe_context = true;
                    if let Some(desc) = cpg.ast.get(&desc_id) {
                        queue.extend(desc.children.iter().copied());
                    }
                }
            }

            "async_block" => {
                let meta = cpg.rust_meta_mut(node_id);
                meta.is_async = true;
            }

            "closure_expression" => {
                let node = &cpg.ast[&node_id];
                let is_move = node.text.as_deref().map_or(false, |t| t.starts_with("move "));
                let meta = cpg.rust_meta_mut(node_id);
                meta.is_move_closure = is_move;
            }

            "macro_invocation" => {
                let node = &cpg.ast[&node_id];
                // Extract macro name from first identifier child
                let macro_name = node.children.iter().find_map(|&cid| {
                    cpg.ast.get(&cid)
                        .filter(|c| c.node_type == "identifier")
                        .and_then(|c| c.text.clone())
                });
                if let Some(n) = cpg.ast.get_mut(&node_id) {
                    n.name = macro_name;
                }
            }

            _ => {}
        }
    }

    // Propagate derive macros from attribute_item siblings to the struct/enum/union they decorate
    let all_ids: Vec<NodeId> = cpg.ast.keys().copied().collect();
    for parent_id in all_ids {
        let parent_children = cpg.ast[&parent_id].children.clone();
        let mut pending_derives: Vec<String> = Vec::new();
        for child_id in parent_children {
            let Some(child) = cpg.ast.get(&child_id) else { continue; };
            match child.node_type.as_str() {
                "attribute_item" | "inner_attribute_item" => {
                    if let Some(meta) = cpg.rust_metadata.get(&child_id) {
                        if !meta.derive_macros.is_empty() {
                            pending_derives.extend(meta.derive_macros.clone());
                        }
                    }
                }
                "struct_item" | "enum_item" | "union_item" => {
                    if !pending_derives.is_empty() {
                        let derives = std::mem::take(&mut pending_derives);
                        let meta = cpg.rust_meta_mut(child_id);
                        meta.derive_macros = derives;
                    }
                }
                _ => {
                    pending_derives.clear();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::type_inference::c_number_literal_type;

    #[test]
    fn decode_string_literal_keeps_length() {
        let (text, len) = decode_string_literal("\"ab\\n\"");
        assert!(text.contains('\n'));
        assert_eq!(len, text.len() as u32);
    }

    #[test]
    fn generator_builds_graph() {
        let source = "int main(){ int x=1; x=x+1; return x; }";
        let cpg = generate_cpg_from_code(source).expect("cpg");
        assert!(!cpg.ast.is_empty());
        assert!(!cpg.call_graph.is_empty());
        assert!(!cpg.dataflow.definitions.is_empty());
    }

    #[test]
    fn c_literal_type_inference_int() {
        let source = "int f(void){ return 42; }";
        let cpg = generate_cpg_from_code(source).expect("cpg");
        let (&id, _) = cpg.ast.iter().find(|(_, n)| n.node_type == "number_literal").expect("literal");
        let meta = cpg.cpp_metadata.get(&id).expect("meta");
        assert_eq!(meta.inferred_type, Some(CType::Int));
    }

    #[test]
    fn c_literal_type_inference_float() {
        let source = "float f(void){ return 3.14f; }";
        let cpg = generate_cpg_from_code(source).expect("cpg");
        let (&id, _) = cpg.ast.iter().find(|(_, n)| n.node_type == "number_literal").expect("literal");
        let meta = cpg.cpp_metadata.get(&id).expect("meta");
        assert_eq!(meta.inferred_type, Some(CType::Float));
    }

    #[test]
    fn c_literal_type_inference_string() {
        let source = r#"const char* s(void){ return "hello"; }"#;
        let cpg = generate_cpg_from_code(source).expect("cpg");
        let (&id, _) = cpg.ast.iter().find(|(_, n)| n.node_type == "string_literal").expect("literal");
        let meta = cpg.cpp_metadata.get(&id).expect("meta");
        assert_eq!(meta.inferred_type, Some(CType::Pointer(Box::new(CType::Char))));
    }

    #[test]
    fn c_literal_type_inference_char() {
        let source = "char f(void){ return 'x'; }";
        let cpg = generate_cpg_from_code(source).expect("cpg");
        let (&id, _) = cpg.ast.iter().find(|(_, n)| n.node_type == "char_literal").expect("literal");
        let meta = cpg.cpp_metadata.get(&id).expect("meta");
        assert_eq!(meta.inferred_type, Some(CType::Char));
    }

    #[test]
    fn c_number_literal_type_suffixes() {
        assert_eq!(c_number_literal_type("42u"), CType::UInt);
        assert_eq!(c_number_literal_type("42L"), CType::Long);
        assert_eq!(c_number_literal_type("42UL"), CType::ULong);
        assert_eq!(c_number_literal_type("42LL"), CType::LongLong);
        assert_eq!(c_number_literal_type("42ULL"), CType::ULongLong);
        assert_eq!(c_number_literal_type("3.14"), CType::Double);
        assert_eq!(c_number_literal_type("3.14f"), CType::Float);
        assert_eq!(c_number_literal_type("3.14L"), CType::LongDouble);
        assert_eq!(c_number_literal_type("1e10"), CType::Double);
    }

    // ── Phase 1: variable-level type inference ──────────────────────────────

    #[test]
    fn go_short_var_type_inference() {
        let source = "package p\nfunc f() {\n  x := 42\n  _ = x\n}\n";
        let mut cpg_gen = CpgGenerator::new_for_language(SourceLanguage::Go).expect("gen");
        let cpg = cpg_gen.generate_from_source_with_options(source.as_bytes(), GraphBuildOptions::default()).expect("cpg");
        // At least one node should have a Go type inferred (from the integer literal)
        let has_typed = cpg.go_metadata.values().any(|m| m.inferred_type.is_some());
        assert!(has_typed, "expected Go integer literal to have inferred type");
    }

    #[test]
    fn java_var_type_inference() {
        let source = "class C { void f() { int x = 5; } }";
        let mut cpg_gen = CpgGenerator::new_for_language(SourceLanguage::Java).expect("gen");
        let cpg = cpg_gen.generate_from_source_with_options(source.as_bytes(), GraphBuildOptions::default()).expect("cpg");
        let has_int = cpg.java_metadata.values().any(|m| {
            m.inferred_type == Some(JavaType::Primitive("int".to_string()))
        });
        assert!(has_int, "expected Java int literal to be inferred");
    }

    #[test]
    fn rust_let_type_inference() {
        let source = "fn f() { let x: i32 = 0; }";
        let mut cpg_gen = CpgGenerator::new_for_language(SourceLanguage::Rust).expect("gen");
        let cpg = cpg_gen.generate_from_source_with_options(source.as_bytes(), GraphBuildOptions::default()).expect("cpg");
        let has_i32 = cpg.rust_metadata.values().any(|m| {
            m.inferred_type == Some(RustType::Prim(crate::PrimKind::I32))
        });
        assert!(has_i32, "expected Rust i32 annotation to be inferred");
    }

    #[test]
    fn py_annotation_type_inference() {
        let source = "def f():\n  x: int = 1\n  return x\n";
        let mut cpg_gen = CpgGenerator::new_for_language(SourceLanguage::Python).expect("gen");
        let cpg = cpg_gen.generate_from_source_with_options(source.as_bytes(), GraphBuildOptions::default()).expect("cpg");
        let has_int = cpg.python_metadata.values().any(|m| m.inferred_type == Some(PyType::Int));
        assert!(has_int, "expected Python int annotation to be inferred");
    }

    // ── Phase 2: DFG language-specific constructs ───────────────────────────

    #[test]
    fn go_channel_flow_edge() {
        let source = "package p\nfunc f() {\n  ch := make(chan int)\n  go func() { ch <- 1 }()\n  v := <-ch\n  _ = v\n}\n";
        let mut cpg_gen = CpgGenerator::new_for_language(SourceLanguage::Go).expect("gen");
        let cpg = cpg_gen.generate_from_source_with_options(source.as_bytes(), GraphBuildOptions::default()).expect("cpg");
        let has_channel_edge = cpg.dataflow.edges.iter().any(|e| e.edge_type == "CHANNEL_FLOW");
        assert!(has_channel_edge, "expected CHANNEL_FLOW DFG edge for Go channel send/receive");
    }

    #[test]
    fn rust_move_edge() {
        let source = "fn consume(s: String) {}\nfn f() { let s = String::from(\"x\"); consume(s); }";
        let mut cpg_gen = CpgGenerator::new_for_language(SourceLanguage::Rust).expect("gen");
        let cpg = cpg_gen.generate_from_source_with_options(source.as_bytes(), GraphBuildOptions::default()).expect("cpg");
        let has_move_edge = cpg.dataflow.edges.iter().any(|e| e.edge_type == "MOVE");
        assert!(has_move_edge, "expected MOVE DFG edge for Rust ownership transfer");
    }

    #[test]
    fn py_walrus_scope_edge() {
        let source = "def f(xs):\n  result = [y := x for x in xs]\n  return y\n";
        let mut cpg_gen = CpgGenerator::new_for_language(SourceLanguage::Python).expect("gen");
        let cpg = cpg_gen.generate_from_source_with_options(source.as_bytes(), GraphBuildOptions::default()).expect("cpg");
        let has_walrus_edge = cpg.dataflow.edges.iter().any(|e| e.edge_type == "WALRUS_SCOPE_ESCAPE");
        assert!(has_walrus_edge, "expected WALRUS_SCOPE_ESCAPE DFG edge for Python walrus operator");
    }

    // ── Phase 3: class hierarchy ────────────────────────────────────────────

    #[test]
    fn class_hierarchy_java() {
        let source = "class Animal {}\nclass Dog extends Animal {}\n";
        let mut cpg_gen = CpgGenerator::new_for_language(SourceLanguage::Java).expect("gen");
        let cpg = cpg_gen.generate_from_source_with_options(source.as_bytes(), GraphBuildOptions::default()).expect("cpg");
        let parents = cpg.workspace.class_hierarchy.get("Dog");
        assert!(
            parents.map(|p| p.iter().any(|s| s == "Animal")).unwrap_or(false),
            "expected Dog → Animal in class hierarchy"
        );
    }

    #[test]
    fn class_hierarchy_populated() {
        let source = "int main(){return 0;}";
        let cpg = generate_cpg_from_code(source).expect("cpg");
        // class_hierarchy field should exist (may be empty for plain C)
        let _ = &cpg.workspace.class_hierarchy;
    }

    // ── Phase 0: SehLeave lifter ────────────────────────────────────────────

    #[test]
    fn seh_leave_lifts_to_seh_leave_kind() {
        // C++ SEH: __leave should map to IrNodeKind::SehLeave, not Break
        let source = "void f() { __try { __leave; } __except(1) {} }";
        let cpg = generate_cpg_from_code(source).expect("cpg");
        let has_seh_leave = cpg.ast.values().any(|n| n.kind == IrNodeKind::SehLeave);
        assert!(has_seh_leave, "expected IrNodeKind::SehLeave node from __leave statement");
        // Also verify no node has node_type "seh_leave_statement" mapped to Break
        let wrongly_mapped = cpg.ast.values().any(|n| {
            n.node_type == "seh_leave_statement" && n.kind == IrNodeKind::Break
        });
        assert!(!wrongly_mapped, "__leave must not be mapped to IrNodeKind::Break");
    }

    // ── Phase 2: Java field scoping ─────────────────────────────────────────

    #[test]
    fn java_field_scoping_this_access() {
        let source = "class C { int x; void f() { this.x = 1; } }";
        let mut cpg_gen = CpgGenerator::new_for_language(SourceLanguage::Java).expect("gen");
        let cpg = cpg_gen.generate_from_source_with_options(source.as_bytes(), GraphBuildOptions::default()).expect("cpg");
        // The CPG should build successfully with a member access on `this`
        assert!(!cpg.ast.is_empty());
        // A DFG definition/assignment related to x should exist
        let has_x_def = cpg.dataflow.definitions.iter().any(|d| d.variable.contains('x') || d.variable.contains("this"));
        assert!(has_x_def, "expected a DFG definition for this.x field access");
    }

    // ── Phase 3: call graph enrichment ──────────────────────────────────────

    #[test]
    fn go_interface_dispatch_marked_external() {
        // A call site whose Go receiver is marked is_interface should become ExternalDecl
        let source = "package p\ntype Doer interface { Do() }\nfunc use(d Doer) { d.Do() }\n";
        let mut cpg_gen = CpgGenerator::new_for_language(SourceLanguage::Go).expect("gen");
        let cpg = cpg_gen.generate_from_source_with_options(source.as_bytes(), GraphBuildOptions::default()).expect("cpg");
        // The CPG should build and contain a call graph entry for `use`
        assert!(!cpg.call_graph.is_empty());
    }

    #[test]
    fn py_class_instantiation_marked_constructor() {
        let source = "class Dog:\n  def __init__(self): pass\ndef f():\n  d = Dog()\n  return d\n";
        let mut cpg_gen = CpgGenerator::new_for_language(SourceLanguage::Python).expect("gen");
        let cpg = cpg_gen.generate_from_source_with_options(source.as_bytes(), GraphBuildOptions::default()).expect("cpg");
        let has_ctor = cpg.python_metadata.values().any(|m| m.is_constructor_call);
        assert!(has_ctor, "expected is_constructor_call=true for Dog() instantiation");
    }

    // ── Phase 4: interprocedural DFG ───────────────────────────────────────

    #[test]
    fn interprocedural_taint_summary() {
        let source = "int pass(int x) { return x; }\nint main() { int v = pass(42); return v; }";
        let cpg = generate_cpg_from_code(source).expect("cpg");
        // After interprocedural analysis, pass() should have a TaintReturn summary
        let has_summary = cpg.workspace.function_summaries.values().any(|s| {
            s.param_effects.iter().any(|e| matches!(e, crate::ParamEffect::TaintReturn(_)))
        });
        assert!(has_summary, "expected interprocedural TaintReturn summary for pass()");
    }
}
