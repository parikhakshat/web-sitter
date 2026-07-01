use std::collections::HashSet;
use std::path::{Path, PathBuf};

use web_ql::loader::{load_rules, load_rules_dir};
use web_ql::{Workspace, builtin_endpoint_registry};
use web_sitter::{self, CpgGenerator, GraphBuildOptions, language_from_path};

fn discover_files(root: &Path, out: &mut Vec<PathBuf>) {
    let known: HashSet<&str> = ["c", "h", "cpp", "cc", "cxx", "hpp"].iter().copied().collect();
    let Ok(entries) = std::fs::read_dir(root) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().unwrap().to_string_lossy();
            if name.starts_with('.') || matches!(name.as_ref(), "target" | ".git") {
                continue;
            }
            discover_files(&path, out);
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if known.contains(ext) {
                out.push(path);
            }
        }
    }
}

fn main() {
    let repo = std::env::args().nth(1).expect("usage: nginx_chain_report <repo> <rules_dir>");
    let rules_dir = std::env::args().nth(2).expect("usage: nginx_chain_report <repo> <rules_dir>");

    let mut files = Vec::new();
    discover_files(Path::new(&repo), &mut files);
    eprintln!("discovered {} files", files.len());

    let registry = builtin_endpoint_registry();
    let mut ws = Workspace::new(registry);
    for path in &files {
        let lang = language_from_path(path.to_str().unwrap());
        let mut generator = match CpgGenerator::new_for_language(lang) {
            Ok(g) => g,
            Err(_) => continue,
        };
        if let Ok(cpg) = generator.generate_from_file_with_options(path, GraphBuildOptions::default()) {
            ws.upsert_file(path.clone(), cpg, 0);
        }
    }
    ws.build_cross_file_edges();

    let mut rule_sets = Vec::new();
    let rp = Path::new(&rules_dir);
    if rp.is_dir() {
        rule_sets.extend(load_rules_dir(rp).expect("load rules dir"));
    } else {
        rule_sets.push(load_rules(rp).expect("load rules"));
    }
    let rule_set = web_ql::RuleSet::merge(rule_sets);

    let findings = ws.scan(&rule_set);
    eprintln!("{} findings", findings.len());

    struct Row {
        rule_id: String,
        path_len: usize,
        src_fn: Option<String>,
        sink_fn: Option<String>,
        src_file: String,
        sink_line: u32,
        cross_function: bool,
    }

    let mut rows = Vec::new();
    for f in &findings {
        if f.matched_nodes.len() < 2 {
            continue;
        }
        let file_idx = match ws.files.get(&PathBuf::from(&f.location.file)) {
            Some(fi) => fi,
            None => continue,
        };
        let cpg = &file_idx.cpg;
        let src_id = f.matched_nodes[0];
        let sink_id = *f.matched_nodes.last().unwrap();

        let fn_name = |nid: web_sitter::NodeId| -> Option<String> {
            let node = cpg.ast.get(&nid)?;
            let fn_id = node.function_id?;
            cpg.ast.get(&fn_id)?.name.clone()
        };

        let src_fn = fn_name(src_id);
        let sink_fn = fn_name(sink_id);
        let cross_function = src_fn != sink_fn;

        rows.push(Row {
            rule_id: f.rule_id.clone(),
            path_len: f.matched_nodes.len(),
            src_fn,
            sink_fn,
            src_file: f.location.file.clone(),
            sink_line: f.location.line,
            cross_function,
        });
    }

    rows.sort_by_key(|r| std::cmp::Reverse(r.path_len));
    eprintln!("\n=== top 20 by path length ===");
    for r in rows.iter().take(20) {
        eprintln!(
            "len={:3} cross_fn={:5} rule={:35} {}():{} src_fn={:?} sink_fn={:?}",
            r.path_len, r.cross_function, r.rule_id, r.src_file, r.sink_line, r.src_fn, r.sink_fn
        );
    }

    let cross_fn: Vec<&Row> = rows.iter().filter(|r| r.cross_function).collect();
    eprintln!("\n=== cross-function findings: {} / {} ===", cross_fn.len(), rows.len());
    for r in cross_fn.iter().take(30) {
        eprintln!(
            "len={:3} rule={:35} {}:{} src_fn={:?} sink_fn={:?}",
            r.path_len, r.rule_id, r.src_file, r.sink_line, r.src_fn, r.sink_fn
        );
    }

    let len_2_cross_fn = cross_fn.iter().filter(|r| r.path_len == 2).count();
    eprintln!(
        "\ncross-function findings with fallback (len==2) path: {} / {}",
        len_2_cross_fn,
        cross_fn.len()
    );
}
