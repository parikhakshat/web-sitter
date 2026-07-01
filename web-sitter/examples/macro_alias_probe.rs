use web_sitter::{CpgGenerator, GraphBuildOptions, SourceLanguage, IrNodeKind};

fn main() {
    let path = std::env::args().nth(1).expect("usage: macro_alias_probe <file.c>");
    let mut generator = CpgGenerator::new_for_language(SourceLanguage::C).unwrap();
    let cpg = generator
        .generate_from_file_with_options(&path, GraphBuildOptions::default())
        .expect("cpg generation failed");

    eprintln!("macro_aliases: {:?}", cpg.c_file.macro_aliases);
    eprintln!("macro_bodies keys: {:?}", cpg.c_file.macro_bodies.keys().collect::<Vec<_>>());

    for (id, node) in &cpg.ast {
        if node.kind == IrNodeKind::Call {
            eprintln!(
                "Call node {id}: node.name={:?} node_type={:?} text={:?}",
                node.name, node.node_type, node.text
            );
        }
    }

    eprintln!("\ncall_graph:");
    for (fn_id, entry) in &cpg.call_graph {
        eprintln!("function {fn_id} ({:?}):", entry.name);
        for call in &entry.calls {
            eprintln!("  call_site={:?} callee={:?} qualified={:?}", call.call_site, call.callee, call.qualified_callee);
        }
    }
}
