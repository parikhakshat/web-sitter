mod output;
mod html_report;

use std::collections::HashSet;
use std::io::{IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rayon::prelude::*;
use tracing::debug;

use web_ql::{RuleSet, Workspace};
use web_ql::loader::{file_hash, load_rules, load_rules_dir};
use web_sitter::{self, CpgGenerator, GraphBuildOptions, SourceLanguage, language_from_path};

use output::OutputFormat;

// ── CLI definition ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "web-scan", version, about = "ScuzzQL repository scanner")]
struct Cli {
    /// Enable debug logging (-d) or trace logging (-dd)
    #[arg(short = 'd', action = clap::ArgAction::Count, global = true)]
    debug: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a repository using one or more ScuzzQL query files or directories
    Scan(ScanArgs),
}

#[derive(Parser)]
struct ScanArgs {
    /// One or more `.wql` rule files or directories containing `.wql` files
    #[arg(required = true, value_name = "QUERY")]
    queries: Vec<PathBuf>,

    /// Repository root to scan (default: current directory)
    #[arg(long, default_value = ".", value_name = "PATH")]
    repo: PathBuf,

    /// Output file (default: stdout; required for --format html)
    #[arg(long, short = 'o', value_name = "PATH")]
    output: Option<PathBuf>,

    /// Output format
    #[arg(long, short = 'f', default_value = "json", value_name = "FORMAT", value_parser = clap::value_parser!(String))]
    format_str: String,

    /// Exclude files matching this path substring (repeatable)
    #[arg(long, value_name = "PATTERN")]
    exclude: Vec<String>,

    /// Skip content-hash caching; always re-parse
    #[arg(long)]
    no_cache: bool,

    /// Exit with code 1 when findings are present, 2 on error
    #[arg(long)]
    exit_code: bool,

    /// Enable profiling output
    #[arg(long)]
    profile: bool,

    /// Write profiling data to this file (JSON by default; a .html companion is also written)
    #[arg(long, value_name = "PATH")]
    profile_output: Option<PathBuf>,
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    let log_level = match cli.debug {
        0 => tracing::Level::WARN,
        1 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };
    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    let exit = match cli.command {
        Command::Scan(args) => {
            let has_findings = match run_scan(args) {
                Ok(n) => n > 0,
                Err(e) => {
                    eprintln!("error: {e:#}");
                    std::process::exit(2);
                }
            };
            if has_findings { 1 } else { 0 }
        }
    };

    std::process::exit(exit);
}

// ── Scan pipeline ─────────────────────────────────────────────────────────────

fn run_scan(args: ScanArgs) -> Result<usize> {
    let format: OutputFormat = args.format_str.parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;

    if args.profile {
        web_profiler::init();
    }

    let use_progress = std::io::stderr().is_terminal();

    let mp = MultiProgress::new();
    if !use_progress {
        mp.set_draw_target(indicatif::ProgressDrawTarget::hidden());
    }

    // Helper: print a status line without interleaving with live bars in TTY mode,
    // and fall back to eprintln in non-TTY mode (hidden draw target swallows mp.println).
    macro_rules! status {
        ($($arg:tt)*) => {{
            let msg = format!($($arg)*);
            if use_progress {
                mp.println(&msg)?;
            } else {
                eprintln!("{}", msg);
            }
        }};
    }

    let spinner_style = ProgressStyle::with_template(
        "  {spinner:.cyan} [{elapsed_precise}] {msg}",
    )
    .unwrap()
    .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "✓"]);

    let bar_style = ProgressStyle::with_template(
        "  {spinner:.cyan} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len}  {per_sec}  eta {eta}  {msg}",
    )
    .unwrap()
    .progress_chars("█▉▊▋▌▍▎▏ ")
    .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "✓"]);

    // Stage 1 — File discovery
    let disc_bar = mp.add(ProgressBar::new_spinner());
    disc_bar.set_style(spinner_style.clone());
    disc_bar.set_message("Discovering source files…");
    disc_bar.enable_steady_tick(std::time::Duration::from_millis(80));

    let source_files = discover_files(&args.repo, &args.exclude)?;
    disc_bar.finish_with_message(format!("Discovered {} source files", source_files.len()));

    // Stage 2 — CPG generation
    let cpg_bar = mp.add(ProgressBar::new(source_files.len() as u64));
    cpg_bar.set_style(bar_style.clone());
    cpg_bar.set_message("Building CPGs…");
    cpg_bar.enable_steady_tick(std::time::Duration::from_millis(80));

    let _cpg_span = web_profiler::span("stage.cpg_build");
    let registry = web_ql::security_patterns::builtin_endpoint_registry();
    let mut workspace = Workspace::new(registry);

    let cpg_results: Vec<(PathBuf, anyhow::Result<web_sitter::Cpg>, u64)> = source_files
        .par_iter()
        .map(|path| {
            let hash = if args.no_cache { 0 } else { file_hash(path).unwrap_or(0) };
            let lang = language_from_path(path.to_str().unwrap_or(""));
            let result = build_cpg(path, lang);
            (path.clone(), result, hash)
        })
        .inspect(|_| cpg_bar.inc(1))
        .collect();
    drop(_cpg_span);
    web_profiler::record_parallel_work(
        "CPG parse", "stage.cpg_build", "stage.cpg_parse_file", rayon::current_num_threads(),
    );

    let mut cpg_errors = 0usize;
    for (path, result, hash) in cpg_results {
        match result {
            Ok(cpg) => { workspace.upsert_file(path, cpg, hash); }
            Err(e) => {
                debug!("CPG error for {}: {e:#}", path.display());
                cpg_errors += 1;
            }
        }
    }
    cpg_bar.finish_with_message(format!(
        "Built CPGs for {} files ({cpg_errors} errors)",
        source_files.len() - cpg_errors
    ));
    web_profiler::count("files_parsed", (source_files.len() - cpg_errors) as u64);

    // Stage 3 — Taint summarization / cross-file edge resolution
    //
    // This runs after every file's own CPG (and per-function taint summary) is
    // already built in stage 2 — it's the workspace-wide pass that resolves each
    // call site's callee across file boundaries. On a large codebase it can take
    // long enough that a bare spinner looks indistinguishable from a hang, so it
    // gets the same determinate per-file bar as CPG build / rule eval.
    let edge_bar = mp.add(ProgressBar::new(workspace.files.len() as u64));
    edge_bar.set_style(bar_style.clone());
    edge_bar.set_message("Summarizing taint & cross-file edges…");
    edge_bar.enable_steady_tick(std::time::Duration::from_millis(80));

    let _edge_span = web_profiler::span("stage.cross_file_edges");
    workspace.build_cross_file_edges_with_progress(|| edge_bar.inc(1));
    drop(_edge_span);

    let n_edges = workspace.cross_file_callee_params.len();
    let n_callee_files = workspace.cross_file_dfgs.len();
    edge_bar.finish_with_message(format!(
        "Taint: {n_edges} cross-file call edges, {n_callee_files} callee files indexed"
    ));

    // Load rule sets
    let rule_set = load_all_rules(&args.queries)?;

    // Stage 5 — Rule evaluation
    let total_files = workspace.files.len() as u64;
    let scan_bar = mp.add(ProgressBar::new(total_files));
    scan_bar.set_style(
        ProgressStyle::with_template(
            "  {spinner:.cyan} [{elapsed_precise}] [{bar:40.green/blue}] {pos}/{len}  {per_sec}  eta {eta}  {msg}",
        )
        .unwrap()
        .progress_chars("█▉▊▋▌▍▎▏ ")
        .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "✓"]),
    );
    scan_bar.enable_steady_tick(std::time::Duration::from_millis(80));
    scan_bar.set_message("Running rules…");

    let _scan_span = web_profiler::span("stage.rule_scan");
    let findings = workspace.scan_with_progress(&rule_set, || {
        scan_bar.inc(1);
    });
    drop(_scan_span);
    web_profiler::record_parallel_work(
        "Rule scan", "stage.rule_scan", "query.scan_file", rayon::current_num_threads(),
    );
    scan_bar.finish_with_message(format!("{} findings", findings.len()));
    web_profiler::count("findings_total", findings.len() as u64);

    // Profile output
    if args.profile {
        let report = web_profiler::report();
        let prof_path = args.profile_output
            .clone()
            .unwrap_or_else(|| PathBuf::from("profile.json"));

        let json = serde_json::to_string_pretty(&report)?;
        std::fs::write(&prof_path, &json)
            .with_context(|| format!("writing profile to {}", prof_path.display()))?;
        status!("Profile written to {}", prof_path.display());

        let html_path = prof_path.with_extension("html");
        std::fs::write(&html_path, report.to_html())
            .with_context(|| format!("writing profile HTML to {}", html_path.display()))?;
        status!("Profile HTML written to {}", html_path.display());
    }

    // Extract CPG subgraphs for HTML output (no-op for other formats)
    let cpg_graphs: Option<Vec<Option<web_sitter::CpgSubgraph>>> = if matches!(format, OutputFormat::Html) {
        Some(findings.iter().map(|f| workspace.extract_cpg_subgraph(f)).collect())
    } else {
        None
    };

    // Render and emit output
    let rendered = output::render(&findings, &format, &args.repo, args.output.as_deref(), workspace.files.len(), cpg_graphs.as_deref())?;
    match &args.output {
        Some(path) => {
            std::fs::write(path, &rendered)
                .with_context(|| format!("writing output to {}", path.display()))?;
            status!("Output written to {}", path.display());
        }
        None => {
            std::io::stdout()
                .write_all(rendered.as_bytes())
                .context("writing to stdout")?;
        }
    }

    Ok(findings.len())
}

// ── File discovery ────────────────────────────────────────────────────────────

fn discover_files(root: &Path, excludes: &[String]) -> Result<Vec<PathBuf>> {
    let known_extensions: HashSet<&str> = [
        "c", "h", "cpp", "cc", "cxx", "hpp", "go", "py", "java", "js", "mjs", "ts", "tsx", "rs",
    ]
    .iter()
    .copied()
    .collect();

    let mut files = Vec::new();
    walk_dir(root, &known_extensions, excludes, &mut files)?;
    files.sort();
    Ok(files)
}

fn walk_dir(
    dir: &Path,
    extensions: &HashSet<&str>,
    excludes: &[String],
    out: &mut Vec<PathBuf>,
) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("reading directory {}", dir.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let path_str = path.to_string_lossy();

        if excludes.iter().any(|pat| path_str.contains(pat.as_str())) {
            continue;
        }

        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') || matches!(name.as_ref(), "target" | "node_modules" | "vendor" | ".git") {
                continue;
            }
            walk_dir(&path, extensions, excludes, out)?;
        } else if file_type.is_file() {
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if extensions.contains(ext) {
                    out.push(path);
                }
            }
        }
    }

    Ok(())
}

// ── CPG generation ────────────────────────────────────────────────────────────

fn build_cpg(path: &Path, language: SourceLanguage) -> Result<web_sitter::Cpg> {
    let _span = web_profiler::span("stage.cpg_parse_file");
    let mut generator = CpgGenerator::new_for_language(language)
        .with_context(|| format!("creating CPG generator for {}", path.display()))?;
    generator.generate_from_file_with_options(path, GraphBuildOptions::default())
        .with_context(|| format!("generating CPG for {}", path.display()))
}

// ── Rule loading ──────────────────────────────────────────────────────────────

fn load_all_rules(query_args: &[PathBuf]) -> Result<RuleSet> {
    let mut all_sets: Vec<RuleSet> = Vec::new();

    for path in query_args {
        if path.is_dir() {
            let sets = load_rules_dir(path)
                .with_context(|| format!("loading rules from directory {}", path.display()))?;
            all_sets.extend(sets);
        } else {
            let rs = load_rules(path)
                .with_context(|| format!("loading rules from {}", path.display()))?;
            all_sets.push(rs);
        }
    }

    if all_sets.iter().all(|rs| rs.rules.is_empty()) {
        anyhow::bail!("no rules loaded — check your QUERY arguments");
    }

    Ok(RuleSet::merge(all_sets))
}
