mod output;

use std::collections::HashSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rayon::prelude::*;
use tracing::debug;

use web_ql::{EndpointRegistry, RuleSet, Workspace};
use web_ql::loader::{file_hash, load_rules, load_rules_dir};
use web_sitter::{CpgGenerator, GraphBuildOptions, SourceLanguage, language_from_path};

use output::{OutputFormat, render};

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

    /// Write profiling data as JSON to this file
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

    let mp = MultiProgress::new();
    let spinner_style = ProgressStyle::with_template("{spinner:.cyan} {msg}")
        .unwrap()
        .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "✓"]);
    let bar_style = ProgressStyle::with_template(
        "{spinner:.cyan} {msg} [{bar:35.cyan/blue}] {pos}/{len}",
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
    disc_bar.finish_with_message(format!(
        "Discovered {} source files",
        source_files.len()
    ));

    // Stage 2 — CPG generation
    let cpg_bar = mp.add(ProgressBar::new(source_files.len() as u64));
    cpg_bar.set_style(bar_style.clone());
    cpg_bar.set_message("Building CPGs…");
    cpg_bar.enable_steady_tick(std::time::Duration::from_millis(80));

    let registry = web_ql::security_patterns::builtin_endpoint_registry();
    let mut workspace = Workspace::new(registry);

    // Generate CPGs in parallel, then upsert sequentially (workspace needs mut).
    let cpg_results: Vec<(PathBuf, anyhow::Result<web_sitter::Cpg>, u64)> = source_files
        .par_iter()
        .map(|path| {
            let hash = if args.no_cache {
                0
            } else {
                file_hash(path).unwrap_or(0)
            };
            let lang = language_from_path(path.to_str().unwrap_or(""));
            let result = build_cpg(path, lang);
            (path.clone(), result, hash)
        })
        .inspect(|_| cpg_bar.inc(1))
        .collect();

    let mut cpg_errors = 0usize;
    for (path, result, hash) in cpg_results {
        match result {
            Ok(cpg) => {
                workspace.upsert_file(path, cpg, hash);
            }
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

    // Stage 3 — Cross-file edge resolution
    let edge_bar = mp.add(ProgressBar::new_spinner());
    edge_bar.set_style(spinner_style.clone());
    edge_bar.set_message("Resolving cross-file edges…");
    edge_bar.enable_steady_tick(std::time::Duration::from_millis(80));

    workspace.build_cross_file_edges();

    let n_edges = workspace.cross_file_callee_params.len();
    let n_callee_files = workspace.cross_file_dfgs.len();
    edge_bar.finish_with_message(format!(
        "Resolved {n_edges} cross-file call edges across {n_callee_files} callee files"
    ));

    // Load rule sets
    let rule_set = load_all_rules(&args.queries)?;

    // Stage 4 — Rule evaluation
    let total_files = workspace.files.len() as u64;
    let scan_bar = mp.add(ProgressBar::new(total_files));
    scan_bar.set_style(
        ProgressStyle::with_template(
            "{spinner:.cyan} Scanning [{bar:35.cyan/blue}] {pos}/{len}  {msg}",
        )
        .unwrap()
        .progress_chars("█▉▊▋▌▍▎▏ ")
        .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "✓"]),
    );
    scan_bar.enable_steady_tick(std::time::Duration::from_millis(80));
    let findings_count = Arc::new(AtomicU64::new(0));

    // Wrap scan so we can update the bar — scan() is parallel internally.
    // We hook into rayon via a thread-local ticker using indicatif's rayon feature.
    let findings = workspace.scan(&rule_set);
    findings_count.store(findings.len() as u64, Ordering::Relaxed);
    scan_bar.set_position(total_files);
    scan_bar.finish_with_message(format!("{} findings", findings.len()));

    mp.clear().ok();

    // Profile output
    if args.profile {
        let report = web_profiler::report();
        if let Some(ref prof_path) = args.profile_output {
            let json = serde_json::to_string_pretty(&report)?;
            std::fs::write(prof_path, &json)
                .with_context(|| format!("writing profile to {}", prof_path.display()))?;
            eprintln!("Profile written to {}", prof_path.display());
        } else {
            eprintln!("{report}");
        }
    }

    // Render and emit output
    let rendered = render(&findings, &format)?;
    match &args.output {
        Some(path) => {
            std::fs::write(path, &rendered)
                .with_context(|| format!("writing output to {}", path.display()))?;
            eprintln!("Output written to {}", path.display());
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
        "c", "h", "cpp", "cc", "cxx", "hpp", "go", "py", "java", "js", "mjs", "ts", "tsx",
        "rs",
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
            // Skip hidden directories and common build/vendor dirs
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
    let mut generator = CpgGenerator::new_for_language(language)
        .with_context(|| format!("creating CPG generator for {}", path.display()))?;
    generator.generate_from_file_with_options(path, GraphBuildOptions::default())
        .with_context(|| format!("generating CPG for {}", path.display()))
}

// ── Rule loading ──────────────────────────────────────────────────────────────

fn load_all_rules(query_args: &[PathBuf]) -> Result<RuleSet> {
    let mut all_rules: Vec<web_ql::ir::CompiledRule> = Vec::new();

    for path in query_args {
        if path.is_dir() {
            let sets = load_rules_dir(path)
                .with_context(|| format!("loading rules from directory {}", path.display()))?;
            for rs in sets {
                all_rules.extend(rs.rules);
            }
        } else {
            let rs = load_rules(path)
                .with_context(|| format!("loading rules from {}", path.display()))?;
            all_rules.extend(rs.rules);
        }
    }

    if all_rules.is_empty() {
        anyhow::bail!("no rules loaded — check your QUERY arguments");
    }

    Ok(RuleSet::new(all_rules))
}
