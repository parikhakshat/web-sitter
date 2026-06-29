/// Rust stdlib / common-crate security patterns.
///
/// # Naming convention
///
/// The Rust CPG uses **two** call node types, each with different name storage:
///
/// | TS node kind              | Example                  | `call.name`       |
/// |---------------------------|--------------------------|-------------------|
/// | `call_expression`         | `std::env::var("KEY")`   | `"std::env::var"` |
/// | `method_call_expression`  | `s.read_line(&mut buf)`  | `"read_line"`     |
///
/// Both forms are listed where applicable.  For path-style calls we include
/// both the fully-qualified (`std::env::var`) and the `use`-shortened
/// (`env::var`) forms since either may appear depending on import style.
///
/// Covered areas: `std::env`, `std::fs`, `std::io`, `std::process`,
/// `std::net`, `std::path`, `std::str`, `std::string`, `std::collections`,
/// `std::thread`, popular crates: `sqlx`, `diesel`, `reqwest`, `tokio::fs`,
/// `actix-web`, `axum`, `serde_json`, `hyper`.

use web_sitter::security_patterns::{SourceSpec, SinkSpec, PropagatorSpec};

// =============================================================================
// Taint sources
// =============================================================================

pub const RUST_TAINT_SOURCES: &[(&str, SourceSpec)] = &[
    // ── std::env — environment variables ──────────────────────────────────────
    (
        "std::env::var",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "env::var",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "std::env::var_os",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "env::var_os",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "std::env::args",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "env::args",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "std::env::args_os",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "env::args_os",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "vars",              // env::vars() → iterator of (key, value)
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    // ── std::fs — file reading ─────────────────────────────────────────────────
    (
        "std::fs::read_to_string",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "fs::read_to_string",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "read_to_string",    // method on Read implementors (also tokio::fs)
        SourceSpec { tainted_params: &[0], tainted_return: false },
    ),
    (
        "std::fs::read",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "fs::read",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "std::fs::read_dir",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "fs::read_dir",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    // ── std::io — stdin reading ────────────────────────────────────────────────
    (
        "read_line",         // BufRead::read_line(&mut buf)
        SourceSpec { tainted_params: &[0], tainted_return: false },
    ),
    (
        "read_to_end",
        SourceSpec { tainted_params: &[0], tainted_return: false },
    ),
    (
        "lines",             // BufRead::lines → iterator of tainted Strings
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "read",              // Read::read(&mut buf) → fills buf with tainted data
        SourceSpec { tainted_params: &[0], tainted_return: false },
    ),
    (
        "read_exact",
        SourceSpec { tainted_params: &[0], tainted_return: false },
    ),
    // ── std::net — network receive ─────────────────────────────────────────────
    (
        "recv",              // TcpStream::recv / UdpSocket::recv
        SourceSpec { tainted_params: &[0], tainted_return: false },
    ),
    (
        "recv_from",
        SourceSpec { tainted_params: &[0], tainted_return: false },
    ),
    (
        "peek",
        SourceSpec { tainted_params: &[0], tainted_return: false },
    ),
    // ── clap / structopt — command-line argument parsing ──────────────────────
    (
        "parse",             // clap::Parser::parse() / structopt::StructOpt::from_args()
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "get_one",           // clap ArgMatches::get_one::<String>(name)
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "get_many",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "get_flag",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "value_of",          // clap (v3) ArgMatches::value_of
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "values_of",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    // ── actix-web / axum — HTTP request data ──────────────────────────────────
    // These are typically extractor types; the taint enters when you call
    // into() / unwrap() on them or use them in handler parameters.
    // For the common pattern `web::Query::<T>::from_query(req.query_string())`:
    (
        "query_string",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "match_info",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    // axum: extract Path, Query from request
    (
        "path",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "query",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    // ── serde_json — deserialization (json! / from_str / from_reader) ──────────
    (
        "from_str",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "from_reader",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "from_value",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
];

// =============================================================================
// Taint sinks
// =============================================================================

pub const RUST_TAINT_SINKS: &[(&str, SinkSpec)] = &[
    // ── std::process — OS command injection ────────────────────────────────────
    (
        "std::process::Command::new",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "Command::new",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "new",               // Process::Command::new — matches when called as Command::new
        SinkSpec { sink_args: &[0] },
    ),
    (
        "arg",               // Command::arg(arg)
        SinkSpec { sink_args: &[0] },
    ),
    (
        "args",              // Command::args(args)
        SinkSpec { sink_args: &[0] },
    ),
    (
        "spawn",             // Command::spawn → executes the command
        SinkSpec { sink_args: &[] },
    ),
    (
        "status",            // Command::status
        SinkSpec { sink_args: &[] },
    ),
    (
        "output",            // Command::output
        SinkSpec { sink_args: &[] },
    ),
    // ── std::fs — file write / path traversal ─────────────────────────────────
    (
        "std::fs::write",
        SinkSpec { sink_args: &[0, 1] },
    ),
    (
        "fs::write",
        SinkSpec { sink_args: &[0, 1] },
    ),
    (
        "write",             // write method on File / BufWriter
        SinkSpec { sink_args: &[0] },
    ),
    (
        "write_all",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "write_fmt",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "std::fs::remove_file",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "fs::remove_file",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "remove_file",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "std::fs::remove_dir_all",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "fs::remove_dir_all",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "std::fs::copy",
        SinkSpec { sink_args: &[0, 1] },
    ),
    (
        "fs::copy",
        SinkSpec { sink_args: &[0, 1] },
    ),
    (
        "std::fs::rename",
        SinkSpec { sink_args: &[0, 1] },
    ),
    (
        "fs::rename",
        SinkSpec { sink_args: &[0, 1] },
    ),
    (
        "std::fs::create_dir",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "fs::create_dir",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "std::fs::create_dir_all",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "fs::create_dir_all",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "std::fs::File::create",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "File::create",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "std::fs::File::open",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "File::open",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "std::fs::OpenOptions::open",
        SinkSpec { sink_args: &[0] },
    ),
    // ── std::net — network connection (SSRF) ──────────────────────────────────
    (
        "std::net::TcpStream::connect",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "TcpStream::connect",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "connect",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "std::net::UdpSocket::connect",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "UdpSocket::connect",
        SinkSpec { sink_args: &[0] },
    ),
    // ── reqwest — HTTP client SSRF ─────────────────────────────────────────────
    (
        "get",               // reqwest::get(url)
        SinkSpec { sink_args: &[0] },
    ),
    (
        "post",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "put",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "delete",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "head",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "patch",
        SinkSpec { sink_args: &[0] },
    ),
    // ── sqlx — SQL injection ───────────────────────────────────────────────────
    (
        "query",             // sqlx::query(sql)
        SinkSpec { sink_args: &[0] },
    ),
    (
        "query_as",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "query_scalar",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "execute",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "fetch_all",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "fetch_one",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "fetch_optional",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "fetch",
        SinkSpec { sink_args: &[0] },
    ),
    // ── diesel — raw SQL ──────────────────────────────────────────────────────
    (
        "sql",               // diesel::dsl::sql(query)
        SinkSpec { sink_args: &[0] },
    ),
    (
        "sql_query",
        SinkSpec { sink_args: &[0] },
    ),
    // ── actix-web / axum — HTTP response (XSS) ────────────────────────────────
    (
        "body",              // HttpResponse::body(content)
        SinkSpec { sink_args: &[0] },
    ),
    // ── serde_json / eval in unsafe blocks ────────────────────────────────────
    (
        "eval",              // boa_engine or deno_runtime eval
        SinkSpec { sink_args: &[0] },
    ),
    // ── log crate — log injection ──────────────────────────────────────────────
    // Note: log::info! etc. are macros (MacroInvocation), not calls; listed for
    // tool reference and rule authors who handle macros separately.
    // ── std::process::exit ────────────────────────────────────────────────────
    (
        "std::process::exit",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "process::exit",
        SinkSpec { sink_args: &[0] },
    ),
    // ── Path manipulation ─────────────────────────────────────────────────────
    (
        "std::path::Path::new",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "Path::new",
        SinkSpec { sink_args: &[0] },
    ),
    (
        "PathBuf::from",
        SinkSpec { sink_args: &[0] },
    ),
];

// =============================================================================
// Taint propagators
// =============================================================================

pub const RUST_TAINT_PROPAGATORS: &[(&str, PropagatorSpec)] = &[
    // ── String / str methods (method_call_expression) ─────────────────────────
    (
        "to_string",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "to_owned",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "to_lowercase",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "to_uppercase",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "trim",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "trim_start",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "trim_end",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "trim_matches",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "trim_start_matches",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "trim_end_matches",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "replace",
        PropagatorSpec { dst: -1, src: &[1] },
    ),
    (
        "replacen",
        PropagatorSpec { dst: -1, src: &[1] },
    ),
    (
        "split",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "splitn",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "split_once",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "rsplit",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "rsplitn",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "rsplit_once",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "lines",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "chars",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "bytes",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "encode_utf16",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "into_bytes",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "as_bytes",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "into_string",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "from_utf8",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "from_utf8_lossy",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "parse",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    // ── String push / concatenation ────────────────────────────────────────────
    (
        "push_str",
        PropagatorSpec { dst: 0, src: &[0] },  // self (dst arg 0 in signature but receiver) — approximate
    ),
    (
        "push",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "insert_str",
        PropagatorSpec { dst: -1, src: &[1] },
    ),
    // String::add / + operator calls
    (
        "add",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    // ── format! / concat! are macros — not Call nodes; listed for completeness
    // ── Vec / slice methods ────────────────────────────────────────────────────
    (
        "join",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "concat",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "iter",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "into_iter",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "collect",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "map",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "filter",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "filter_map",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "flat_map",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "flatten",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "fold",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "enumerate",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "zip",
        PropagatorSpec { dst: -1, src: &[-1] },
    ),
    (
        "chain",
        PropagatorSpec { dst: -1, src: &[-1] },
    ),
    (
        "cloned",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "copied",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "get",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    // ── Path / PathBuf ────────────────────────────────────────────────────────
    (
        "join",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "with_file_name",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "with_extension",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    // ── Option / Result — taint passes through ────────────────────────────────
    (
        "unwrap",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "unwrap_or",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "unwrap_or_else",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "expect",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "ok",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "err",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "map",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "and_then",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "or_else",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "map_err",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    // ── serde — serialization carries taint ──────────────────────────────────
    (
        "to_string",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "to_value",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    // ── base64 crate ─────────────────────────────────────────────────────────
    (
        "encode",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "decode",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "encode_string",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    (
        "decode_vec",
        PropagatorSpec { dst: -1, src: &[0] },
    ),
    // ── url crate ─────────────────────────────────────────────────────────────
    (
        "as_str",
        PropagatorSpec { dst: -1, src: &[] },
    ),
    (
        "into_string",
        PropagatorSpec { dst: -1, src: &[] },
    ),
];

// =============================================================================
// Named sets
// =============================================================================

/// Rust OS command execution sinks.
pub const RUST_EXEC_SINKS: &[&str] = &[
    "std::process::Command::new", "Command::new", "new",
    "arg", "args", "spawn", "status", "output",
];

/// Rust file system sinks (path traversal / arbitrary write).
pub const RUST_FILE_SINKS: &[&str] = &[
    "std::fs::write", "fs::write", "write", "write_all",
    "std::fs::remove_file", "fs::remove_file", "remove_file",
    "std::fs::remove_dir_all", "fs::remove_dir_all",
    "std::fs::copy", "fs::copy",
    "std::fs::rename", "fs::rename",
    "std::fs::create_dir", "fs::create_dir",
    "std::fs::create_dir_all", "fs::create_dir_all",
    "std::fs::File::create", "File::create",
    "std::fs::File::open", "File::open",
    "Path::new", "PathBuf::from",
];

/// Rust network / SSRF sinks.
pub const RUST_NET_SINKS: &[&str] = &[
    "std::net::TcpStream::connect", "TcpStream::connect", "connect",
    "std::net::UdpSocket::connect", "UdpSocket::connect",
    "get", "post", "put", "delete", "head", "patch", "request",
];

/// Rust database query sinks.
pub const RUST_DB_SINKS: &[&str] = &[
    "query", "query_as", "query_scalar", "execute",
    "fetch_all", "fetch_one", "fetch_optional", "fetch",
    "sql", "sql_query",
];

/// Rust environment / CLI sources.
pub const RUST_ENV_SOURCES: &[&str] = &[
    "std::env::var", "env::var",
    "std::env::var_os", "env::var_os",
    "std::env::args", "env::args",
    "std::env::args_os", "env::args_os",
    "vars",
    "parse", "get_one", "get_many", "value_of", "values_of",
];

/// Rust I/O sources.
pub const RUST_IO_SOURCES: &[&str] = &[
    "read_line", "read_to_end", "read_to_string", "lines", "read", "read_exact",
    "std::fs::read_to_string", "fs::read_to_string",
    "std::fs::read", "fs::read",
    "std::fs::read_dir", "fs::read_dir",
    "recv", "recv_from", "peek",
];
