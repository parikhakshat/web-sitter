/// C++ security patterns.
///
/// C++ coverage (std::string, std::filesystem, Qt, Boost, OpenSSL C++ APIs,
/// etc.) lives in the same canonical table as C in `web_sitter::security_patterns`
/// because the C++ lifter processes the same node kinds.  This module
/// re-exports the combined table under C++-oriented aliases and adds any
/// additional pure-C++ patterns not present in web-sitter.

pub use super::c::{
    AllocSpec, PropagatorSpec, SinkSpec, SourceSpec,
    C_TAINT_SOURCES, C_TAINT_SINKS, C_TAINT_PROPAGATORS, C_HEAP_ALLOCATORS,
    BUILTIN_SET_EXEC_OPS, BUILTIN_SET_FILE_OPS, BUILTIN_SET_ALLOC_OPS,
    BUILTIN_SET_STRING_COPY_OPS, BUILTIN_SET_STRING_DUP_OPS, BUILTIN_SET_BOUNDED_COPY_OPS,
    NORETURN_FUNCTIONS, FREE_FUNCTIONS, DEALLOC_OR_ASSERT_CALLS,
    RESOURCE_OPENERS, RESOURCE_CLOSERS, PRIVILEGE_FUNCTIONS, PTHREAD_FUNCTIONS,
};

// ── Additional C++-only sources ───────────────────────────────────────────────

/// C++ stream / standard-library taint sources not fully covered by the
/// C table (operator>> semantics, std::getline, std::cin extraction).
/// Call nodes for these appear with the unqualified method name because the
/// C++ lifter's `short_callee_name` strips namespace prefixes.
pub const CPP_TAINT_SOURCES: &[(&str, SourceSpec)] = &[
    // std::cin >> var — the extraction operator writes attacker data into var.
    // Modelled as arg 0 (the variable) being tainted; no return taint.
    (
        "operator>>",
        SourceSpec { tainted_params: &[0], tainted_return: false },
    ),
    // std::getline(stream, str) — arg 1 (the string) receives tainted data.
    (
        "getline",
        SourceSpec { tainted_params: &[1], tainted_return: false },
    ),
    // boost::program_options / CLI11 / TCLAP parsed values
    (
        "as",          // po::variable_value::as<T>()
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
    (
        "value_of",
        SourceSpec { tainted_params: &[], tainted_return: true },
    ),
];

// ── Additional C++-only sinks ─────────────────────────────────────────────────

pub const CPP_TAINT_SINKS: &[(&str, SinkSpec)] = &[
    // std::system / popen are already in C; list C++ wrappers
    ("boost::process::system",  SinkSpec { sink_args: &[0] }),
    ("boost::process::child",   SinkSpec { sink_args: &[0] }),
    // Qt process execution
    ("QProcess::start",         SinkSpec { sink_args: &[0] }),
    ("QProcess::startDetached", SinkSpec { sink_args: &[0] }),
    // Poco::Process
    ("Poco::Process::launch",   SinkSpec { sink_args: &[0] }),
    // C++ format library (fmt::format_to_n with attacker-controlled format)
    ("fmt::format",             SinkSpec { sink_args: &[0] }),
    ("fmt::vformat",            SinkSpec { sink_args: &[0] }),
    // std::filesystem — path traversal sinks
    ("std::filesystem::remove",     SinkSpec { sink_args: &[0] }),
    ("std::filesystem::remove_all", SinkSpec { sink_args: &[0] }),
    ("std::filesystem::rename",     SinkSpec { sink_args: &[0, 1] }),
    ("std::filesystem::copy",       SinkSpec { sink_args: &[0, 1] }),
    ("std::filesystem::copy_file",  SinkSpec { sink_args: &[0, 1] }),
    // Poco::Net HTTP client — SSRF
    ("Poco::Net::HTTPClientSession::sendRequest", SinkSpec { sink_args: &[0] }),
    // libcurl C++ wrappers
    ("curlpp::Easy::setOpt",    SinkSpec { sink_args: &[0, 1] }),
];

// ── C++-only propagators ──────────────────────────────────────────────────────

pub const CPP_TAINT_PROPAGATORS: &[(&str, PropagatorSpec)] = &[
    // std::string::append(str) — return value and *this are tainted if arg tainted
    ("append",  PropagatorSpec { dst: -1, src: &[0] }),
    // std::string::insert(pos, str) — return value is tainted
    ("insert",  PropagatorSpec { dst: -1, src: &[1] }),
    // std::string::replace(pos, len, str) — return value
    ("replace", PropagatorSpec { dst: -1, src: &[2] }),
    // std::string::substr(pos, len) — return value is slice of tainted
    ("substr",  PropagatorSpec { dst: -1, src: &[0] }),
    // std::to_string(val) — return value
    ("to_string", PropagatorSpec { dst: -1, src: &[0] }),
    // fmt::format(fmt_str, args...) — return value
    ("format",    PropagatorSpec { dst: -1, src: &[-1] }),
    // std::string + operator  (handled as unnamed operator+ call)
    ("operator+", PropagatorSpec { dst: -1, src: &[0, 1] }),
    // Ranges / views — pass taint through lazily
    ("std::views::transform", PropagatorSpec { dst: -1, src: &[0] }),
    ("std::views::filter",    PropagatorSpec { dst: -1, src: &[0] }),
];

/// Named set: C++ string-manipulation sinks that are dangerous when the
/// format string or path comes from user input.
pub const CPP_FORMAT_SINKS: &[&str] = &[
    "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf", "vsprintf", "vsnprintf",
    "fmt::print", "fmt::println", "fmt::format",
    "std::format", "std::vformat",
    "QDebug::operator<<",
];

/// C++ command execution — superset of C BUILTIN_SET_EXEC_OPS.
pub const CPP_EXEC_OPS: &[&str] = &[
    "system", "popen",
    "execl", "execle", "execlp", "execv", "execve", "execvp", "execvpe",
    "boost::process::system", "boost::process::child",
    "QProcess::start", "QProcess::startDetached",
    "Poco::Process::launch",
];
