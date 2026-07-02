/// Multi-language security patterns for the web-ql taint engine.
///
/// Each language is in its own sub-module:
///
/// | Module         | Language(s)               | Key naming form      |
/// |----------------|---------------------------|----------------------|
/// | [`c`]          | C / POSIX / Windows / GLib| bare function name   |
/// | [`cpp`]        | C++ (superset of C)       | bare / qualified     |
/// | [`java`]       | Java (JDK + frameworks)   | bare method name     |
/// | [`javascript`] | JavaScript / Node.js      | bare function name   |
/// | [`typescript`] | TypeScript ecosystem      | bare function name   |
/// | [`go`]         | Go standard library       | unqualified selector |
/// | [`rust`]       | Rust std + popular crates | path or method name  |
///
/// # Combined API
///
/// The free functions at the bottom of this module search across all
/// languages simultaneously and are the primary entry point for analysis:
///
/// ```rust
/// use web_ql::security_patterns as sp;
///
/// if let Some(spec) = sp::get_source_spec("getParameter") {
///     // Java HttpServletRequest.getParameter is a taint source
/// }
/// if let Some(spec) = sp::get_sink_spec("Getenv") {
///     // Go os.Getenv — matches via short selector form
/// }
/// ```
///
/// # C / C++ delegation
///
/// The C and C++ tables are the authoritative `web_sitter::security_patterns`
/// tables (which hold thousands of C/POSIX/Windows/C++ entries).  They are
/// re-exported here so callers need only this crate.

pub mod c;
pub mod cpp;
pub mod java;
pub mod javascript;
pub mod typescript;
pub mod go;
pub mod rust;

// ── Re-export the spec types so consumers use a single import path ─────────
pub use web_sitter::security_patterns::{
    AllocSpec, PropagatorSpec, SinkSpec, SourceSpec,
};

// ── Re-export C/C++ canonical helper functions ─────────────────────────────
pub use c::{
    c_get_propagator,
    c_get_source_spec,
    c_get_sink_spec,
    c_get_alloc_spec,
    c_is_known_stdlib,
    c_is_string_dup_op,
    c_is_bounded_copy_op,
    c_is_dealloc_or_assert,
    c_builtin_sets,
    // Named constant sets
    BUILTIN_SET_C_IO_SOURCES,
    BUILTIN_SET_FILE_OPS,
    BUILTIN_SET_EXEC_OPS,
    BUILTIN_SET_ALLOC_OPS,
    BUILTIN_SET_STRING_COPY_OPS,
    BUILTIN_SET_PATH_SANITIZERS,
    BUILTIN_SET_COMMAND_SANITIZERS,
    BUILTIN_SET_STRING_DUP_OPS,
    BUILTIN_SET_BOUNDED_COPY_OPS,
    NORETURN_FUNCTIONS,
    FREE_FUNCTIONS,
    DEALLOC_OR_ASSERT_CALLS,
    PRIVILEGE_FUNCTIONS,
    RESOURCE_OPENERS,
    RESOURCE_CLOSERS,
    STRING_TO_INT_FUNCTIONS,
    MISC_STDLIB,
    PTHREAD_FUNCTIONS,
};

use std::collections::{BTreeMap, HashMap};
use std::sync::LazyLock;

/// Map every `Call` node id in `cpg` to its resolved callee name.
///
/// `IrNode::name` is NOT populated for `Call` nodes by every language's
/// lifter — for C, for example, the callee identifier lives in a separate
/// child `Identifier` node, and the `Call` node's own `.name` is `None`. The
/// query engine's `n.callee_name()` (see `engine.rs`) already knows this and
/// resolves through `cpg.call_graph`'s per-call-site `CallSite.callee`
/// instead (mirrored here from `KindIndex::build`'s `call_site_by_node`
/// index). Any code matching taint sources/sinks/propagators by callee name
/// against `node.name` directly — as this module's registry used to — silently
/// matches nothing for those languages. Falls back to `node.name` for
/// languages/node shapes where it *is* populated directly.
fn callee_names_by_node(cpg: &web_sitter::Cpg) -> HashMap<web_sitter::NodeId, String> {
    let mut names: HashMap<web_sitter::NodeId, String> = HashMap::new();
    for entry in cpg.call_graph.values() {
        for cs in &entry.calls {
            if let Some(call_id) = cs.call_site {
                names.insert(call_id, cs.callee.clone());
            }
        }
    }
    for (&id, node) in &cpg.ast {
        if node.kind == web_sitter::IrNodeKind::Call {
            if let Some(name) = &node.name {
                names.entry(id).or_insert_with(|| name.clone());
            }
        }
    }
    names
}

/// Resolve the `idx`-th argument node of a `Call`, descending into the
/// `argument_list`/`arguments` container child most languages wrap arguments
/// in (falling back to the call node's direct children for shapes that
/// don't). Mirrors the `arg()` node method in `engine.rs`.
fn call_arg_node(cpg: &web_sitter::Cpg, call_id: web_sitter::NodeId, idx: usize) -> Option<web_sitter::NodeId> {
    let node = cpg.ast.get(&call_id)?;
    let arg_id = node.children.iter().find_map(|&cid| {
        let child = cpg.ast.get(&cid)?;
        if matches!(child.node_type.as_str(), "argument_list" | "arguments") {
            child.children.get(idx).copied()
        } else {
            None
        }
    });
    arg_id.or_else(|| node.children.get(idx).copied())
}

// =============================================================================
// Combined static lookup maps (all languages)
// =============================================================================

// ── Sources ─────────────────────────────────────────────────────────────────

static ALL_SOURCE_MAP: LazyLock<std::collections::HashMap<&'static str, &'static SourceSpec>> =
    LazyLock::new(|| {
        let mut m = std::collections::HashMap::new();
        // C/C++ (from web_sitter; thousands of entries)
        for (name, spec) in c::C_TAINT_SOURCES.iter() {
            m.insert(*name, spec);
        }
        // Language-specific additions; later entries override C if names collide
        // (prefer the more language-specific spec when there is overlap).
        for (name, spec) in cpp::CPP_TAINT_SOURCES.iter() {
            m.insert(*name, spec);
        }
        for (name, spec) in java::JAVA_TAINT_SOURCES.iter() {
            m.insert(*name, spec);
        }
        for (name, spec) in javascript::JS_TAINT_SOURCES.iter() {
            m.insert(*name, spec);
        }
        for (name, spec) in typescript::TS_TAINT_SOURCES.iter() {
            m.insert(*name, spec);
        }
        for (name, spec) in go::GO_TAINT_SOURCES.iter() {
            m.insert(*name, spec);
        }
        for (name, spec) in rust::RUST_TAINT_SOURCES.iter() {
            m.insert(*name, spec);
        }
        m
    });

// ── Sinks ────────────────────────────────────────────────────────────────────

static ALL_SINK_MAP: LazyLock<std::collections::HashMap<&'static str, &'static SinkSpec>> =
    LazyLock::new(|| {
        let mut m = std::collections::HashMap::new();
        for (name, spec) in c::C_TAINT_SINKS.iter() {
            m.insert(*name, spec);
        }
        for (name, spec) in cpp::CPP_TAINT_SINKS.iter() {
            m.insert(*name, spec);
        }
        for (name, spec) in java::JAVA_TAINT_SINKS.iter() {
            m.insert(*name, spec);
        }
        for (name, spec) in javascript::JS_TAINT_SINKS.iter() {
            m.insert(*name, spec);
        }
        for (name, spec) in typescript::TS_TAINT_SINKS.iter() {
            m.insert(*name, spec);
        }
        for (name, spec) in go::GO_TAINT_SINKS.iter() {
            m.insert(*name, spec);
        }
        for (name, spec) in rust::RUST_TAINT_SINKS.iter() {
            m.insert(*name, spec);
        }
        m
    });

// ── Propagators ───────────────────────────────────────────────────────────────

static ALL_PROPAGATOR_MAP: LazyLock<std::collections::HashMap<&'static str, &'static PropagatorSpec>> =
    LazyLock::new(|| {
        let mut m = std::collections::HashMap::new();
        for (name, spec) in c::C_TAINT_PROPAGATORS.iter() {
            m.insert(*name, spec);
        }
        for (name, spec) in cpp::CPP_TAINT_PROPAGATORS.iter() {
            m.insert(*name, spec);
        }
        for (name, spec) in java::JAVA_TAINT_PROPAGATORS.iter() {
            m.insert(*name, spec);
        }
        for (name, spec) in javascript::JS_TAINT_PROPAGATORS.iter() {
            m.insert(*name, spec);
        }
        for (name, spec) in typescript::TS_TAINT_PROPAGATORS.iter() {
            m.insert(*name, spec);
        }
        for (name, spec) in go::GO_TAINT_PROPAGATORS.iter() {
            m.insert(*name, spec);
        }
        for (name, spec) in rust::RUST_TAINT_PROPAGATORS.iter() {
            m.insert(*name, spec);
        }
        m
    });

// =============================================================================
// Per-language lookup helpers
// =============================================================================

/// Language tag used to narrow lookups to a single language's tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    C,
    Cpp,
    Java,
    JavaScript,
    TypeScript,
    Go,
    Rust,
}

/// Returns the [`SourceSpec`] for `name` in the given `language` table only.
/// Prefer [`get_source_spec`] for cross-language lookups.
pub fn get_source_spec_for(name: &str, lang: Language) -> Option<&'static SourceSpec> {
    let table: &[(&str, SourceSpec)] = match lang {
        Language::C | Language::Cpp  => c::C_TAINT_SOURCES,
        Language::Java               => java::JAVA_TAINT_SOURCES,
        Language::JavaScript         => javascript::JS_TAINT_SOURCES,
        Language::TypeScript         => typescript::TS_TAINT_SOURCES,
        Language::Go                 => go::GO_TAINT_SOURCES,
        Language::Rust               => rust::RUST_TAINT_SOURCES,
    };
    table.iter().find(|(n, _)| *n == name).map(|(_, s)| s)
}

/// Returns the [`SinkSpec`] for `name` in the given `language` table only.
pub fn get_sink_spec_for(name: &str, lang: Language) -> Option<&'static SinkSpec> {
    let table: &[(&str, SinkSpec)] = match lang {
        Language::C | Language::Cpp  => c::C_TAINT_SINKS,
        Language::Java               => java::JAVA_TAINT_SINKS,
        Language::JavaScript         => javascript::JS_TAINT_SINKS,
        Language::TypeScript         => typescript::TS_TAINT_SINKS,
        Language::Go                 => go::GO_TAINT_SINKS,
        Language::Rust               => rust::RUST_TAINT_SINKS,
    };
    table.iter().find(|(n, _)| *n == name).map(|(_, s)| s)
}

/// Returns the [`PropagatorSpec`] for `name` in the given `language` table only.
pub fn get_propagator_for(name: &str, lang: Language) -> Option<&'static PropagatorSpec> {
    let table: &[(&str, PropagatorSpec)] = match lang {
        Language::C | Language::Cpp  => c::C_TAINT_PROPAGATORS,
        Language::Java               => java::JAVA_TAINT_PROPAGATORS,
        Language::JavaScript         => javascript::JS_TAINT_PROPAGATORS,
        Language::TypeScript         => typescript::TS_TAINT_PROPAGATORS,
        Language::Go                 => go::GO_TAINT_PROPAGATORS,
        Language::Rust               => rust::RUST_TAINT_PROPAGATORS,
    };
    table.iter().find(|(n, _)| *n == name).map(|(_, s)| s)
}

// =============================================================================
// Cross-language lookup functions (primary API)
// =============================================================================

/// Returns the [`SourceSpec`] for `name` across **all** language tables.
///
/// When the same bare name appears in multiple language tables (e.g., `"read"`
/// is both a C I/O function and a Java/Go method), the first match wins in
/// table-insert order (C → C++ → Java → JS → TS → Go → Rust).  Use
/// [`get_source_spec_for`] to query a specific language.
#[inline]
pub fn get_source_spec(name: &str) -> Option<&'static SourceSpec> {
    ALL_SOURCE_MAP.get(name).copied()
}

/// Returns the [`SinkSpec`] for `name` across **all** language tables.
#[inline]
pub fn get_sink_spec(name: &str) -> Option<&'static SinkSpec> {
    ALL_SINK_MAP.get(name).copied()
}

/// Returns the [`PropagatorSpec`] for `name` across **all** language tables.
#[inline]
pub fn get_propagator(name: &str) -> Option<&'static PropagatorSpec> {
    ALL_PROPAGATOR_MAP.get(name).copied()
}

/// Returns the C/POSIX/Windows/C++ [`AllocSpec`] for `name`.
/// Heap allocation is a C/C++ concept; no equivalent exists for other languages.
#[inline]
pub fn get_alloc_spec(name: &str) -> Option<&'static AllocSpec> {
    c_get_alloc_spec(name)
}

/// Returns `true` if `name` is a security-relevant function in **any** language.
pub fn is_known_stdlib(name: &str) -> bool {
    get_source_spec(name).is_some()
        || get_sink_spec(name).is_some()
        || get_propagator(name).is_some()
        || get_alloc_spec(name).is_some()
        || c_is_known_stdlib(name)
}

// =============================================================================
// Combined named-set registry
// =============================================================================

/// Returns a `BTreeMap` of all named builtin sets, merged across all languages.
///
/// Keys are `"language.set_name"` strings, e.g. `"c.exec_ops"`,
/// `"java.sql_sinks"`, `"go.env_sources"`.  Values are sorted lists of
/// member function names.
pub fn builtin_sets() -> BTreeMap<String, Vec<String>> {
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();

    macro_rules! insert_set {
        ($prefix:expr, $key:expr, $slice:expr) => {
            map.insert(
                format!("{}.{}", $prefix, $key),
                $slice.iter().map(|s| s.to_string()).collect(),
            );
        };
    }

    // ── C / POSIX / Windows ───────────────────────────────────────────────────
    insert_set!("c", "io_sources",          BUILTIN_SET_C_IO_SOURCES);
    insert_set!("c", "file_ops",            BUILTIN_SET_FILE_OPS);
    insert_set!("c", "exec_ops",            BUILTIN_SET_EXEC_OPS);
    insert_set!("c", "alloc_ops",           BUILTIN_SET_ALLOC_OPS);
    insert_set!("c", "string_copy_ops",     BUILTIN_SET_STRING_COPY_OPS);
    insert_set!("c", "path_sanitizers",     BUILTIN_SET_PATH_SANITIZERS);
    insert_set!("c", "command_sanitizers",  BUILTIN_SET_COMMAND_SANITIZERS);
    insert_set!("c", "string_dup_ops",      BUILTIN_SET_STRING_DUP_OPS);
    insert_set!("c", "bounded_copy_ops",    BUILTIN_SET_BOUNDED_COPY_OPS);
    insert_set!("c", "noreturn",            NORETURN_FUNCTIONS);
    insert_set!("c", "free_functions",      FREE_FUNCTIONS);
    insert_set!("c", "dealloc_or_assert",   DEALLOC_OR_ASSERT_CALLS);
    insert_set!("c", "privilege",           PRIVILEGE_FUNCTIONS);
    insert_set!("c", "resource_openers",    RESOURCE_OPENERS);
    insert_set!("c", "resource_closers",    RESOURCE_CLOSERS);
    insert_set!("c", "string_to_int",       STRING_TO_INT_FUNCTIONS);
    insert_set!("c", "misc_stdlib",         MISC_STDLIB);
    insert_set!("c", "pthread",             PTHREAD_FUNCTIONS);

    // ── C++ ───────────────────────────────────────────────────────────────────
    insert_set!("cpp", "format_sinks",      cpp::CPP_FORMAT_SINKS);
    insert_set!("cpp", "exec_ops",          cpp::CPP_EXEC_OPS);

    // ── Java ──────────────────────────────────────────────────────────────────
    insert_set!("java", "http_sources",         java::JAVA_HTTP_SOURCES);
    insert_set!("java", "sql_sinks",            java::JAVA_SQL_SINKS);
    insert_set!("java", "exec_sinks",           java::JAVA_EXEC_SINKS);
    insert_set!("java", "reflection_sinks",     java::JAVA_REFLECTION_SINKS);
    insert_set!("java", "deserialization_sources", java::JAVA_DESERIALIZATION_SOURCES);
    insert_set!("java", "http_response_sinks",  java::JAVA_HTTP_RESPONSE_SINKS);
    insert_set!("java", "log_sinks",            java::JAVA_LOG_SINKS);
    insert_set!("java", "jndi_sinks",           java::JAVA_JNDI_SINKS);
    insert_set!("java", "xpath_sinks",          java::JAVA_XPATH_SINKS);
    insert_set!("java", "ldap_sinks",           java::JAVA_LDAP_SINKS);
    insert_set!("java", "xxe_sinks",            java::JAVA_XXE_SINKS);
    insert_set!("java", "template_sinks",       java::JAVA_TEMPLATE_SINKS);
    insert_set!("java", "ssrf_sinks",           java::JAVA_SSRF_SINKS);

    // ── JavaScript ────────────────────────────────────────────────────────────
    insert_set!("js", "dom_xss_sinks",      javascript::JS_DOM_XSS_SINKS);
    insert_set!("js", "exec_sinks",         javascript::JS_EXEC_SINKS);
    insert_set!("js", "file_write_sinks",   javascript::JS_FILE_WRITE_SINKS);
    insert_set!("js", "db_sinks",           javascript::JS_DB_SINKS);
    insert_set!("js", "ssrf_sinks",         javascript::JS_SSRF_SINKS);
    insert_set!("js", "eval_sinks",         javascript::JS_EVAL_SINKS);
    insert_set!("js", "template_sinks",     javascript::JS_TEMPLATE_SINKS);
    insert_set!("js", "redirect_sinks",     javascript::JS_REDIRECT_SINKS);
    insert_set!("js", "deserialization_sinks", javascript::JS_DESERIALIZATION_SINKS);
    insert_set!("js", "ldap_sinks",         javascript::JS_LDAP_SINKS);
    insert_set!("js", "vm_sinks",           javascript::JS_VM_SINKS);

    // ── TypeScript ────────────────────────────────────────────────────────────
    insert_set!("ts", "typeorm_sinks",      typescript::TS_TYPEORM_SINKS);
    insert_set!("ts", "prisma_raw_sinks",   typescript::TS_PRISMA_RAW_SINKS);
    insert_set!("ts", "angular_bypass_sinks", typescript::TS_ANGULAR_BYPASS_SINKS);
    insert_set!("ts", "nestjs_sources",     typescript::TS_NESTJS_SOURCES);

    // ── Go ────────────────────────────────────────────────────────────────────
    insert_set!("go", "exec_sinks",         go::GO_EXEC_SINKS);
    insert_set!("go", "sql_sinks",          go::GO_SQL_SINKS);
    insert_set!("go", "file_sinks",         go::GO_FILE_SINKS);
    insert_set!("go", "net_sinks",          go::GO_NET_SINKS);
    insert_set!("go", "http_response_sinks",go::GO_HTTP_RESPONSE_SINKS);
    insert_set!("go", "template_sinks",     go::GO_TEMPLATE_SINKS);
    insert_set!("go", "env_sources",        go::GO_ENV_SOURCES);
    insert_set!("go", "http_request_sources", go::GO_HTTP_REQUEST_SOURCES);
    insert_set!("go", "read_sources",       go::GO_READ_SOURCES);
    insert_set!("go", "flag_sources",       go::GO_FLAG_SOURCES);

    // ── Rust ──────────────────────────────────────────────────────────────────
    insert_set!("rust", "exec_sinks",       rust::RUST_EXEC_SINKS);
    insert_set!("rust", "file_sinks",       rust::RUST_FILE_SINKS);
    insert_set!("rust", "net_sinks",        rust::RUST_NET_SINKS);
    insert_set!("rust", "db_sinks",         rust::RUST_DB_SINKS);
    insert_set!("rust", "env_sources",      rust::RUST_ENV_SOURCES);
    insert_set!("rust", "io_sources",       rust::RUST_IO_SOURCES);

    // Also merge the C builtin_sets map under the "c" namespace
    for (k, v) in c_builtin_sets() {
        map.entry(format!("c.{k}")).or_insert(v);
    }

    map
}

// =============================================================================
// Convenience: source / sink name sets (all languages, flat)
// =============================================================================

/// Returns all source function names across every language as a sorted `Vec`.
pub fn all_source_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = ALL_SOURCE_MAP.keys().copied().collect();
    names.sort_unstable();
    names.dedup();
    names
}

/// Returns all sink function names across every language as a sorted `Vec`.
pub fn all_sink_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = ALL_SINK_MAP.keys().copied().collect();
    names.sort_unstable();
    names.dedup();
    names
}

/// Returns all propagator function names across every language as a sorted `Vec`.
pub fn all_propagator_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = ALL_PROPAGATOR_MAP.keys().copied().collect();
    names.sort_unstable();
    names.dedup();
    names
}

// =============================================================================
// Built-in endpoint registry (for `.wql` queries referencing security_patterns)
// =============================================================================

/// Build an [`EndpointRegistry`] pre-populated with all security_patterns builtin sets.
///
/// The registered names follow the pattern `"<language>.<set>"`, matching the
/// keys returned by [`builtin_sets()`]. For example:
///
/// ```wql
/// taint {
///     sources: ["c.io_sources"]
///     sinks:   ["c.exec_ops"]
///     sanitizers: ["c.command_sanitizers"]
/// }
/// ```
///
/// Short aliases without the language prefix are also registered for the most
/// common cross-language sets (e.g. `"io_sources"` → C I/O sources).
pub fn builtin_endpoint_registry() -> crate::taint::EndpointRegistry {
    use web_sitter::IrNodeKind;
    let mut registry = crate::taint::EndpointRegistry::new();

    // ── Helper macro: register a builtin set as a source (Call nodes whose name is in the set)
    macro_rules! reg_source {
        ($registry:expr, $name:expr, $set:expr) => {{
            let set: &'static [&'static str] = $set;
            $registry.register($name, move |cpg| {
                let call_names = callee_names_by_node(cpg);
                cpg.ast.iter()
                    .filter(|(id, n)| {
                        n.kind == IrNodeKind::Call &&
                        call_names.get(id).map_or(false, |nm| set.contains(&nm.as_str()))
                    })
                    .map(|(id, _)| *id)
                    .collect()
            });
        }};
    }

    // ── Helper macro: register a builtin set as a sink.
    //
    // Unlike sources (whose seed is the call's *return value*, so the whole
    // Call node is the right taint-graph anchor), a sink's danger lives in a
    // specific *argument* — DFG edges never target the enclosing Call node
    // itself unless that function also happens to be a registered taint
    // propagator (see `add_taint_propagator_edges` in web-sitter/src/dfg.rs,
    // which adds a `src_arg -> call_id` edge only for the propagator table).
    // Registering the Call node as the sink for a pure sink (e.g. `system`,
    // `fopen`, non-propagating `exec`/file-open calls) meant taint could
    // never reach it: there is simply no edge ending there. Resolve each
    // matched call's actual dangerous argument(s) via its `SinkSpec` instead,
    // so the sink anchor is a node the DFG can actually flow taint into.
    // Falls back to the call node itself when no `SinkSpec` is registered
    // for that name (better than never matching at all).
    macro_rules! reg_sink {
        ($registry:expr, $name:expr, $set:expr) => {{
            let set: &'static [&'static str] = $set;
            $registry.register($name, move |cpg| {
                let call_names = callee_names_by_node(cpg);
                let mut out = Vec::new();
                for (id, n) in cpg.ast.iter() {
                    if n.kind != IrNodeKind::Call {
                        continue;
                    }
                    let Some(callee) = call_names.get(id) else { continue };
                    if !set.contains(&callee.as_str()) {
                        continue;
                    }
                    match get_sink_spec(callee.as_str()) {
                        Some(spec) if !spec.sink_args.is_empty() => {
                            for &arg_idx in spec.sink_args {
                                if let Some(arg_id) = call_arg_node(cpg, *id, arg_idx as usize) {
                                    out.push(arg_id);
                                }
                            }
                        }
                        _ => out.push(*id),
                    }
                }
                out
            });
        }};
    }

    // ── Helper macro: register a PropagatorSpec table as a named propagator.
    // Mirrors `add_taint_propagator_edges` in web-sitter/src/dfg.rs (which
    // wires the base C/POSIX `TAINT_PROPAGATORS` table into DFG edges
    // automatically), but for the per-language tables in this crate
    // (CPP_TAINT_PROPAGATORS, JAVA_TAINT_PROPAGATORS, JS_TAINT_PROPAGATORS,
    // etc.) that web-sitter can't see (wrong crate layer). Those tables were
    // previously dead: defined but never consulted by anything.
    macro_rules! reg_propagator {
        ($registry:expr, $name:expr, $table:expr) => {{
            let table: &'static [(&'static str, PropagatorSpec)] = $table;
            $registry.register_propagator($name, move |cpg| propagator_edges_for(cpg, table));
        }};
    }

    // ── C / POSIX / Windows ──────────────────────────────────────────────────
    reg_source!(registry, "c.io_sources",         BUILTIN_SET_C_IO_SOURCES);
    reg_sink!(  registry, "c.exec_ops",           BUILTIN_SET_EXEC_OPS);
    reg_sink!(  registry, "c.file_ops",           BUILTIN_SET_FILE_OPS);
    reg_sink!(  registry, "c.alloc_ops",          BUILTIN_SET_ALLOC_OPS);
    reg_sink!(  registry, "c.string_copy_ops",    BUILTIN_SET_STRING_COPY_OPS);
    reg_source!(registry, "c.string_dup_ops",     BUILTIN_SET_STRING_DUP_OPS);
    reg_sink!(  registry, "c.bounded_copy_ops",   BUILTIN_SET_BOUNDED_COPY_OPS);
    reg_source!(registry, "c.path_sanitizers",    BUILTIN_SET_PATH_SANITIZERS);
    reg_source!(registry, "c.command_sanitizers", BUILTIN_SET_COMMAND_SANITIZERS);
    reg_sink!(  registry, "c.free_functions",     FREE_FUNCTIONS);
    reg_sink!(  registry, "c.dealloc_or_assert",  DEALLOC_OR_ASSERT_CALLS);
    reg_source!(registry, "c.noreturn",           NORETURN_FUNCTIONS);
    reg_source!(registry, "c.misc_stdlib",        MISC_STDLIB);
    reg_source!(registry, "c.pthread",            PTHREAD_FUNCTIONS);
    reg_source!(registry, "c.resource_openers",   RESOURCE_OPENERS);
    reg_sink!(  registry, "c.resource_closers",   RESOURCE_CLOSERS);
    reg_source!(registry, "c.string_to_int",      STRING_TO_INT_FUNCTIONS);
    reg_source!(registry, "c.privilege",          PRIVILEGE_FUNCTIONS);
    // Also registered as a named propagator for explicit `propagators:` use;
    // already applied unconditionally to DFG edges in web-sitter's
    // add_taint_propagator_edges, so this is redundant-but-harmless there —
    // the default-application wiring below is what actually matters for the
    // *other* languages' tables, which have no such DFG-level equivalent.
    reg_propagator!(registry, "c.propagators", c::C_TAINT_PROPAGATORS);

    // ── C++ ──────────────────────────────────────────────────────────────────
    reg_sink!(registry, "cpp.format_sinks", cpp::CPP_FORMAT_SINKS);
    reg_propagator!(registry, "cpp.propagators", cpp::CPP_TAINT_PROPAGATORS);
    reg_sink!(registry, "cpp.exec_ops",     cpp::CPP_EXEC_OPS);

    // ── Java ─────────────────────────────────────────────────────────────────
    reg_source!(registry, "java.http_sources",            java::JAVA_HTTP_SOURCES);
    reg_sink!(  registry, "java.sql_sinks",               java::JAVA_SQL_SINKS);
    reg_sink!(  registry, "java.exec_sinks",              java::JAVA_EXEC_SINKS);
    reg_sink!(  registry, "java.reflection_sinks",        java::JAVA_REFLECTION_SINKS);
    reg_source!(registry, "java.deserialization_sources", java::JAVA_DESERIALIZATION_SOURCES);
    reg_sink!(  registry, "java.http_response_sinks",     java::JAVA_HTTP_RESPONSE_SINKS);
    reg_sink!(  registry, "java.log_sinks",               java::JAVA_LOG_SINKS);
    reg_sink!(  registry, "java.jndi_sinks",              java::JAVA_JNDI_SINKS);
    reg_sink!(  registry, "java.xpath_sinks",             java::JAVA_XPATH_SINKS);
    reg_sink!(  registry, "java.ldap_sinks",              java::JAVA_LDAP_SINKS);
    reg_sink!(  registry, "java.xxe_sinks",               java::JAVA_XXE_SINKS);
    reg_sink!(  registry, "java.template_sinks",          java::JAVA_TEMPLATE_SINKS);
    reg_sink!(  registry, "java.ssrf_sinks",              java::JAVA_SSRF_SINKS);
    reg_propagator!(registry, "java.propagators",         java::JAVA_TAINT_PROPAGATORS);

    // ── JavaScript ───────────────────────────────────────────────────────────
    reg_sink!(  registry, "js.dom_xss_sinks",         javascript::JS_DOM_XSS_SINKS);
    reg_sink!(  registry, "js.exec_sinks",            javascript::JS_EXEC_SINKS);
    reg_sink!(  registry, "js.file_write_sinks",      javascript::JS_FILE_WRITE_SINKS);
    reg_sink!(  registry, "js.db_sinks",              javascript::JS_DB_SINKS);
    reg_sink!(  registry, "js.ssrf_sinks",            javascript::JS_SSRF_SINKS);
    reg_sink!(  registry, "js.eval_sinks",            javascript::JS_EVAL_SINKS);
    reg_sink!(  registry, "js.template_sinks",        javascript::JS_TEMPLATE_SINKS);
    reg_sink!(  registry, "js.redirect_sinks",        javascript::JS_REDIRECT_SINKS);
    reg_sink!(  registry, "js.deserialization_sinks", javascript::JS_DESERIALIZATION_SINKS);
    reg_sink!(  registry, "js.ldap_sinks",            javascript::JS_LDAP_SINKS);
    reg_sink!(  registry, "js.vm_sinks",              javascript::JS_VM_SINKS);
    reg_propagator!(registry, "js.propagators",       javascript::JS_TAINT_PROPAGATORS);
    // `Cpg::language` is the full name ("javascript"/"typescript", see
    // SourceLanguage::as_str in web-sitter/src/cpg_generator.rs), not the
    // "js"/"ts" short form used by the named sink sets above — register
    // under both so the `"{lang}.propagators"` auto-apply lookup in
    // `TaintEngine::run` resolves correctly.
    reg_propagator!(registry, "javascript.propagators", javascript::JS_TAINT_PROPAGATORS);

    // ── TypeScript ───────────────────────────────────────────────────────────
    reg_sink!(  registry, "ts.typeorm_sinks",         typescript::TS_TYPEORM_SINKS);
    reg_sink!(  registry, "ts.prisma_raw_sinks",      typescript::TS_PRISMA_RAW_SINKS);
    reg_sink!(  registry, "ts.angular_bypass_sinks",  typescript::TS_ANGULAR_BYPASS_SINKS);
    reg_source!(registry, "ts.nestjs_sources",        typescript::TS_NESTJS_SOURCES);
    reg_propagator!(registry, "ts.propagators",       typescript::TS_TAINT_PROPAGATORS);
    reg_propagator!(registry, "typescript.propagators", typescript::TS_TAINT_PROPAGATORS);

    // ── Go ───────────────────────────────────────────────────────────────────
    reg_sink!(  registry, "go.exec_sinks",              go::GO_EXEC_SINKS);
    reg_sink!(  registry, "go.sql_sinks",               go::GO_SQL_SINKS);
    reg_sink!(  registry, "go.file_sinks",              go::GO_FILE_SINKS);
    reg_sink!(  registry, "go.net_sinks",               go::GO_NET_SINKS);
    reg_sink!(  registry, "go.http_response_sinks",     go::GO_HTTP_RESPONSE_SINKS);
    reg_sink!(  registry, "go.template_sinks",          go::GO_TEMPLATE_SINKS);
    reg_source!(registry, "go.env_sources",             go::GO_ENV_SOURCES);
    reg_source!(registry, "go.http_request_sources",    go::GO_HTTP_REQUEST_SOURCES);
    reg_source!(registry, "go.read_sources",            go::GO_READ_SOURCES);
    reg_source!(registry, "go.flag_sources",            go::GO_FLAG_SOURCES);
    reg_propagator!(registry, "go.propagators",         go::GO_TAINT_PROPAGATORS);

    // ── Rust ─────────────────────────────────────────────────────────────────
    reg_sink!(  registry, "rust.exec_sinks",   rust::RUST_EXEC_SINKS);
    reg_sink!(  registry, "rust.file_sinks",   rust::RUST_FILE_SINKS);
    reg_sink!(  registry, "rust.net_sinks",    rust::RUST_NET_SINKS);
    reg_sink!(  registry, "rust.db_sinks",     rust::RUST_DB_SINKS);
    reg_source!(registry, "rust.env_sources",  rust::RUST_ENV_SOURCES);
    reg_source!(registry, "rust.io_sources",   rust::RUST_IO_SOURCES);
    reg_propagator!(registry, "rust.propagators", rust::RUST_TAINT_PROPAGATORS);

    registry
}

/// Extract `(source_node, dest_node)` taint-propagator edges for every `Call`
/// node in `cpg` whose callee name matches an entry in `table`. Mirrors the
/// argument-list extraction convention used throughout the engine (e.g.
/// `web-ql/src/engine.rs`'s `arg()` method): arguments live inside an
/// `argument_list`/`arguments` container child when present, else fall back
/// to the call node's raw children.
fn propagator_edges_for(
    cpg: &web_sitter::Cpg,
    table: &'static [(&'static str, PropagatorSpec)],
) -> Vec<(web_sitter::NodeId, web_sitter::NodeId)> {
    use web_sitter::IrNodeKind;

    fn call_arg_nodes(cpg: &web_sitter::Cpg, call_id: web_sitter::NodeId) -> Vec<web_sitter::NodeId> {
        let Some(node) = cpg.ast.get(&call_id) else { return Vec::new() };
        for &cid in &node.children {
            if let Some(child) = cpg.ast.get(&cid) {
                if matches!(child.node_type.as_str(), "argument_list" | "arguments") {
                    return child.children.clone();
                }
            }
        }
        node.children.clone()
    }

    let call_names = callee_names_by_node(cpg);
    let mut edges = Vec::new();
    for (&call_id, node) in cpg.ast.iter() {
        if node.kind != IrNodeKind::Call {
            continue;
        }
        let Some(name) = call_names.get(&call_id) else { continue };
        let Some((_, spec)) = table.iter().find(|(n, _)| *n == name.as_str()) else { continue };

        let args = call_arg_nodes(cpg, call_id);
        let dst_node = if spec.dst >= 0 {
            match args.get(spec.dst as usize) {
                Some(&n) => n,
                None => continue,
            }
        } else {
            // -1: return value is the destination, represented by the call
            // node itself (matches the convention used elsewhere for
            // return-tainting sources, e.g. `getenv`).
            call_id
        };

        let variadic_skip = (spec.dst.max(0) as usize).saturating_add(1);
        for &src_idx in spec.src {
            if src_idx == -1 {
                for &a in args.iter().skip(variadic_skip) {
                    edges.push((a, dst_node));
                }
            } else if let Some(&a) = args.get(src_idx as usize) {
                edges.push((a, dst_node));
            }
        }
    }
    edges
}
