/// C / POSIX / Windows security patterns.
///
/// All data is pulled directly from `web_sitter::security_patterns`, which
/// carries the canonical, exhaustive C/POSIX/Windows/GLib/OpenSSL/libcurl
/// coverage.  Nothing is duplicated here; this module is a thin re-export so
/// callers can import language-specific modules without pulling in unrelated
/// data.

// Re-export the core types so consumers of this module get them without
// additional imports.
pub use web_sitter::security_patterns::{
    AllocSpec, PropagatorSpec, SinkSpec, SourceSpec,
};

// Re-export every named constant and helper from the canonical source.
pub use web_sitter::security_patterns::{
    // Primary data tables
    STDLIB_TAINT_SOURCES  as C_TAINT_SOURCES,
    STDLIB_TAINT_SINKS    as C_TAINT_SINKS,
    TAINT_PROPAGATORS     as C_TAINT_PROPAGATORS,
    HEAP_ALLOCATORS       as C_HEAP_ALLOCATORS,
    // Named sets used by the rule loader
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
    // Helper fns
    get_propagator    as c_get_propagator,
    get_source_spec   as c_get_source_spec,
    get_sink_spec     as c_get_sink_spec,
    get_alloc_spec    as c_get_alloc_spec,
    is_known_stdlib   as c_is_known_stdlib,
    is_string_dup_op  as c_is_string_dup_op,
    is_bounded_copy_op as c_is_bounded_copy_op,
    is_dealloc_or_assert as c_is_dealloc_or_assert,
    builtin_sets      as c_builtin_sets,
};
