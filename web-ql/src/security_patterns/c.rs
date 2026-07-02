/// C / POSIX / Windows security patterns.
///
/// All data is pulled directly from `web_sitter::security_patterns`, which
/// carries the canonical, exhaustive C/POSIX/Windows/GLib/OpenSSL/libcurl
/// coverage.  Nothing is duplicated here; this module is a thin re-export so
/// callers can import language-specific modules without pulling in unrelated
/// data.
// Re-export the core types so consumers of this module get them without
// additional imports.
pub use web_sitter::security_patterns::{AllocSpec, PropagatorSpec, SinkSpec, SourceSpec};

// Re-export every named constant and helper from the canonical source.
pub use web_sitter::security_patterns::{
    BUILTIN_SET_ALLOC_OPS,
    BUILTIN_SET_BOUNDED_COPY_OPS,
    // Named sets used by the rule loader
    BUILTIN_SET_C_IO_SOURCES,
    BUILTIN_SET_COMMAND_SANITIZERS,
    BUILTIN_SET_EXEC_OPS,
    BUILTIN_SET_FILE_OPS,
    BUILTIN_SET_PATH_SANITIZERS,
    BUILTIN_SET_STRING_COPY_OPS,
    BUILTIN_SET_STRING_DUP_OPS,
    DEALLOC_OR_ASSERT_CALLS,
    FREE_FUNCTIONS,
    HEAP_ALLOCATORS as C_HEAP_ALLOCATORS,
    MISC_STDLIB,
    NORETURN_FUNCTIONS,
    PRIVILEGE_FUNCTIONS,
    PTHREAD_FUNCTIONS,
    RESOURCE_CLOSERS,
    RESOURCE_OPENERS,
    STDLIB_TAINT_SINKS as C_TAINT_SINKS,
    // Primary data tables
    STDLIB_TAINT_SOURCES as C_TAINT_SOURCES,
    STRING_TO_INT_FUNCTIONS,
    TAINT_PROPAGATORS as C_TAINT_PROPAGATORS,
    builtin_sets as c_builtin_sets,
    get_alloc_spec as c_get_alloc_spec,
    // Helper fns
    get_propagator as c_get_propagator,
    get_sink_spec as c_get_sink_spec,
    get_source_spec as c_get_source_spec,
    is_bounded_copy_op as c_is_bounded_copy_op,
    is_dealloc_or_assert as c_is_dealloc_or_assert,
    is_known_stdlib as c_is_known_stdlib,
    is_string_dup_op as c_is_string_dup_op,
};
