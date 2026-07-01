/*
 * interprocedural_wrapper_test.c
 *
 * Tests interprocedural taint analysis through wrapper functions.
 * Exercises source wrappers, sink wrappers, propagator wrappers,
 * free wrappers, and bounded-copy wrappers with the full rule-matcher.
 *
 * All test function names start with vuln_ or safe_ so they are
 * automatically tracked by the finding-matrix runner.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* =========================================================================
 * SOURCE WRAPPERS
 * =========================================================================
 *
 * These thin wrappers forward calls to recognised taint sources
 * (getenv, fgets).  The CPG builds INTERPROCEDURAL_FLOW edges from the
 * wrapper's return value back to the caller, so the taint originating
 * inside the wrapper is still visible at the call site.
 */

/* Wraps getenv – return value carries attacker-controlled taint */
static char *env_read(const char *name) {
    return getenv(name);
}

/* Wraps fgets – the buffer filled by this wrapper is tainted */
static char g_stdin_buf[512];
static char *stdin_read(void) {
    if (!fgets(g_stdin_buf, (int)sizeof(g_stdin_buf), stdin))
        return NULL;
    g_stdin_buf[strcspn(g_stdin_buf, "\n")] = '\0';
    return g_stdin_buf;
}

/* =========================================================================
 * PROPAGATOR WRAPPERS
 *
 * These wrappers copy or forward their input – taint passes through.
 */

/* strdup propagates taint: output taint = input taint */
static char *dup_tainted(const char *s) {
    return strdup(s);
}

/* =========================================================================
 * SINK WRAPPERS
 *
 * These wrappers forward to recognised dangerous sinks.
 * The CPG propagates taint through argument→parameter edges, so
 * tainted data passed to these wrappers reaches the actual sink.
 */

/* Wraps fopen – tainted path leads to CWE-22 */
static FILE *open_path(const char *path) {
    return fopen(path, "r");
}

/* Realpath-sanitising wrapper – tainted path is resolved before fopen */
static FILE *safe_open_path(const char *path) {
    char resolved[4096];
    if (realpath(path, resolved) == NULL)
        return NULL;
    return fopen(resolved, "r");
}

/* =========================================================================
 * FREE WRAPPERS
 *
 * Wrappers that call free() on one of their parameters.
 * The engine identifies these via call-graph analysis so that
 * caller-side use-after-free patterns are detected.
 */

/* Frees its first (and only) pointer parameter */
static void free_ptr(char *p) {
    free(p);
}

/* Frees its SECOND parameter; first is an unrelated sentinel */
static void free_second_param(int sentinel, char *p) {
    (void)sentinel;
    free(p);
}

/* =========================================================================
 * COPY WRAPPERS
 *
 * Sink wrappers that perform buffer copies.
 */

/* Unbounded strcpy – sink for CWE-121 */
static void unsafe_strcpy(char *dst, const char *src) {
    strcpy(dst, src);
}

/* Bounded strncpy – safe copy wrapper */
static void safe_strcpy(char *dst, size_t dst_len, const char *src) {
    strncpy(dst, src, dst_len - 1);
    dst[dst_len - 1] = '\0';
}

/* =========================================================================
 * CWE-22: Path Traversal via wrapper chain
 * =========================================================================
 */

/* VULNERABLE: env_read() taint flows into open_path() → fopen() */
void vuln_cwe22_source_to_sink_wrapper(void) {
    char *path = env_read("FILE_PATH");
    FILE *f = open_path(path);
    if (f) fclose(f);
}

/* SAFE: env_read() taint resolved by safe_open_path() before fopen() */
void safe_cwe22_sanitized_wrapper(void) {
    char *path = env_read("FILE_PATH");
    if (!path) return;
    FILE *f = safe_open_path(path);
    if (f) fclose(f);
}

/* VULNERABLE: stdin taint flows through dup_tainted() into open_path() */
void vuln_cwe22_propagator_then_sink(void) {
    char *raw  = stdin_read();
    char *copy = dup_tainted(raw);
    FILE *f    = open_path(copy);
    if (f) fclose(f);
}

/* =========================================================================
 * CWE-416: Use-After-Free via free wrappers
 * =========================================================================
 */

/* VULNERABLE: malloc → free_ptr(buf) → printf(buf) (UAF) */
void vuln_cwe416_free_first_param(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    snprintf(buf, 128, "secret");
    free_ptr(buf);             /* buf freed inside free_ptr */
    printf("%s\n", buf);      /* USE-AFTER-FREE */
}

/* SAFE: printf(buf) before free_ptr(buf) */
void safe_cwe416_use_before_free(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    strcpy(buf, "secret");
    printf("%s\n", buf);      /* use BEFORE free */
    free_ptr(buf);
}

/* VULNERABLE: malloc → free_second_param(0, buf) → write buf[0] */
void vuln_cwe416_free_second_param(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    free_second_param(0, buf); /* frees buf (2nd param) */
    buf[0] = 'X';              /* USE-AFTER-FREE write */
}

/* SAFE: write buf[0] before free_second_param */
void safe_cwe416_write_then_free(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    buf[0] = 'X';              /* use BEFORE free */
    free_second_param(0, buf);
}

/* =========================================================================
 * CWE-121: Buffer Overflow via copy wrapper
 * =========================================================================
 */

/* VULNERABLE: stdin_read (≤512 B) → unsafe_strcpy → 32-byte local */
void vuln_cwe121_copy_wrapper_overflow(void) {
    char local[32];
    char *input = stdin_read();          /* up to 512 bytes */
    unsafe_strcpy(local, input);         /* 512 B → 32 B: overflow */
    printf("%s\n", local);
}

/* SAFE: stdin_read → safe_strcpy with size limit */
void safe_cwe121_copy_wrapper_bounded(void) {
    char local[32];
    char *input = stdin_read();
    safe_strcpy(local, sizeof(local), input);
    printf("%s\n", local);
}

/* =========================================================================
 * CWE-415: Double-Free via wrapper
 * =========================================================================
 */

/* VULNERABLE: free_ptr(buf) called twice */
void vuln_cwe415_double_free_via_wrapper(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    strcpy(buf, "hi");
    free_ptr(buf);   /* first free */
    free_ptr(buf);   /* DOUBLE FREE */
}

/* SAFE: free_ptr called once, pointer nulled */
void safe_cwe415_single_free_wrapper(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    strcpy(buf, "hi");
    free_ptr(buf);
    buf = NULL;
}

/* =========================================================================
 * CWE-401: Memory Leak via allocation wrapper
 * =========================================================================
 */

/* Simple allocator wrapper */
static char *alloc_buf(size_t n) {
    return (char *)malloc(n);
}

/* VULNERABLE: alloc_buf() with no corresponding free */
void vuln_cwe401_alloc_wrapper_leak(void) {
    char *buf = alloc_buf(256);
    if (!buf) return;
    strcpy(buf, "data");
    /* no free → memory leak */
}

/* SAFE: alloc_buf() with proper free */
void safe_cwe401_alloc_wrapper_freed(void) {
    char *buf = alloc_buf(256);
    if (!buf) return;
    strcpy(buf, "data");
    free(buf);
}
