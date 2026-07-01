/*
 * guard_regression_test.c
 *
 * Tests that the rule engine correctly distinguishes between:
 *   - Vulnerable patterns with NO guard (should flag)
 *   - Safe patterns with a VALID guard (should be suppressed)
 *   - Vulnerable patterns with an INVALID guard on the WRONG variable
 *     (guard is present but irrelevant → should still flag)
 *
 * Functions use vuln_ or safe_ prefixes so the finding-matrix runner
 * tracks them automatically.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* =========================================================================
 * Section 1: Division-by-zero guards
 *
 * CWE369-PARAM-DIVISOR fires when a function parameter is used as a
 * divisor and the function body contains NO zero-equality test on it.
 * A guard of the form `if (b == 0) return;` suppresses the finding.
 * ========================================================================= */

/* VULNERABLE: no zero check before dividing by parameter */
void vuln_div_no_guard(int a, int b) {
    int result = a / b;
    (void)result;
}

/* VULNERABLE: guard checks the WRONG variable (a, not b) */
void vuln_div_wrong_guard(int a, int b) {
    if (a == 0) return;   /* checks a, but b is the divisor */
    int result = a / b;
    (void)result;
}

/* SAFE: guard checks b == 0 before the division */
void safe_div_zero_check(int a, int b) {
    if (b == 0) return;
    int result = a / b;
    (void)result;
}

/* SAFE: guard uses != 0 form (semantically equivalent) */
void safe_div_nonzero_check(int a, int b) {
    if (b != 0) {
        int result = a / b;
        (void)result;
    }
}

/* SAFE: multiple divisors, all guarded */
void safe_div_multi_guarded(int a, int b, int c) {
    if (b == 0 || c == 0) return;
    int r1 = a / b;
    int r2 = a / c;
    (void)r1;
    (void)r2;
}

/* =========================================================================
 * Section 2: NULL pointer dereference guards
 *
 * CWE476-MALLOC-DEREF fires when malloc()/calloc() is dereferenced
 * without an intervening NULL check.  A `if (!p) return;` guard
 * before the first dereference suppresses the finding.
 * ========================================================================= */

/* VULNERABLE: malloc result dereferenced with no NULL check */
void vuln_null_deref_no_check(size_t n) {
    char *p = (char *)malloc(n);
    *p = 'A';     /* CWE476: not checked */
    free(p);
}

/* VULNERABLE: NULL check is present but comes AFTER the dereference */
void vuln_null_deref_check_too_late(size_t n) {
    char *p = (char *)malloc(n);
    *p = 'A';     /* dereference BEFORE check */
    if (!p) return;
    free(p);
}

/* SAFE: NULL check before first dereference */
void safe_null_deref_checked(size_t n) {
    char *p = (char *)malloc(n);
    if (!p) return;
    *p = 'A';
    free(p);
}

/* SAFE: explicit NULL comparison with early return */
void safe_null_deref_explicit_check(size_t n) {
    char *p = (char *)malloc(n);
    if (p == NULL) return;
    *p = 'B';
    free(p);
}

/* =========================================================================
 * Section 3: Path traversal guards
 *
 * CWE22-FILE-OPEN-TRAVERSAL fires when a tainted path (from getenv/fgets)
 * reaches fopen without realpath sanitisation.  Calling realpath() on the
 * path before fopen suppresses the finding.
 * ========================================================================= */

/* VULNERABLE: fgets-derived path fed directly to fopen, no sanitisation */
void vuln_path_no_sanitizer(void) {
    char path[512];
    fgets(path, (int)sizeof(path), stdin);
    path[strcspn(path, "\n")] = '\0';
    FILE *f = fopen(path, "r");   /* CWE22: unsanitised */
    if (f) fclose(f);
}

/* VULNERABLE: getenv path with wrong guard (NULL check, not traversal check) */
void vuln_path_wrong_guard(void) {
    char *path = getenv("FILE");
    if (!path) return;            /* NULL guard – needed but not sufficient */
    FILE *f = fopen(path, "r");   /* CWE22: no path sanitisation */
    if (f) fclose(f);
}

/* SAFE: realpath() sanitises the path before fopen */
void safe_path_realpath_sanitized(void) {
    char *raw = getenv("FILE");
    if (!raw) return;
    char resolved[4096];
    if (realpath(raw, resolved) == NULL) return;
    FILE *f = fopen(resolved, "r");   /* sanitised path */
    if (f) fclose(f);
}

/* =========================================================================
 * Section 4: Format-string guards
 *
 * CWE134-PRINTF-FORMAT fires when a tainted string (from fgets/getenv)
 * reaches a printf-family call AS the format argument.  Using a
 * literal format string ("%s") suppresses the finding.
 * ========================================================================= */

/* VULNERABLE: tainted user input used as printf format string */
void vuln_format_string_no_guard(void) {
    char fmt[256];
    fgets(fmt, (int)sizeof(fmt), stdin);
    printf(fmt);   /* CWE134: tainted format string */
}

/* SAFE: user input passed as argument, not as format string */
void safe_format_string_literal_fmt(void) {
    char msg[256];
    fgets(msg, (int)sizeof(msg), stdin);
    printf("%s", msg);   /* literal format string – safe */
}

/* =========================================================================
 * Section 5: Memory-leak guards
 *
 * CWE401-NO-FREE-SIMPLE fires when malloc() is followed by return
 * without a corresponding free().  Adding free() before return
 * suppresses the finding.
 * ========================================================================= */

/* VULNERABLE: early return leaks the allocation */
void vuln_leak_early_return(int cond) {
    char *buf = (char *)malloc(128);
    if (cond) {
        return;      /* CWE401: buf leaked */
    }
    free(buf);
}

/* SAFE: free() on every return path */
void safe_leak_all_paths_freed(int cond) {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    if (cond) {
        free(buf);
        return;
    }
    free(buf);
}

/* =========================================================================
 * Section 6: Hard-exit guards (abort/exit as early-exit equivalents)
 *
 * An if-body that calls abort() or exit() is equivalent to an early return.
 * CWE476-MALLOC-DEREF must be suppressed when the NULL check calls abort.
 * ========================================================================= */

#include <assert.h>

/* SAFE: abort() on NULL is equivalent to return */
void safe_null_abort_guard(size_t n) {
    char *p = (char *)malloc(n);
    if (!p) abort();
    *p = 'A';
    free(p);
}

/* SAFE: exit(1) on NULL is equivalent to return */
void safe_null_exit_guard(size_t n) {
    char *p = (char *)malloc(n);
    if (p == NULL) exit(1);
    *p = 'B';
    free(p);
}

/* SAFE: assert(ptr != NULL) guards the dereference */
void safe_assert_null_guard(size_t n) {
    char *p = (char *)malloc(n);
    assert(p != NULL);
    *p = 'C';
    free(p);
}

/* SAFE: assert(divisor != 0) guards the division */
void safe_assert_divisor_guard(int a, int b) {
    assert(b != 0);
    int result = a / b;
    (void)result;
}

/* SAFE: if (!p) { log_error(); abort(); } */
void safe_null_compound_abort(size_t n) {
    char *p = (char *)malloc(n);
    if (!p) {
        abort();
    }
    *p = 'D';
    free(p);
}
