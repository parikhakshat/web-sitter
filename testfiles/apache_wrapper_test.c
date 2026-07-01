#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

// ============================================================================
// Apache-style memory operation wrappers
// ============================================================================

// ---------------------------------------------------------------------------
// Allocator wrappers
// ---------------------------------------------------------------------------

void* ap_malloc(size_t size) {
    return malloc(size);
}

void* ap_calloc(size_t nmemb, size_t size) {
    return calloc(nmemb, size);
}

void* apr_palloc(void* pool, size_t size) {
    // Apache pool allocator (simplified - just uses malloc)
    (void)pool;
    return malloc(size);
}

void* apr_pcalloc(void* pool, size_t size) {
    // Apache pool calloc (simplified - just uses calloc)
    (void)pool;
    return calloc(1, size);
}

// ---------------------------------------------------------------------------
// Deallocator wrappers
// ---------------------------------------------------------------------------

void ap_free(void* ptr) {
    free(ptr);
}

void apr_pfree(void* pool, void* ptr) {
    // Apache pool free (simplified - just uses free)
    (void)pool;
    free(ptr);
}

// ---------------------------------------------------------------------------
// Buffer operation wrappers
// ---------------------------------------------------------------------------

void* ap_memcpy(void* dest, const void* src, size_t n) {
    return memcpy(dest, src, n);
}

void* apr_memcpy(void* dest, const void* src, size_t n) {
    return memcpy(dest, src, n);
}

void* ap_memset(void* s, int c, size_t n) {
    return memset(s, c, n);
}

// ---------------------------------------------------------------------------
// String operation wrappers
// ---------------------------------------------------------------------------

char* ap_strcpy(char* dest, const char* src) {
    return strcpy(dest, src);
}

char* ap_strcat(char* dest, const char* src) {
    return strcat(dest, src);
}

char* apr_pstrdup(void* pool, const char* s) {
    // Apache pool strdup (simplified - just uses strdup)
    (void)pool;
    return strdup(s);
}

// ---------------------------------------------------------------------------
// Format string operation wrappers
// ---------------------------------------------------------------------------

int ap_snprintf(char* str, size_t size, const char* format, ...) {
    va_list args;
    va_start(args, format);
    int ret = vsnprintf(str, size, format, args);
    va_end(args);
    return ret;
}

int apr_snprintf(char* buf, size_t len, const char* format, ...) {
    va_list args;
    va_start(args, format);
    int ret = vsnprintf(buf, len, format, args);
    va_end(args);
    return ret;
}

int ap_sprintf(char* str, const char* format, ...) {
    va_list args;
    va_start(args, format);
    int ret = vsprintf(str, format, args);
    va_end(args);
    return ret;
}

// ============================================================================
// Vulnerability test cases
// ============================================================================

// ---------------------------------------------------------------------------
// Test 1: Buffer overflow via allocator wrapper (CWE-121)
// ---------------------------------------------------------------------------

void vuln_cwe121_allocator_wrapper() {
    // Allocate 10 bytes using wrapper
    char* buf1 = ap_malloc(10);
    char* buf2 = ap_calloc(1, 20);
    char* buf3 = apr_palloc(NULL, 30);

    // VULNERABLE: strcpy with string longer than buffer
    strcpy(buf1, "this is way too long for 10 bytes");  // CWE-121
    strcpy(buf2, "also too long for 20 bytes buffer");  // CWE-121
    strcpy(buf3, "overflow in pool allocated buffer");  // CWE-121

    ap_free(buf1);
    ap_free(buf2);
    apr_pfree(NULL, buf3);
}

void safe_cwe121_allocator_wrapper() {
    // Allocate sufficient space
    char* buf1 = ap_malloc(100);
    char* buf2 = ap_calloc(1, 100);

    // SAFE: strings fit within allocated size
    strcpy(buf1, "short");  // SAFE
    strcpy(buf2, "also short");  // SAFE

    ap_free(buf1);
    ap_free(buf2);
}

// ---------------------------------------------------------------------------
// Test 2: Buffer overflow via string operation wrapper (CWE-121)
// ---------------------------------------------------------------------------

void vuln_cwe121_string_wrapper() {
    char dest[10];

    // VULNERABLE: ap_strcpy wrapper with overflow
    ap_strcpy(dest, "this is way too long");  // CWE-121
}

void vuln_cwe121_string_wrapper_strcat() {
    char dest[10] = "foo";

    // VULNERABLE: ap_strcat wrapper with overflow
    ap_strcat(dest, "this is way too long");  // CWE-121
}

void safe_cwe121_string_wrapper() {
    char dest[100];

    // SAFE: string fits in buffer
    ap_strcpy(dest, "short");  // SAFE
    ap_strcat(dest, " string");  // SAFE
}

// ---------------------------------------------------------------------------
// Test 3: Buffer overflow via buffer operation wrapper (CWE-787)
// ---------------------------------------------------------------------------

void vuln_cwe787_buffer_wrapper() {
    char dest[10];
    char src[50] = "overflow source data that is too long";

    // VULNERABLE: ap_memcpy wrapper with overflow
    ap_memcpy(dest, src, 50);  // CWE-787
}

void vuln_cwe787_buffer_wrapper_apr() {
    char dest[20];
    char src[100] = "another overflow source";

    // VULNERABLE: apr_memcpy wrapper with overflow
    apr_memcpy(dest, src, 100);  // CWE-787
}

void safe_cwe787_buffer_wrapper() {
    char dest[100];
    char src[50] = "safe source";

    // SAFE: copy fits in destination
    ap_memcpy(dest, src, 50);  // SAFE
}

// ---------------------------------------------------------------------------
// Test 4: Format string vulnerability via wrapper (CWE-134)
// ---------------------------------------------------------------------------

void vuln_cwe134_format_wrapper(const char* user_input) {
    char buf[100];

    // VULNERABLE: user input used as format string
    ap_sprintf(buf, user_input);  // CWE-134
}

void vuln_cwe134_format_wrapper_apr(const char* user_input) {
    char buf[100];

    // VULNERABLE: user input used as format string
    apr_snprintf(buf, 100, user_input);  // CWE-134
}

void safe_cwe134_format_wrapper(const char* user_input) {
    char buf[100];

    // SAFE: literal format string, user input as argument
    ap_snprintf(buf, 100, "User provided: %s", user_input);  // SAFE
}

// ---------------------------------------------------------------------------
// Test 5: Use-after-free via deallocator wrapper (CWE-416)
// ---------------------------------------------------------------------------

void vuln_cwe416_deallocator_wrapper() {
    char* buf = ap_malloc(100);
    strcpy(buf, "initial data");

    // Free using wrapper
    ap_free(buf);

    // VULNERABLE: use after free
    strcpy(buf, "use after free");  // CWE-416
}

void vuln_cwe416_pool_deallocator() {
    char* buf = apr_palloc(NULL, 100);
    strcpy(buf, "pool data");

    // Free using pool wrapper
    apr_pfree(NULL, buf);

    // VULNERABLE: use after free
    strcpy(buf, "use after pool free");  // CWE-416
}

void safe_cwe416_deallocator_wrapper() {
    char* buf1 = ap_malloc(100);
    char* buf2 = ap_malloc(100);

    strcpy(buf1, "first buffer");
    strcpy(buf2, "second buffer");

    ap_free(buf1);

    // SAFE: use buf2, not buf1
    strcpy(buf2, "still valid");  // SAFE

    ap_free(buf2);
}

// ---------------------------------------------------------------------------
// Test 6: Combined wrappers (multiple categories)
// ---------------------------------------------------------------------------

void vuln_combined_wrappers() {
    // Allocate with wrapper
    char* buf = ap_malloc(10);

    // Copy with string wrapper (overflow)
    ap_strcpy(buf, "this is too long");  // CWE-121

    // Format with format wrapper (safe, but on already-overflowed buffer)
    ap_sprintf(buf, "test");

    // Free with wrapper
    ap_free(buf);

    // Use after free
    ap_strcpy(buf, "use after free");  // CWE-416
}

void vuln_pool_combined() {
    void* pool = NULL;

    // Allocate with pool wrapper
    char* buf = apr_palloc(pool, 15);

    // Copy with buffer wrapper (overflow)
    apr_memcpy(buf, "this is longer than 15 bytes", 30);  // CWE-787

    // Duplicate string with pool strdup
    char* dup = apr_pstrdup(pool, "test");

    // Free pool memory
    apr_pfree(pool, buf);
    apr_pfree(pool, dup);
}

// ---------------------------------------------------------------------------
// Test 7: Nested wrapper calls
// ---------------------------------------------------------------------------

// Custom wrapper that wraps ap_malloc
void* my_custom_malloc(size_t size) {
    return ap_malloc(size);  // Wraps ap_malloc which wraps malloc
}

void vuln_nested_wrapper() {
    // Triple-nested wrapper: my_custom_malloc -> ap_malloc -> malloc
    char* buf = my_custom_malloc(10);

    // VULNERABLE: overflow through nested wrapper chain
    strcpy(buf, "this is too long");  // CWE-121

    ap_free(buf);
}

// ---------------------------------------------------------------------------
// Main function
// ---------------------------------------------------------------------------

int main() {
    printf("Apache wrapper test cases\n");
    printf("Expected vulnerabilities:\n");
    printf("  - CWE-121: Buffer overflow (allocator + string wrappers)\n");
    printf("  - CWE-787: Out-of-bounds write (buffer wrappers)\n");
    printf("  - CWE-134: Format string (format wrappers)\n");
    printf("  - CWE-416: Use-after-free (deallocator wrappers)\n");

    // Note: Not actually running vulnerable code to avoid crashes
    // This file is for static analysis testing only

    return 0;
}
