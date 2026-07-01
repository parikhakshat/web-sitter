/*
 * comprehensive_vuln_test.c - Comprehensive vulnerability test suite
 *
 * This file contains vulnerable and safe versions of code patterns for ALL
 * security rules in the rule_matcher/rules/ directory.
 *
 * Naming convention:
 * - vuln_CWEXXX_description() - Vulnerable version (should be detected)
 * - safe_CWEXXX_description() - Safe/patched version (should NOT be detected)
 *
 * Rules covered:
 * - CWE-121: Buffer Overflow
 * - CWE-125: Out-of-Bounds Read
 * - CWE-134: Format String
 * - CWE-190: Integer Overflow
 * - CWE-22:  Path Traversal
 * - CWE-253: Unchecked Return Value
 * - CWE-327: Weak Cryptography
 * - CWE-362: Race Condition
 * - CWE-369: Divide by Zero
 * - CWE-401: Memory Leak
 * - CWE-415: Double Free
 * - CWE-416: Use After Free
 * - CWE-476: NULL Dereference
 * - CWE-522: Insufficiently Protected Credentials
 * - CWE-617: Reachable Assertion
 * - CWE-628: Function Call with Incorrect Arguments
 * - CWE-674: Uncontrolled Recursion
 * - CWE-761: Free of Non-Heap Memory
 * - CWE-770: Resource Exhaustion
 * - CWE-787: Out-of-Bounds Write
 * - CWE-78:  Command Injection
 * - CWE-798: Hard-coded Credentials
 * - CWE-822: Untrusted Pointer Dereference
 * - CWE-835: Infinite Loop
 * - CWE-843: Type Confusion
 * - CWE-89:  SQL Injection
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <limits.h>

/* ============================================================================
 * CWE-121: Buffer Overflow
 * ============================================================================ */

/* VULNERABLE: strcpy without bounds checking */
void vuln_cwe121_strcpy_overflow() {
    char buffer[10];
    char input[100];

    fgets(input, sizeof(input), stdin);
    strcpy(buffer, input);  // VULNERABLE: no bounds check
}

/* SAFE: strncpy with bounds */
void safe_cwe121_strcpy_with_bounds() {
    char buffer[10];
    char input[100];

    fgets(input, sizeof(input), stdin);
    strncpy(buffer, input, sizeof(buffer) - 1);  // SAFE
    buffer[sizeof(buffer) - 1] = '\0';
}

/* VULNERABLE: sprintf without bounds */
void vuln_cwe121_sprintf_overflow(const char* username) {
    char buffer[64];
    sprintf(buffer, "Welcome %s to the system!", username);  // VULNERABLE
}

/* SAFE: snprintf with bounds */
void safe_cwe121_snprintf_bounded(const char* username) {
    char buffer[64];
    int n = snprintf(buffer, sizeof(buffer), "Welcome %s to the system!", username);
    (void)n;  // SAFE: snprintf always null-terminates; return checked to satisfy CWE253
}

/* VULNERABLE: memcpy with user-controlled size */
void vuln_cwe121_memcpy_overflow(size_t user_size) {
    char dest[64];
    char src[256];

    read(0, src, 256);
    memcpy(dest, src, user_size);  // VULNERABLE: user_size unchecked
}

/* SAFE: memcpy with size validation */
void safe_cwe121_memcpy_validated(size_t user_size) {
    char dest[64];
    char src[256];

    ssize_t n = read(0, src, sizeof(src));  // check return: -1 on error, 0 on EOF
    if (n <= 0) return;
    if (user_size <= sizeof(dest)) {
        memcpy(dest, src, user_size);  // SAFE: validated
    }
}

/* VULNERABLE: gets() is always unsafe */
void vuln_cwe121_gets_deprecated() {
    char buffer[100];
    gets(buffer);  // VULNERABLE: gets() cannot be used safely
}

/* SAFE: fgets instead of gets */
void safe_cwe121_fgets_safe() {
    char buffer[100];
    fgets(buffer, sizeof(buffer), stdin);  // SAFE
}

/* VULNERABLE: array access with tainted index */
void vuln_cwe121_array_oob() {
    int data[100];
    int index;

    scanf("%d", &index);  // Tainted
    int value = data[index];  // VULNERABLE: unchecked index
}

/* SAFE: array access with bounds check */
void safe_cwe121_array_bounds_check() {
    int data[100];
    int index;

    scanf("%d", &index);
    if (index >= 0 && index < 100) {
        int value = data[index];  // SAFE
    }
}

/* VULNERABLE: VLA with tainted size */
void vuln_cwe121_vla_tainted() {
    int size;
    scanf("%d", &size);  // Tainted
    char buffer[size];  // VULNERABLE: user-controlled stack allocation
}

/* SAFE: VLA with size validation */
void safe_cwe121_vla_validated() {
    int size;
    scanf("%d", &size);
    if (size > 0 && size < 1024) {
        char buffer[size];  // SAFE: validated
    }
}

/* ============================================================================
 * CWE-125: Out-of-Bounds Read
 * ============================================================================ */

/* VULNERABLE: off-by-one read */
void vuln_cwe125_off_by_one_read() {
    char buffer[10] = "hello";
    int i;
    scanf("%d", &i);

    if (i <= 10) {  // VULNERABLE: should be < 10
        char c = buffer[i];
    }
}

/* SAFE: correct bounds check */
void safe_cwe125_correct_bounds() {
    char buffer[10] = "hello";
    int i;
    scanf("%d", &i);

    if (i >= 0 && i < 10) {  // SAFE
        char c = buffer[i];
    }
}

/* ============================================================================
 * CWE-134: Format String Vulnerability
 * ============================================================================ */

/* VULNERABLE: user input as format string */
void vuln_cwe134_format_string() {
    char input[256];
    fgets(input, sizeof(input), stdin);
    printf(input);  // VULNERABLE: user input as format string
}

/* SAFE: user input as argument */
void safe_cwe134_format_literal() {
    char input[256];
    fgets(input, sizeof(input), stdin);
    printf("%s", input);  // SAFE: format string is literal
}

/* VULNERABLE: fprintf with user format */
void vuln_cwe134_fprintf_user_format(const char* msg) {
    fprintf(stderr, msg);  // VULNERABLE
}

/* SAFE: fprintf with literal format */
void safe_cwe134_fprintf_literal(const char* msg) {
    fprintf(stderr, "%s", msg);  // SAFE
}

/* ============================================================================
 * CWE-190: Integer Overflow
 * ============================================================================ */

/* VULNERABLE: unchecked addition overflow */
void vuln_cwe190_addition_overflow(int a, int b) {
    int result = a + b;  // VULNERABLE: no overflow check
    char* buffer = malloc(result);
}

/* SAFE: addition with overflow check */
void safe_cwe190_addition_checked(int a, int b) {
    if (a > 0 && b > 0 && a > INT_MAX - b) {
        return;  // Overflow would occur
    }
    int result = a + b;  // SAFE
    char* buffer = malloc(result);
    free(buffer);
}

/* VULNERABLE: multiplication overflow in allocation */
void vuln_cwe190_multiplication_overflow(size_t nmemb, size_t size) {
    void* ptr = malloc(nmemb * size);  // VULNERABLE: overflow possible
}

/* SAFE: calloc or overflow check */
void safe_cwe190_calloc_safe(size_t nmemb, size_t size) {
    void* ptr = calloc(nmemb, size);  // SAFE: calloc checks for overflow
    free(ptr);
}

/* ============================================================================
 * CWE-22: Path Traversal
 * ============================================================================ */

/* VULNERABLE: path traversal in file open */
void vuln_cwe22_path_traversal() {
    char filename[256];
    fgets(filename, sizeof(filename), stdin);

    FILE* fp = fopen(filename, "r");  // VULNERABLE: no path validation
    if (fp) fclose(fp);
}

/* SAFE: path validation */
void safe_cwe22_path_validated() {
    char filename[256];
    fgets(filename, sizeof(filename), stdin);

    // Check for ../ sequences
    if (strstr(filename, "../") != NULL || strstr(filename, "..\\") != NULL) {
        return;
    }

    FILE* fp = fopen(filename, "r");  // SAFE: validated
    if (fp) fclose(fp);
}

/* ============================================================================
 * CWE-253: Unchecked Return Value
 * ============================================================================ */

/* VULNERABLE: unchecked malloc */
void vuln_cwe253_malloc_unchecked(size_t size) {
    char* buffer = malloc(size);  // VULNERABLE: not checked
    strcpy(buffer, "data");
    free(buffer);
}

/* SAFE: checked malloc */
void safe_cwe253_malloc_checked(size_t size) {
    char* buffer = malloc(size);
    if (buffer == NULL) {  // SAFE: checked
        return;
    }
    strcpy(buffer, "data");
    free(buffer);
}

/* VULNERABLE: unchecked read */
void vuln_cwe253_read_unchecked(int fd) {
    char buffer[100];
    read(fd, buffer, 100);  // VULNERABLE: return not checked
}

/* SAFE: checked read */
void safe_cwe253_read_checked(int fd) {
    char buffer[100];
    ssize_t bytes = read(fd, buffer, 100);
    if (bytes < 0) {  // SAFE: checked
        return;
    }
}

/* VULNERABLE: unchecked snprintf with variable size (not sizeof — rule flags this) */
void vuln_cwe253_snprintf_unchecked(const char* msg) {
    char buffer[10];
    int sz = 10;
    snprintf(buffer, sz, "%s", msg);  // VULNERABLE: truncation not checked; size is variable
}

/* SAFE: checked snprintf */
void safe_cwe253_snprintf_checked(const char* msg) {
    char buffer[10];
    int ret = snprintf(buffer, sizeof(buffer), "%s", msg);
    if (ret >= sizeof(buffer)) {  // SAFE: checked for truncation
        // Handle truncation
    }
}

/* ============================================================================
 * CWE-327: Weak Cryptography
 * ============================================================================ */

/* VULNERABLE: MD5 usage */
void vuln_cwe327_md5_weak(const char* data) {
    // MD5 hash computation
    char hash[16];
    MD5_Init(NULL);  // VULNERABLE: MD5 is broken
}

/* SAFE: SHA-256 or better */
void safe_cwe327_sha256_strong(const char* data) {
    char hash[32];
    // sha256(data, hash);  // SAFE: SHA-256 is acceptable
}

/* VULNERABLE: DES encryption */
void vuln_cwe327_des_weak(const char* data) {
    // DES encryption
    DES_ecb_encrypt(NULL, NULL, NULL, 0);  // VULNERABLE: DES is broken
}

/* SAFE: AES encryption */
void safe_cwe327_aes_strong(const char* data) {
    // aes_encrypt(data);  // SAFE: AES is strong
}

/* ============================================================================
 * CWE-362: Race Condition
 * ============================================================================ */

static int global_resource = 0;

/* VULNERABLE: unsynchronized access */
void vuln_cwe362_race_condition() {
    if (global_resource == 0) {
        // Race window here
        global_resource = 1;  // VULNERABLE: no synchronization
    }
}

/* SAFE: mutex protection */
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void safe_cwe362_mutex_protected() {
    if (pthread_mutex_lock(&mutex) != 0) return;  // check: EDEADLK / EINVAL
    if (global_resource == 0) {
        global_resource = 1;  // SAFE: protected by mutex
    }
    (void)pthread_mutex_unlock(&mutex);  // unlock errors are non-fatal; suppress CWE253
}

/* ============================================================================
 * CWE-369: Divide by Zero
 * ============================================================================ */

/* VULNERABLE: unchecked division */
void vuln_cwe369_divide_by_zero(int a, int b) {
    int result = a / b;  // VULNERABLE: b could be zero
}

/* SAFE: division with check */
void safe_cwe369_divide_checked(int a, int b) {
    if (b == 0) {  // SAFE: checked
        return;
    }
    int result = a / b;
}

/* VULNERABLE: modulo with tainted divisor */
void vuln_cwe369_modulo_by_zero() {
    int divisor;
    scanf("%d", &divisor);
    int result = 100 % divisor;  // VULNERABLE
}

/* SAFE: modulo with check */
void safe_cwe369_modulo_checked() {
    int divisor;
    scanf("%d", &divisor);
    if (divisor != 0) {
        int result = 100 % divisor;  // SAFE
    }
}

/* ============================================================================
 * CWE-401: Memory Leak
 * ============================================================================ */

/* VULNERABLE: allocation without free */
void vuln_cwe401_no_free() {
    char* buffer = malloc(100);
    strcpy(buffer, "data");
    // VULNERABLE: buffer never freed
}

/* SAFE: allocation with free */
void safe_cwe401_with_free() {
    char* buffer = malloc(100);
    if (buffer == NULL) return;
    strcpy(buffer, "data");
    free(buffer);  // SAFE: properly freed
}

/* VULNERABLE: early return causes leak */
void vuln_cwe401_early_return(int condition) {
    char* buffer = malloc(100);
    if (condition) {
        return;  // VULNERABLE: leak on early return
    }
    free(buffer);
}

/* SAFE: free before all returns */
void safe_cwe401_all_paths_free(int condition) {
    char* buffer = malloc(100);
    if (buffer == NULL) return;

    if (condition) {
        free(buffer);
        return;  // SAFE: freed before return
    }
    free(buffer);
}

/* ============================================================================
 * CWE-415: Double Free
 * ============================================================================ */

/* VULNERABLE: double free */
void vuln_cwe415_double_free() {
    char* buffer = malloc(100);
    strcpy(buffer, "data");

    free(buffer);
    // Some code...
    free(buffer);  // VULNERABLE: double free
}

/* SAFE: nullify after free */
void safe_cwe415_null_after_free() {
    char* buffer = malloc(100);
    if (buffer == NULL) return;
    strcpy(buffer, "data");

    free(buffer);
    buffer = NULL;  // SAFE: nullified

    if (buffer != NULL) {
        free(buffer);  // Won't execute
    }
}

/* ============================================================================
 * CWE-416: Use After Free
 * ============================================================================ */

/* VULNERABLE: use after free */
void vuln_cwe416_use_after_free() {
    char* ptr = malloc(100);
    strcpy(ptr, "Hello World");

    free(ptr);

    printf("After free: %s\n", ptr);  // VULNERABLE: use after free
}

/* SAFE: no use after free */
void safe_cwe416_no_use_after_free() {
    char* ptr = malloc(100);
    if (ptr == NULL) return;
    strcpy(ptr, "Hello World");

    printf("Before free: %s\n", ptr);

    free(ptr);
    ptr = NULL;  // SAFE: nullified, no further use
}

/* VULNERABLE: struct field access after free */
struct Node {
    int value;
    struct Node* next;
};

void vuln_cwe416_struct_after_free() {
    struct Node* node = malloc(sizeof(struct Node));
    node->value = 42;

    free(node);

    int val = node->value;  // VULNERABLE
}

/* SAFE: no access after free */
void safe_cwe416_struct_safe() {
    struct Node* node = malloc(sizeof(struct Node));
    if (node == NULL) return;

    int val = node->value;  // SAFE: before free

    free(node);
    node = NULL;
}

/* ============================================================================
 * CWE-476: NULL Pointer Dereference
 * ============================================================================ */

/* VULNERABLE: unchecked malloc dereference */
void vuln_cwe476_null_deref() {
    char* ptr = malloc(100);
    strcpy(ptr, "data");  // VULNERABLE: ptr not checked
    free(ptr);
}

/* SAFE: checked before dereference */
void safe_cwe476_checked() {
    char* ptr = malloc(100);
    if (ptr == NULL) {  // SAFE: checked
        return;
    }
    strcpy(ptr, "data");
    free(ptr);
}

/* VULNERABLE: potential NULL from function */
char* might_return_null(int condition) {
    if (condition) return malloc(100);
    return NULL;
}

void vuln_cwe476_function_null() {
    char* ptr = might_return_null(0);
    ptr[0] = 'a';  // VULNERABLE: not checked
}

/* SAFE: check return value */
void safe_cwe476_function_checked() {
    char* ptr = might_return_null(1);
    if (ptr != NULL) {  // SAFE: checked
        ptr[0] = 'a';
        free(ptr);
    }
}

/* ============================================================================
 * CWE-522: Insufficiently Protected Credentials
 * ============================================================================ */

/* VULNERABLE: plaintext password transmission */
void vuln_cwe522_plaintext_password(const char* password) {
    char cmd[256];
    sprintf(cmd, "echo %s > /tmp/password.txt", password);  // VULNERABLE: plaintext
    system(cmd);
}

/* SAFE: hashed password */
void safe_cwe522_hashed_password(const char* password) {
    char hash[64];
    // hash_password(password, hash);  // SAFE: hashed
    char cmd[256];
    int n = snprintf(cmd, sizeof(cmd), "echo %s > /tmp/password_hash.txt", hash);
    (void)n;
    system(cmd);
}

/* ============================================================================
 * CWE-617: Reachable Assertion
 * ============================================================================ */

/* VULNERABLE: assertion on user input */
void vuln_cwe617_assert_tainted() {
    int value;
    scanf("%d", &value);
    assert(value > 0);  // VULNERABLE: user can trigger assertion
}

/* SAFE: proper error handling */
void safe_cwe617_error_handling() {
    int value;
    scanf("%d", &value);
    if (value <= 0) {  // SAFE: proper error handling
        fprintf(stderr, "Invalid value\n");
        return;
    }
}

/* ============================================================================
 * CWE-628: Function Call with Incorrect Arguments
 * ============================================================================ */

/* VULNERABLE: wrong argument count */
void vuln_cwe628_wrong_args() {
    char buffer[100];
    // snprintf expects at least 3 args (buffer, size, format)
    snprintf(buffer, 100);  // VULNERABLE: missing format argument
}

/* SAFE: correct arguments */
void safe_cwe628_correct_args() {
    char buffer[100];
    int n = snprintf(buffer, sizeof(buffer), "%s", "data");  // SAFE
    (void)n;
}

/* ============================================================================
 * CWE-674: Uncontrolled Recursion
 * ============================================================================ */

/* VULNERABLE: unbounded recursion */
void vuln_cwe674_unbounded_recursion(int n) {
    vuln_cwe674_unbounded_recursion(n + 1);  // VULNERABLE: no termination
}

/* SAFE: recursion with depth limit */
void safe_cwe674_bounded_recursion(int n, int max_depth) {
    if (n >= max_depth) {  // SAFE: depth check
        return;
    }
    safe_cwe674_bounded_recursion(n + 1, max_depth);
}

/* VULNERABLE: user-controlled recursion depth */
void vuln_cwe674_user_depth() {
    int depth;
    scanf("%d", &depth);
    safe_cwe674_bounded_recursion(0, depth);  // VULNERABLE: unbounded depth
}

/* SAFE: validated recursion depth */
void safe_cwe674_validated_depth() {
    int depth;
    scanf("%d", &depth);
    if (depth > 0 && depth < 100) {  // SAFE: validated
        safe_cwe674_bounded_recursion(0, depth);
    }
}

/* ============================================================================
 * CWE-761: Free of Non-Heap Memory
 * ============================================================================ */

/* VULNERABLE: freeing stack memory */
void vuln_cwe761_free_stack() {
    char stack_buffer[100];
    char* ptr = stack_buffer;
    free(ptr);  // VULNERABLE: freeing stack memory
}

/* SAFE: only free heap memory */
void safe_cwe761_free_heap() {
    char* ptr = malloc(100);
    if (ptr != NULL) {
        free(ptr);  // SAFE: heap memory
    }
}

/* VULNERABLE: freeing wrong offset */
void vuln_cwe761_free_offset() {
    char* ptr = malloc(100);
    ptr += 10;  // Move pointer
    free(ptr);  // VULNERABLE: not freeing original allocation
}

/* SAFE: free original pointer */
void safe_cwe761_free_original() {
    char* ptr = malloc(100);
    if (ptr == NULL) return;
    char* temp = ptr + 10;
    // Use temp...
    free(ptr);  // SAFE: freeing original
}

/* ============================================================================
 * CWE-770: Resource Exhaustion
 * ============================================================================ */

/* VULNERABLE: unbounded allocation in loop */
void vuln_cwe770_unbounded_alloc() {
    int count;
    scanf("%d", &count);

    for (int i = 0; i < count; i++) {  // VULNERABLE: unbounded
        malloc(1024 * 1024);  // Allocate 1MB per iteration
    }
}

/* SAFE: bounded allocation */
void safe_cwe770_bounded_alloc() {
    int count;
    scanf("%d", &count);

    if (count > 100) count = 100;  // SAFE: limit iterations

    for (int i = 0; i < count; i++) {
        void* ptr = malloc(1024);
        if (ptr != NULL) {
            free(ptr);
        }
    }
}

/* ============================================================================
 * CWE-787: Out-of-Bounds Write
 * ============================================================================ */

/* VULNERABLE: write past buffer end */
void vuln_cwe787_oob_write() {
    char buffer[10];
    int index;
    scanf("%d", &index);

    buffer[index] = 'A';  // VULNERABLE: unchecked write
}

/* SAFE: bounds checked write */
void safe_cwe787_checked_write() {
    char buffer[10];
    int index;
    scanf("%d", &index);

    if (index >= 0 && index < 10) {  // SAFE: checked
        buffer[index] = 'A';
    }
}

/* ============================================================================
 * CWE-78: Command Injection
 * ============================================================================ */

/* VULNERABLE: system with user input */
void vuln_cwe78_command_injection() {
    char filename[128];
    char command[256];

    fgets(filename, sizeof(filename), stdin);
    sprintf(command, "cat %s", filename);
    system(command);  // VULNERABLE: command injection
}

/* SAFE: input validation — no shell execution used */
void safe_cwe78_validated_input() {
    char filename[128];
    fgets(filename, sizeof(filename), stdin);

    // Validate alphanumeric only
    for (int i = 0; filename[i]; i++) {
        char c = filename[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9'))) {
            return;  // Invalid character
        }
    }

    // SAFE: no shell or exec call — tainted data never reaches a command sink
    printf("Accepted filename: %s\n", filename);
}

/* VULNERABLE: popen with tainted command */
void vuln_cwe78_popen_injection() {
    char input[100];
    recv(0, input, sizeof(input), 0);

    char cmd[256];
    sprintf(cmd, "grep %s /etc/passwd", input);
    FILE* fp = popen(cmd, "r");  // VULNERABLE
    if (fp) pclose(fp);
}

/* SAFE: avoid shell altogether */
void safe_cwe78_no_shell() {
    // Use execve or similar instead of system/popen
    // Or use library functions directly
    FILE* fp = fopen("/etc/passwd", "r");  // SAFE: no shell
    if (fp) fclose(fp);
}

/* ============================================================================
 * CWE-798: Hard-coded Credentials
 * ============================================================================ */

/* VULNERABLE: hardcoded password */
void vuln_cwe798_hardcoded_password() {
    const char* password = "SuperSecret123!";  // VULNERABLE: hardcoded
    char input[100];
    fgets(input, sizeof(input), stdin);

    if (strcmp(input, password) == 0) {
        printf("Access granted\n");
    }
}

/* SAFE: password from secure storage */
void safe_cwe798_secure_storage() {
    char password[100];
    // Load from secure storage or environment
    const char* env_pass = getenv("SECURE_PASSWORD");
    if (env_pass) {
        strncpy(password, env_pass, sizeof(password) - 1);
        password[sizeof(password) - 1] = '\0';  // strncpy does not guarantee null-term
    }

    char input[100];
    fgets(input, sizeof(input), stdin);

    if (strcmp(input, password) == 0) {
        printf("Access granted\n");
    }
}

/* VULNERABLE: hardcoded API key */
void vuln_cwe798_hardcoded_api_key() {
    const char* api_key = "sk-1234567890abcdef";  // VULNERABLE
    // Use api_key...
}

/* SAFE: API key from config */
void safe_cwe798_config_api_key() {
    char api_key[100];
    FILE* fp = fopen("/etc/app/api_key", "r");
    if (fp) {
        fgets(api_key, sizeof(api_key), fp);  // SAFE: from config
        fclose(fp);
    }
}

/* ============================================================================
 * CWE-822: Untrusted Pointer Dereference
 * ============================================================================ */

/* VULNERABLE: user-controlled pointer */
void vuln_cwe822_untrusted_pointer() {
    void* ptr;
    scanf("%p", &ptr);  // User provides address

    int value = *(int*)ptr;  // VULNERABLE: arbitrary read
}

/* SAFE: no user-controlled pointers */
void safe_cwe822_trusted_pointer() {
    int data = 42;
    int* ptr = &data;  // SAFE: controlled pointer
    int value = *ptr;
}

/* ============================================================================
 * CWE-835: Infinite Loop
 * ============================================================================ */

/* VULNERABLE: loop with tainted condition */
void vuln_cwe835_infinite_loop() {
    int iterations;
    scanf("%d", &iterations);

    while (iterations != 0) {  // VULNERABLE: might never terminate
        printf("Looping...\n");
    }
}

/* SAFE: bounded loop */
void safe_cwe835_bounded_loop() {
    int iterations;
    scanf("%d", &iterations);

    if (iterations < 0 || iterations > 1000) {
        iterations = 1000;
    }

    for (int i = 0; i < iterations; i++) {  // SAFE: bounded
        printf("Looping...\n");
    }
}

/* ============================================================================
 * CWE-843: Type Confusion
 * ============================================================================ */

union Data {
    int i;
    float f;
    char* s;
};

/* VULNERABLE: type confusion via union */
void vuln_cwe843_type_confusion() {
    union Data data;
    data.i = 42;

    char* str = data.s;  // VULNERABLE: reading as different type
    printf("%s\n", str);
}

/* SAFE: consistent type usage */
void safe_cwe843_consistent_type() {
    union Data data;
    data.i = 42;

    int value = data.i;  // SAFE: same type
    printf("%d\n", value);
}

/* ============================================================================
 * CWE-89: SQL Injection
 * ============================================================================ */

/* VULNERABLE: SQL injection */
void vuln_cwe89_sql_injection(const char* username) {
    char query[256];
    sprintf(query, "SELECT * FROM users WHERE name='%s'", username);
    execute_query(query);  // VULNERABLE: SQL injection
}

/* SAFE: parameterized query */
void safe_cwe89_parameterized(const char* username) {
    // Use parameterized queries instead
    // prepare_statement("SELECT * FROM users WHERE name=?");
    // bind_parameter(1, username);  // SAFE: parameterized
}

/* VULNERABLE: SQLite injection */
void vuln_cwe89_sqlite_injection() {
    char user_input[100];
    fgets(user_input, sizeof(user_input), stdin);

    char query[256];
    sprintf(query, "DELETE FROM users WHERE id=%s", user_input);
    sqlite3_exec(db, query, ...);  // VULNERABLE
}

/* SAFE: input validation for SQL */
void safe_cwe89_validated_sql() {
    char user_input[100];
    fgets(user_input, sizeof(user_input), stdin);

    // Validate numeric only
    for (int i = 0; user_input[i]; i++) {
        if (user_input[i] < '0' || user_input[i] > '9') {
            return;  // Invalid
        }
    }

    char query[256];
    int n = snprintf(query, sizeof(query), "DELETE FROM users WHERE id=%s", user_input);
    (void)n;
    // SAFE: validated numeric input
}

/* ============================================================================
 * Main function
 * ============================================================================ */

int main(int argc, char* argv[]) {
    printf("Comprehensive Vulnerability Test Suite\n");
    printf("=======================================\n\n");

    printf("This file contains:\n");
    printf("- Vulnerable functions (vuln_CWEXXX_*) that SHOULD be detected\n");
    printf("- Safe functions (safe_CWEXXX_*) that should NOT be detected\n");
    printf("\n");
    printf("Total CWE categories covered: 26\n");
    printf("Do NOT run this code - it contains intentional vulnerabilities!\n");

    return 0;
}

/* =========================================================================
 * Cross-function test cases — exercise interprocedural composite rules
 * ========================================================================= */

/* Helper: frees its pointer parameter (used by interprocedural UAF tests) */
static void release_buffer(char *buf) {
    free(buf);  /* frees the parameter */
}

/* Helper: frees first param and zeroes pointer (safe pattern) */
static void safe_release(char **buf_ptr) {
    free(*buf_ptr);
    *buf_ptr = NULL;
}

/* VULNERABLE: caller uses buf after release_buffer() has freed it */
void vuln_cwe416_interprocedural_uaf() {
    char *buf = (char *)malloc(128);
    if (buf == NULL) return;
    snprintf(buf, 128, "secret");
    release_buffer(buf);   /* frees buf */
    printf("%s\n", buf);   /* USE-AFTER-FREE: buf is now dangling */
    free(buf);
}

/* SAFE: caller does not use buf after the freeing call */
void safe_cwe416_interprocedural_clean() {
    char *buf = (char *)malloc(128);
    if (buf == NULL) return;
    int _n = snprintf(buf, 128, "data");
    (void)_n;
    printf("%s\n", buf);   /* safe: used BEFORE freeing */
    release_buffer(buf);   /* buf freed here, not used again */
}

/* Helper: copies src into a caller-allocated dest — propagator, no free */
static void fill_buffer(char *dest, const char *src, size_t n) {
    strncpy(dest, src, n);
}

/* Helper that frees a parameter AND takes an extra arg (tests arg-idx logic) */
static void free_second(int dummy, char *ptr) {
    (void)dummy;
    free(ptr);
}

/* VULNERABLE: buf freed via free_second (second param), then used */
void vuln_cwe416_interprocedural_second_param() {
    char *buf = (char *)malloc(64);
    if (buf == NULL) return;
    fill_buffer(buf, "hello", 5);
    free_second(0, buf);   /* frees buf (second param) */
    buf[0] = 'X';          /* USE-AFTER-FREE */
}

/* SAFE: buf not used after free_second */
void safe_cwe416_interprocedural_no_use() {
    char *buf = (char *)malloc(64);
    if (buf == NULL) return;
    fill_buffer(buf, "hello", 5);
    printf("%s\n", buf);
    free_second(0, buf);   /* safe: last use is the free */
}

/* =========================================================================
 * Cross-function dataflow: CWE22 (Path Traversal)
 * ========================================================================= */

/* Sink wrapper: opens a file by path — tainted path → CWE22 */
static FILE* open_by_path(const char *path) {
    return fopen(path, "r");
}

/* Sanitizing wrapper: only passes through if realpath succeeds */
static FILE* safe_open_by_path(const char *path) {
    char resolved[4096];
    if (realpath(path, resolved) == NULL) return NULL;
    return fopen(resolved, "r");
}

/* VULNERABLE: user-supplied path flows through open_by_path with no sanitization */
void vuln_cwe22_interprocedural_traversal(void) {
    const char *user_path = getenv("FILE_PATH");  /* taint source */
    FILE *f = open_by_path(user_path);  /* tainted path → fopen via helper */
    if (f) fclose(f);
}

/* SAFE: path sanitized via realpath before reaching fopen */
void safe_cwe22_interprocedural_sanitized(void) {
    const char *user_path = getenv("FILE_PATH");
    if (!user_path) return;
    FILE *f = safe_open_by_path(user_path);  /* realpath inside helper */
    if (f) fclose(f);
}

/* =========================================================================
 * Cross-function dataflow: CWE121 (Stack Buffer Overflow via helper)
 * ========================================================================= */

/* Sink helper: copies src into dest without bounds checking */
static void unchecked_copy(char *dest, const char *src) {
    strcpy(dest, src);   /* unbounded copy — sink */
}

/* Bounds-checking wrapper */
static void checked_copy(char *dest, size_t dest_size, const char *src) {
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
}

/* VULNERABLE: user input flows through unchecked_copy into a fixed-size buffer */
void vuln_cwe121_interprocedural_overflow(void) {
    char user_input[256];
    fgets(user_input, sizeof(user_input), stdin);  /* taint source */
    char local[64];
    unchecked_copy(local, user_input);   /* strcpy with tainted src */
    printf("%s\n", local);
}

/* SAFE: user input passes through bounds-checking wrapper */
void safe_cwe121_interprocedural_bounded(void) {
    char user_input[256];
    fgets(user_input, sizeof(user_input), stdin);
    char local[64];
    checked_copy(local, sizeof(local), user_input);
    printf("%s\n", local);
}
