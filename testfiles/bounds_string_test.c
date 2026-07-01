// Comprehensive test file for array bounds, allocation, and string length tracking
// Each test has a vulnerable (vuln_*) and safe (safe_*) version

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// =============================================================================
// CWE-121: Stack-based Buffer Overflow
// =============================================================================

// Test 1: strcpy overflow
void vuln_strcpy_overflow(char *input) {
    char buffer[10];
    strcpy(buffer, input);  // Vulnerable - no size checking
}

void safe_strcpy_overflow(char *input) {
    char buffer[10];
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
}

// Test 2: strcpy with known literal
void vuln_strcpy_literal() {
    char buffer[5];
    strcpy(buffer, "This is a very long string");  // Vulnerable - literal too long
}

void safe_strcpy_literal() {
    char buffer[30];
    strcpy(buffer, "This is a very long string");  // Safe - buffer is large enough
}

// Test 3: strcat overflow
void vuln_strcat_overflow(char *input) {
    char buffer[10] = "Hello";
    strcat(buffer, input);  // Vulnerable - remaining space is only 4 bytes
}

void safe_strcat_overflow(char *input) {
    char buffer[100] = "Hello";
    strncat(buffer, input, sizeof(buffer) - strlen(buffer) - 1);
}

// Test 4: sprintf overflow
void vuln_sprintf_overflow(char *name, int age) {
    char buffer[10];
    sprintf(buffer, "Name: %s, Age: %d", name, age);  // Vulnerable
}

void safe_sprintf_overflow(char *name, int age) {
    char buffer[100];
    snprintf(buffer, sizeof(buffer), "Name: %s, Age: %d", name, age); // cpg-suppress: CWE253-SNPRINTF-UNCHECKED
}

// =============================================================================
// CWE-122: Heap-based Buffer Overflow
// =============================================================================

// Test 5: memcpy heap overflow
void vuln_memcpy_heap(char *input, size_t len) {
    char *buffer = malloc(10);
    memcpy(buffer, input, len);  // Vulnerable - len may exceed 10
    free(buffer);
}

void safe_memcpy_heap(char *input, size_t len) {
    size_t buffer_size = 10;
    char *buffer = malloc(buffer_size);
    if (buffer && len <= buffer_size) {
        memcpy(buffer, input, len);
    }
    free(buffer);
}

// Test 6: strcpy heap with symbolic size
void vuln_strcpy_heap_symbolic(char *input, int n) {
    char *buffer = malloc(n);
    strcpy(buffer, input);  // Vulnerable - input may be longer than n
    free(buffer);
}

void safe_strcpy_heap_symbolic(char *input, int n) {
    char *buffer = malloc(n + 1);  // +1 for null terminator
    if (buffer) {
        strncpy(buffer, input, n);
        buffer[n] = '\0';
    }
    free(buffer);
}

// Test 7: Symbolic size comparison (n+10 > n)
void vuln_symbolic_overflow(int n) {
    char *buffer = malloc(n);
    char *input = malloc(n + 10);
    memcpy(buffer, input, n + 10);  // Vulnerable - definite overflow by 10
    free(buffer);
    free(input);
}

void safe_symbolic_overflow(int n) {
    char *buffer = malloc(n + 10);
    char *input = malloc(n + 10);
    memcpy(buffer, input, n + 10);  // Safe - sizes match
    free(buffer);
    free(input);
}

// =============================================================================
// CWE-125: Out-of-bounds Read
// =============================================================================

// Test 8: Array index read
void vuln_array_read(int index) {
    int array[10];
    int value = array[index];  // Vulnerable - index not validated
}

void safe_array_read(int index) {
    int array[10];
    if (index >= 0 && index < 10) {
        int value = array[index];
    }
}

// Test 9: String read with strlen
void vuln_string_read(char *str) {
    char buffer[10];
    strcpy(buffer, "test");
    int i = strlen(str);  // If str is from buffer, i could be > 10
    char c = buffer[i];   // Vulnerable - out of bounds read
}

void safe_string_read(char *str) {
    char buffer[10];
    strcpy(buffer, "test");
    int len = strlen(buffer);
    if (len < 10) {
        char c = buffer[len];  // Safe - len is validated
    }
}

// Test 10: Loop-based read
void vuln_loop_read(int n) {
    int array[10];
    for (int i = 0; i <= n; i++) {  // Vulnerable - may exceed bounds
        int x = array[i];
    }
}

void safe_loop_read(int n) {
    int array[10];
    int limit = (n < 10) ? n : 9;
    for (int i = 0; i <= limit; i++) {
        int x = array[i];
    }
}

// =============================================================================
// CWE-787: Out-of-bounds Write
// =============================================================================

// Test 11: Array index write
void vuln_array_write(int index, int value) {
    int array[10];
    array[index] = value;  // Vulnerable - index not validated
}

void safe_array_write(int index, int value) {
    int array[10];
    if (index >= 0 && index < 10) {
        array[index] = value;
    }
}

// Test 12: Loop-based write
void vuln_loop_write(int n) {
    char buffer[10];
    for (int i = 0; i < n; i++) {  // Vulnerable - n may exceed 10
        buffer[i] = 'A';
    }
}

void safe_loop_write(int n) {
    char buffer[10];
    int limit = (n < 10) ? n : 10;
    for (int i = 0; i < limit; i++) {
        buffer[i] = 'A';
    }
}

// Test 13: memmove with wrong size
void vuln_memmove_size(char *src, int n) {
    char dest[10];
    memmove(dest, src, n);  // Vulnerable - n may exceed 10
}

void safe_memmove_size(char *src, int n) {
    char dest[10];
    size_t copy_size = (n < 10) ? n : 10;
    memmove(dest, src, copy_size);
}

// =============================================================================
// CWE-676: Use of Potentially Dangerous Function
// =============================================================================

// Test 14: gets() usage
void vuln_gets_usage() {
    char buffer[10];
    gets(buffer);  // Vulnerable - no bounds checking possible
}

void safe_gets_usage() {
    char buffer[10];
    fgets(buffer, sizeof(buffer), stdin);  // Safe - size limited
}

// Test 15: scanf without width specifier
void vuln_scanf_no_width() {
    char buffer[10];
    scanf("%s", buffer);  // Vulnerable - no width limit
}

void safe_scanf_no_width() {
    char buffer[10];
    scanf("%9s", buffer);  // Safe - width specifier limits input
}

// =============================================================================
// String Length Tracking Tests
// =============================================================================

// Test 16: fgets length tracking
void vuln_fgets_tracking() {
    char buffer[10];
    fgets(buffer, 15, stdin);  // Vulnerable - reads more than buffer size
}

void safe_fgets_tracking() {
    char buffer[10];
    fgets(buffer, sizeof(buffer), stdin);  // Safe - correct size
}

// Test 17: scanf width tracking
void vuln_scanf_width() {
    char buffer[5];
    scanf("%20s", buffer);  // Vulnerable - width exceeds buffer
}

void safe_scanf_width() {
    char buffer[21];
    scanf("%20s", buffer);  // Safe - buffer matches width (+1 for null)
}

// Test 18: String literal length
void vuln_literal_length() {
    char buffer[5];
    const char *str = "Hello World";  // 11 chars + null
    strcpy(buffer, str);  // Vulnerable - literal is 12 bytes
}

void safe_literal_length() {
    char buffer[20];
    const char *str = "Hello World";
    strcpy(buffer, str);  // Safe - buffer is large enough
}

// =============================================================================
// Complex Multi-step Tests
// =============================================================================

// Test 19: Chained operations
void vuln_chained_ops(char *input) {
    char buffer1[10];
    char buffer2[5];
    strcpy(buffer1, input);  // Step 1: potentially unsafe
    strcpy(buffer2, buffer1);  // Step 2: definitely unsafe (10 > 5)
}

void safe_chained_ops(char *input) {
    char buffer1[10];
    char buffer2[10];
    strncpy(buffer1, input, sizeof(buffer1) - 1);
    buffer1[sizeof(buffer1) - 1] = '\0';
    strcpy(buffer2, buffer1);  // Safe - sizes match
}

// Test 20: Conditional allocation
void vuln_conditional_alloc(int size, int use_small) {
    char *buffer;
    if (use_small) {
        buffer = malloc(10);
    } else {
        buffer = malloc(100);
    }
    // Without tracking control flow, we don't know which size was allocated
    memcpy(buffer, "This is a test string that is quite long", 41);  // May overflow
    free(buffer);
}

void safe_conditional_alloc(int size, int use_small) {
    size_t buffer_size = use_small ? 10 : 100;
    char *buffer = malloc(buffer_size);
    if (buffer && buffer_size >= 41) {
        memcpy(buffer, "This is a test string that is quite long", 41);
    }
    free(buffer);
}

// Test 21: Loop with symbolic bound
void vuln_symbolic_loop(int n) {
    char buffer[10];
    for (int i = 0; i < n; i++) {  // Vulnerable if n > 10
        buffer[i] = 'X';
    }
}

void safe_symbolic_loop(int n) {
    char buffer[10];
    for (int i = 0; i < n && i < 10; i++) {
        buffer[i] = 'X';
    }
}

// Test 22: Offset arithmetic
void vuln_offset_arithmetic(int offset) {
    char buffer[10];
    char *ptr = buffer + offset;
    *ptr = 'A';  // Vulnerable - offset not validated
}

void safe_offset_arithmetic(int offset) {
    char buffer[10];
    if (offset >= 0 && offset < 10) {
        char *ptr = buffer + offset;
        *ptr = 'A';
    }
}

// Test 23: Size-2 pattern (common in null termination)
void vuln_size_minus_pattern(int n) {
    char *buffer = malloc(n);
    buffer[n - 2] = 'X';  // May be OK
    buffer[n] = '\0';     // Vulnerable - off by one
    free(buffer);
}

void safe_size_minus_pattern(int n) {
    char *buffer = malloc(n);
    buffer[n - 2] = 'X';
    buffer[n - 1] = '\0';  // Safe - correct index
    free(buffer);
}

// Test 24: realloc tracking
void vuln_realloc_tracking(int new_size) {
    char *buffer = malloc(10);
    strcpy(buffer, "test");
    buffer = realloc(buffer, new_size);  // Size changes
    memset(buffer, 'A', 20);  // Vulnerable - may exceed new_size
    free(buffer);
}

void safe_realloc_tracking(int new_size) {
    char *buffer = malloc(10);
    strcpy(buffer, "test");
    buffer = realloc(buffer, new_size);
    if (buffer && new_size >= 20) {
        memset(buffer, 'A', 20);
    }
    free(buffer);
}

// Test 25: String concatenation buildup
void vuln_concat_buildup() {
    char buffer[10] = "";
    strcat(buffer, "Hello");  // 5 chars
    strcat(buffer, " ");      // 6 chars
    strcat(buffer, "World");  // 11 chars - OVERFLOW
}

void safe_concat_buildup() {
    char buffer[20] = "";
    strncat(buffer, "Hello", sizeof(buffer) - strlen(buffer) - 1);
    strncat(buffer, " ", sizeof(buffer) - strlen(buffer) - 1);
    strncat(buffer, "World", sizeof(buffer) - strlen(buffer) - 1);
}

// Test 26: Array of strings
void vuln_string_array(int index) {
    char *strings[5] = {"one", "two", "three", "four", "five"};
    char buffer[5];
    strcpy(buffer, strings[index]);  // Vulnerable - index not validated, "three" won't fit
}

void safe_string_array(int index) {
    char *strings[5] = {"one", "two", "three", "four", "five"};
    char buffer[10];
    if (index >= 0 && index < 5) {
        strncpy(buffer, strings[index], sizeof(buffer) - 1);
        buffer[sizeof(buffer) - 1] = '\0';
    }
}

// Test 27: Nested loops
void vuln_nested_loops(int rows, int cols) {
    int matrix[10][10];
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            matrix[i][j] = i * j;  // Vulnerable if rows > 10 or cols > 10
        }
    }
}

void safe_nested_loops(int rows, int cols) {
    int matrix[10][10];
    int r = (rows < 10) ? rows : 10;
    int c = (cols < 10) ? cols : 10;
    for (int i = 0; i < r; i++) {
        for (int j = 0; j < c; j++) {
            matrix[i][j] = i * j;
        }
    }
}

// Test 28: Escape sequences in literals
void vuln_escape_sequences() {
    char buffer[5];
    strcpy(buffer, "Hi\n\t");  // 5 chars (H, i, \n, \t, \0) - exact fit but risky
    strcat(buffer, "X");  // Overflow - no room left
}

void safe_escape_sequences() {
    char buffer[10];
    strcpy(buffer, "Hi\n\t");
    strcat(buffer, "X");  // Safe - plenty of room
}

// Test 29: memcpy with sizeof misuse
void vuln_sizeof_misuse(int *src) {
    int dest[10];
    memcpy(dest, src, sizeof(src));  // Vulnerable - sizeof(pointer) not array
}

void safe_sizeof_misuse(int *src) {
    int dest[10];
    memcpy(dest, src, sizeof(dest));  // Safe - correct size
}

// Test 30: Off-by-one in loop bound
void vuln_off_by_one_loop() {
    char buffer[10];
    for (int i = 0; i <= 10; i++) {  // Vulnerable - should be i < 10
        buffer[i] = 'A';
    }
}

void safe_off_by_one_loop() {
    char buffer[10];
    for (int i = 0; i < 10; i++) {
        buffer[i] = 'A';
    }
}

// Test 31: strcat with unknown initial length (from variable initializer)
// The buffer is initialized from another variable, so the initial string length
// is unknown. Any subsequent strcat could overflow. Engine must NOT report safe.
void vuln_strcat_unknown_initial(const char *prefix, char *suffix) {
    char buffer[20];
    // 'prefix' initializes the content; we don't know how long it is
    strncpy(buffer, prefix, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    // strcat may overflow if prefix is near-full
    strcat(buffer, suffix);  // Potentially unsafe
}

int main() {
    printf("Bounds and string length test file - %d test pairs\n", 31);
    return 0;
}
