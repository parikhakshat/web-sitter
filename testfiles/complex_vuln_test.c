/*
 * complex_vuln_test.c - Comprehensive vulnerability test cases
 * 
 * This file contains multiple vulnerable and safe functions to test
 * all rules in the rule_matcher/rules/ directory:
 * - CWE-121: Buffer Overflow (strcpy, memcpy, sprintf, gets, array OOB, VLA)
 * - CWE-416: Use After Free (classic UAF, double free, return freed, missing NULL)
 * - CWE-78: Command Injection (system, popen, sprintf+system, getenv)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ============================================================================
 * CWE-121: Buffer Overflow Vulnerabilities
 * ============================================================================ */

/* VULNERABLE: CWE121-STRCPY-OVERFLOW - strcpy with fgets source */
void vuln_strcpy_from_fgets() {
    char buffer[10];
    char input[100];
    
    fgets(input, sizeof(input), stdin);  // Source: user input
    strcpy(buffer, input);  // VULNERABLE: input can exceed buffer size
    
    printf("You entered: %s\n", buffer);
}

/* VULNERABLE: CWE121-STRCPY-OVERFLOW - strcpy with gets (deprecated) */
void vuln_strcpy_from_gets() {
    char buffer[20];
    char input[200];
    
    gets(input);  // VULNERABLE: gets itself is dangerous
    strcpy(buffer, input);  // VULNERABLE: no bounds checking
}

/* SAFE: strcpy with strlen guard - should NOT flag */
void safe_strcpy_with_guard() {
    char buffer[50];
    char input[100];
    
    fgets(input, sizeof(input), stdin);
    if (strlen(input) < sizeof(buffer)) {
        strcpy(buffer, input);  // SAFE: protected by strlen check
    }
}

/* SAFE: strncpy instead of strcpy - should NOT flag */
void safe_strncpy() {
    char buffer[50];
    char input[100];
    
    fgets(input, sizeof(input), stdin);
    strncpy(buffer, input, sizeof(buffer) - 1);  // SAFE: bounded copy
    buffer[sizeof(buffer) - 1] = '\0';
}

/* VULNERABLE: CWE121-MEMCPY-OVERFLOW - memcpy with unchecked size */
void vuln_memcpy_overflow(size_t user_size) {
    char dest[64];
    char src[256];
    
    read(0, src, 256);  // Read from stdin
    memcpy(dest, src, user_size);  // VULNERABLE: user_size could exceed 64
}

/* VULNERABLE: CWE121-SPRINTF-OVERFLOW - sprintf without bounds */
void vuln_sprintf_overflow(const char* username) {
    char buffer[128];
    
    sprintf(buffer, "Welcome, %s! Your session has started.", username);
    // VULNERABLE: username could overflow buffer
}

/* SAFE: snprintf with bounds - should NOT flag CWE121-SPRINTF */
void safe_snprintf(const char* username) {
    char buffer[128];
    
    snprintf(buffer, sizeof(buffer), "Welcome, %s!", username);  // SAFE
}

/* VULNERABLE: CWE121-GETS-DEPRECATED - gets is always unsafe */
void vuln_gets_usage() {
    char buffer[100];
    
    printf("Enter your name: ");
    gets(buffer);  // VULNERABLE: gets() cannot be used safely
    printf("Hello, %s!\n", buffer);
}

/* VULNERABLE: CWE121-ARRAY-OOB - array access with tainted index */
void vuln_array_oob() {
    int data[100];
    int index;
    
    scanf("%d", &index);  // Tainted source
    
    int value = data[index];  // VULNERABLE: index not validated
    printf("Value: %d\n", value);
}

/* SAFE: array access with bounds check - should NOT flag */
void safe_array_access() {
    int data[100];
    int index;
    
    scanf("%d", &index);
    
    if (index >= 0 && index < 100) {
        int value = data[index];  // SAFE: bounds checked
        printf("Value: %d\n", value);
    }
}

/* VULNERABLE: CWE121-VLA-TAINTED-SIZE - VLA with tainted size */
void vuln_vla_tainted_size() {
    int size;
    
    scanf("%d", &size);  // Tainted source
    
    char buffer[size];  // VULNERABLE: stack allocation with user-controlled size
    fgets(buffer, size, stdin);
}

/* ============================================================================
 * CWE-416: Use After Free Vulnerabilities
 * ============================================================================ */

/* VULNERABLE: CWE416-USE-AFTER-FREE - classic UAF pattern */
void vuln_use_after_free() {
    char* ptr = malloc(100);
    
    strcpy(ptr, "Hello World");
    printf("Before free: %s\n", ptr);
    
    free(ptr);  // Memory freed
    
    printf("After free: %s\n", ptr);  // VULNERABLE: use after free
}

/* VULNERABLE: CWE416-USE-AFTER-FREE - UAF in struct access */
struct Node {
    int value;
    struct Node* next;
};

void vuln_uaf_struct() {
    struct Node* node = malloc(sizeof(struct Node));
    node->value = 42;
    node->next = NULL;
    
    free(node);  // Memory freed
    
    int val = node->value;  // VULNERABLE: accessing freed memory
    printf("Value: %d\n", val);
}

/* VULNERABLE: CWE415-DOUBLE-FREE - freeing memory twice */
void vuln_double_free() {
    char* buffer = malloc(256);
    
    strcpy(buffer, "Some data");
    
    free(buffer);  // First free
    
    // Some code that might forget buffer was freed...
    
    free(buffer);  // VULNERABLE: double free
}

/* VULNERABLE: CWE416-RETURN-FREED - returning freed pointer */
char* vuln_return_freed() {
    char* data = malloc(100);
    
    strcpy(data, "temporary data");
    
    free(data);  // Memory freed
    
    return data;  // VULNERABLE: returning dangling pointer
}

/* VULNERABLE: CWE416-MISSING-NULL-AFTER-FREE - not nullifying after free */
void vuln_missing_null_after_free() {
    char* ptr = malloc(50);
    
    strcpy(ptr, "data");
    
    free(ptr);  // VULNERABLE: ptr not set to NULL
    
    // Later code might accidentally use ptr thinking it's valid
    // ptr = NULL;  // Missing!
}

/* SAFE: Setting NULL after free - good practice */
void safe_null_after_free() {
    char* ptr = malloc(50);
    
    strcpy(ptr, "data");
    
    free(ptr);
    ptr = NULL;  // SAFE: nullified after free
    
    // Any accidental use would now cause immediate crash (better than UAF)
}

/* SAFE: Proper memory management - should NOT flag UAF */
void safe_memory_management() {
    char* buffer = malloc(100);
    
    if (buffer == NULL) {
        return;
    }
    
    strcpy(buffer, "Hello");
    printf("Data: %s\n", buffer);
    
    free(buffer);
    buffer = NULL;
    // No more use of buffer after this point
}

/* ============================================================================
 * CWE-78: Command Injection Vulnerabilities
 * ============================================================================ */

/* VULNERABLE: CWE78-SYSTEM-INJECTION - system() with user input */
void vuln_system_injection() {
    char command[256];
    char filename[128];
    
    printf("Enter filename to display: ");
    fgets(filename, sizeof(filename), stdin);  // Tainted source
    
    sprintf(command, "cat %s", filename);
    system(command);  // VULNERABLE: filename could contain shell metacharacters
}

/* VULNERABLE: CWE78-SYSTEM-INJECTION - popen with user input */
void vuln_popen_injection() {
    char cmd[256];
    char input[100];
    
    recv(0, input, sizeof(input), 0);  // Tainted from network
    
    sprintf(cmd, "grep %s /etc/passwd", input);
    
    FILE* fp = popen(cmd, "r");  // VULNERABLE: command injection via popen
    if (fp) {
        char result[1024];
        fgets(result, sizeof(result), fp);
        printf("%s", result);
        pclose(fp);
    }
}

/* VULNERABLE: CWE78-SPRINTF-COMMAND - sprintf + system composite */
void vuln_sprintf_then_system() {
    char cmd_buffer[512];
    char user_input[256];
    
    scanf("%s", user_input);  // Tainted source
    
    sprintf(cmd_buffer, "ls -la /home/%s", user_input);  // Stage 2: sprintf
    
    system(cmd_buffer);  // Stage 3: execute - VULNERABLE
}

/* VULNERABLE: CWE78-GETENV-COMMAND - environment variable in command */
void vuln_getenv_command() {
    char* path = getenv("USER_PATH");  // Tainted from environment
    char command[256];
    
    if (path != NULL) {
        sprintf(command, "ls %s", path);
        system(command);  // VULNERABLE: env var in command
    }
}

/* SAFE: Command with hardcoded value - should NOT flag */
void safe_hardcoded_command() {
    system("ls -la /tmp");  // SAFE: no user input
}

/* SAFE: Validated input before command - should NOT flag */
void safe_validated_command(const char* filename) {
    // Only allow alphanumeric filenames
    for (int i = 0; filename[i] != '\0'; i++) {
        char c = filename[i];
        if (!((c >= 'a' && c <= 'z') || 
              (c >= 'A' && c <= 'Z') || 
              (c >= '0' && c <= '9'))) {
            printf("Invalid filename\n");
            return;
        }
    }
    
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "cat %s", filename);
    system(cmd);  // Safer: input was validated
}

/* ============================================================================
 * Additional Complex Test Cases
 * ============================================================================ */

/* VULNERABLE: Multiple issues in one function */
void vuln_multiple_issues() {
    char* ptr = malloc(50);
    char buffer[20];
    char input[100];
    
    // Issue 1: fgets to strcpy without bounds check
    fgets(input, sizeof(input), stdin);
    strcpy(buffer, input);  // VULNERABLE: CWE-121
    
    // Issue 2: Use after free
    free(ptr);
    strcpy(ptr, "test");  // VULNERABLE: CWE-416
}

/* VULNERABLE: Interprocedural dataflow (helper function) */
char* get_user_input() {
    static char buffer[256];
    fgets(buffer, sizeof(buffer), stdin);
    return buffer;
}

void vuln_interprocedural() {
    char* input = get_user_input();  // Tainted
    char small_buffer[10];
    
    strcpy(small_buffer, input);  // VULNERABLE: interprocedural taint flow
}

/* VULNERABLE: Conditional UAF - freed in one branch */
void vuln_conditional_uaf(int condition) {
    char* data = malloc(100);
    
    if (condition) {
        free(data);
    }
    
    // Bug: data might be freed depending on condition
    printf("Data: %s\n", data);  // VULNERABLE: potential UAF
}

/* Main function for testing */
int main(int argc, char* argv[]) {
    printf("Complex Vulnerability Test Cases\n");
    printf("================================\n\n");
    
    printf("This file contains intentionally vulnerable code.\n");
    printf("Do NOT use any of these patterns in production!\n");
    
    return 0;
}
