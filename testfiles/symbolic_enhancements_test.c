// Test file for symbolic interpreter enhancements
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BUF_SIZE 100
#define MAX_LEN 50

// Test 1: || false branch inference (De Morgan's law)
void test_or_false_branch() {
    char buffer[BUF_SIZE];
    int len = get_user_input();

    // False branch: !(len < 0 || len > BUF_SIZE) means len >= 0 AND len <= BUF_SIZE
    if (len < 0 || len > BUF_SIZE) {
        return; // Invalid
    } else {
        // SAFE: len is in range [0, BUF_SIZE]
        memcpy(buffer, get_data(), len); // Should NOT be flagged
    }
}

// Test 2: && false branch with short-circuit (left condition false)
void test_and_false_branch() {
    char buffer[BUF_SIZE];
    int len = get_user_input();

    // False branch with short-circuit: left is false means len >= BUF_SIZE
    if (len < BUF_SIZE && check_valid(len)) {
        process(buffer, len);
    } else {
        // len >= BUF_SIZE here (short-circuit: left was false)
        memcpy(buffer, get_data(), len); // Should be flagged as potentially unsafe
    }
}

// Test 3: Ternary conditional join
void test_ternary_clamp() {
    char buffer[BUF_SIZE];
    int requested_size = get_user_input();

    // Clamp size to MAX_LEN (50)
    int safe_size = (requested_size > MAX_LEN) ? MAX_LEN : requested_size;

    // Even if requested_size is huge, safe_size is at most MAX_LEN
    char *data = malloc(safe_size); // Should NOT be flagged as integer overflow

    // But this could still overflow if requested_size is negative
    memcpy(buffer, data, safe_size); // May flag if safe_size could be negative
}

// Test 4: strlen on string literal
void test_strlen_literal() {
    char buffer[20];

    // strlen("hello") == 5 (constant)
    int len = strlen("hello");

    // SAFE: len is definitely 5, well within buffer size
    memcpy(buffer, "hello", len); // Should NOT be flagged

    // UNSAFE: explicit overflow
    memcpy(buffer, "this is a very long string that will overflow",
           strlen("this is a very long string that will overflow")); // Should be flagged
}

// Test 5: Combination - ternary + constraint
void test_combined() {
    char buffer[BUF_SIZE];
    int user_len = get_user_input();

    // Clamp to BUF_SIZE
    int clamped = (user_len > BUF_SIZE) ? BUF_SIZE : user_len;

    if (clamped < 0 || clamped > BUF_SIZE) {
        return; // Impossible - already clamped
    } else {
        // SAFE: clamped is in [0, BUF_SIZE]
        memcpy(buffer, get_data(), clamped); // Should NOT be flagged
    }
}

// Test 6: Nested || with De Morgan
void test_nested_or() {
    char buffer[BUF_SIZE];
    int len = get_user_input();

    // Complex condition: !(len < 5 || len > 95 || len == 50)
    // False branch means: len >= 5 AND len <= 95 AND len != 50
    if (len < 5 || len > 95 || len == 50) {
        return;
    } else {
        // SAFE: len is in [5, 95] excluding 50
        memcpy(buffer, get_data(), len); // Should NOT be flagged
    }
}

// Test 7: Short-circuit && with multiple conditions
void test_multiple_and() {
    char buffer[BUF_SIZE];
    int len = get_user_input();

    // If false: leftmost false condition applies (short-circuit)
    if (len > 0 && len < BUF_SIZE && check_valid(len)) {
        memcpy(buffer, get_data(), len);
    } else {
        // Could be: len <= 0, OR len >= BUF_SIZE, OR invalid
        // With short-circuit: if len > 0 failed, we know len <= 0
        if (len <= 0) {
            // Definitely here due to short-circuit
            return;
        }
        // Otherwise len >= BUF_SIZE
        memcpy(buffer, get_data(), len); // Should be flagged
    }
}

// Helpers
extern int get_user_input(void);
extern void* get_data(void);
extern int check_valid(int);
extern void process(char*, int);
