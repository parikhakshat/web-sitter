// Test file for guard validation enhancements
#include <string.h>
#include <stdlib.h>

// Test 1: Valid guard - checks the correct variable (size)
void test_valid_guard_memcpy(char *src, size_t size) {
    // This guard checks 'size' which is relevant to the memcpy below
    if (size >= 1024) {
        return;  // Early return
    }

    char buf[1024];
    memcpy(buf, src, size);  // Should be SAFE - protected by guard
}

// Test 2: Invalid guard - checks wrong variable
void test_invalid_guard_memcpy(char *src, size_t size, int flag) {
    // This guard checks 'flag' which is NOT relevant to the memcpy
    if (flag >= 10) {
        return;  // Early return but irrelevant
    }

    char buf[100];
    memcpy(buf, src, size);  // Should be VULNERABLE - guard doesn't check size/buf
}

// Test 3: Valid guard for strcpy - checks destination buffer
void test_valid_guard_strcpy(char *src, char *dest, size_t dest_size) {
    // Guard checks dest_size which relates to destination buffer
    if (dest_size < strlen(src) + 1) {
        return;
    }

    strcpy(dest, src);  // Should be SAFE - protected by guard
}

// Test 4: Invalid guard for strcpy - checks unrelated variable
void test_invalid_guard_strcpy(char *src, char *dest, int count) {
    // Guard checks 'count' which is NOT related to src/dest
    if (count >= 100) {
        return;
    }

    strcpy(dest, src);  // Should be VULNERABLE - no size check
}

// Test 5: Valid guard for array access - checks index
void test_valid_guard_array(int *arr, int index, int size) {
    // Guard checks 'index' against 'size'
    if (index >= size) {
        return;
    }

    int val = arr[index];  // Should be SAFE - index validated
}

// Test 6: Invalid guard for array access - checks wrong variable
void test_invalid_guard_array(int *arr, int index, int limit) {
    // Guard checks 'limit' which is unrelated to the array access
    if (limit >= 50) {
        return;
    }

    int val = arr[index];  // Should be VULNERABLE - index not checked
}

// Test 7: Valid guard for pointer dereference
void test_valid_guard_pointer(char *ptr) {
    // Guard checks 'ptr' for NULL
    if (ptr == NULL) {
        return;
    }

    char c = *ptr;  // Should be SAFE - NULL check exists
}

// Test 8: Invalid guard for pointer dereference - checks wrong pointer
void test_invalid_guard_pointer(char *ptr, char *other) {
    // Guard checks 'other' not 'ptr'
    if (other == NULL) {
        return;
    }

    char c = *ptr;  // Should be VULNERABLE - ptr not checked
}

// Test 9: Valid guard for snprintf - checks buffer size
void test_valid_guard_snprintf(char *buf, size_t buf_size, const char *fmt) {
    // Guard checks buf_size
    if (buf_size < 10) {
        return;
    }

    snprintf(buf, buf_size, fmt);  // Should be SAFE - size validated
}

// Test 10: No guard at all - baseline vulnerable case
void test_no_guard_memcpy(char *src, size_t size) {
    char buf[100];
    memcpy(buf, src, size);  // Should be VULNERABLE - no guard
}
