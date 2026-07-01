// Test _symbolic_condition_bounds_var across different data types
// This tests INDEX bounds (strict inequality) vs SIZE bounds (inclusive)

#include <stdlib.h>
#include <string.h>

// ==============================================================================
// ARRAYS - Index bounds require strict inequality
// ==============================================================================

void vuln_array_off_by_one(int n) {
    char buffer[10];
    // VULN: i <= 10 allows index 10 which is out of bounds (valid: 0-9)
    if (n >= 0 && n <= 10) {
        buffer[n] = 'X';  // CWE-125/787: off-by-one
    }
}

void safe_array_strict_bound(int n) {
    char buffer[10];
    // SAFE: i < 10 ensures index is in valid range 0-9
    if (n >= 0 && n < 10) {
        buffer[n] = 'X';
    }
}

// ==============================================================================
// HEAP MEMORY - Same semantics as arrays (offset must be < size)
// ==============================================================================

void vuln_heap_off_by_one(int offset) {
    char* ptr = malloc(100);
    // VULN: offset <= 100 allows offset 100 which is out of bounds (valid: 0-99)
    if (offset >= 0 && offset <= 100) {
        ptr[offset] = 'Y';  // CWE-125/787: off-by-one
    }
    free(ptr);
}

void safe_heap_strict_bound(int offset) {
    char* ptr = malloc(100);
    // SAFE: offset < 100 ensures offset is in valid range 0-99
    if (offset >= 0 && offset < 100) {
        ptr[offset] = 'Y';
    }
    free(ptr);
}

// ==============================================================================
// STRINGS - Null-terminated strings have different semantics
// ==============================================================================

void safe_string_null_terminated(char* str, int i) {
    // SAFE: null-terminator check ensures bounds
    // This is handled by _is_null_terminated_iteration, not _symbolic_condition_bounds_var
    while (str[i] != '\0') {
        str[i] = 'A';
        i++;
    }
}

void safe_string_with_strlen(char* str, int i) {
    // SAFE: strlen check (fast path in _is_guarded_by_bounds_check)
    if (i >= 0 && i < strlen(str)) {
        str[i] = 'B';
    }
}

void vuln_string_off_by_one(char* str, int i) {
    // VULN: i <= strlen(str) allows writing to the null terminator position
    // str[strlen(str)] overwrites '\0', corrupting the string
    if (i >= 0 && i <= strlen(str)) {
        str[i] = 'C';  // CWE-787: off-by-one (overwrites null terminator)
    }
}

// ==============================================================================
// STRUCTS - Field access doesn't use index bounds
// ==============================================================================

struct Point {
    int x;
    int y;
    char data[10];
};

void safe_struct_field_access(struct Point* p, int i) {
    // SAFE: accessing struct fields, not index bounds
    p->x = 42;
    p->y = 100;

    // Array within struct still needs index bounds
    if (i >= 0 && i < 10) {
        p->data[i] = 'C';
    }
}

void vuln_struct_array_off_by_one(struct Point* p, int i) {
    // VULN: i <= 10 allows index 10 for p->data[10]
    if (i >= 0 && i <= 10) {
        p->data[i] = 'D';  // CWE-125/787: off-by-one
    }
}

// ==============================================================================
// POINTER ARITHMETIC - Same semantics as arrays
// ==============================================================================

void vuln_pointer_arith_off_by_one(char* base, int offset) {
    // VULN: offset <= 50 allows offset 50 which is out of bounds
    if (offset >= 0 && offset <= 50) {
        *(base + offset) = 'Z';  // CWE-125/787: off-by-one (assuming base is malloc(50))
    }
}

void safe_pointer_arith_strict_bound(char* base, int offset) {
    // SAFE: offset < 50 ensures offset is in valid range 0-49
    if (offset >= 0 && offset < 50) {
        *(base + offset) = 'Z';
    }
}

// ==============================================================================
// SIZE VALIDATION - Different semantics (uses _condition_validates_size)
// ==============================================================================

void safe_memcpy_size_equal(char* dest, char* src, int size) {
    // SAFE: size <= 100 is correct for SIZE bounds (copying up to 100 bytes into 100-byte buffer)
    // This is validated by _condition_validates_size, NOT _symbolic_condition_bounds_var
    if (size <= 100) {
        memcpy(dest, src, size);  // OK when dest is 100 bytes
    }
}

void safe_memcpy_size_strict(char* dest, char* src, int size) {
    // SAFE: size < 100 is also safe (more conservative)
    if (size < 100) {
        memcpy(dest, src, size);
    }
}

// ==============================================================================
// MULTI-DIMENSIONAL ARRAYS
// ==============================================================================

void vuln_2d_array_off_by_one(int i, int j) {
    char matrix[10][20];
    // VULN: both i <= 10 and j <= 20 allow out-of-bounds indices
    if (i >= 0 && i <= 10 && j >= 0 && j <= 20) {
        matrix[i][j] = 'M';  // CWE-125/787: off-by-one on both dimensions
    }
}

void safe_2d_array_strict_bound(int i, int j) {
    char matrix[10][20];
    // SAFE: strict inequality for both dimensions
    if (i >= 0 && i < 10 && j >= 0 && j < 20) {
        matrix[i][j] = 'M';
    }
}
