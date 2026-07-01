#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function() {
    char buffer[10];
    char input[100];
    
    printf("Enter text: ");
    // Source: Read up to 100 chars
    fgets(input, 100, stdin);
    
    // Sink: Copy 100 chars into 10-char buffer
    // Vulnerability: CWE-121 Stack-based Buffer Overflow
    strcpy(buffer, input);
    
    printf("Buffer: %s\n", buffer);
}

void safe_function() {
    char buffer[10];
    char input[100];
    
    fgets(input, 100, stdin);
    
    // Safe: Check length first (Sanitizer)
    if (strlen(input) < 10) {
        strcpy(buffer, input);
    }
}

int main() {
    vulnerable_function();
    return 0;
}
