// Sample vulnerable C code for testing PatchScout

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Buffer overflow vulnerabilities
void copy_data(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // CWE-120: Buffer overflow
}

void concat_strings(char *dest, char *src) {
    strcat(dest, src);  // CWE-120: Buffer overflow
}

// Format string vulnerability
void print_message(char *msg) {
    printf(msg);  // CWE-134: Format string vulnerability
}

// Use after free
void use_after_free_bug() {
    char *ptr = malloc(100);
    free(ptr);
    strcpy(ptr, "data");  // CWE-416: Use after free
}

// Integer overflow in malloc
void allocate_memory(int size) {
    char *buffer = malloc(size * sizeof(int));  // CWE-190: Integer overflow
}

// Unsafe user input
void read_input() {
    char buffer[100];
    gets(buffer);  // CWE-120: Dangerous function
}

int main() {
    char input[200];
    scanf("%s", input);
    copy_data(input);
    return 0;
}
