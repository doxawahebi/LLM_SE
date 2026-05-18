#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*
 * DELIBERATE VULNERABILITY: stack-based buffer overflow.
 * `buf` is 16 bytes; we copy INPUT_SIZE bytes unconditionally.
 */
#define INPUT_SIZE 64

void stack_overflow(const char *input) {
    char buf[16];
    memcpy(buf, input, INPUT_SIZE);   /* line 12 — overflow */
}

#ifndef HARNESS
int main(void) {
    char input[INPUT_SIZE];
    /* read exactly INPUT_SIZE bytes from stdin for reproducibility */
    size_t n = 0;
    while (n < INPUT_SIZE) {
        int c = getchar();
        if (c == EOF) break;
        input[n++] = (char)c;
    }
    stack_overflow(input);
    return 0;
}
#endif
