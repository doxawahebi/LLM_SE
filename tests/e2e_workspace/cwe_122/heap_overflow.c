#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*
 * DELIBERATE VULNERABILITY: heap buffer overflow.
 * Only 8 bytes are allocated; 32 bytes are written.
 */
#define WRITE_SIZE 32

void heap_write(const char *input) {
    char *heap_buf = (char *)malloc(8);
    if (!heap_buf) return;
    memcpy(heap_buf, input, WRITE_SIZE);  /* line 13 — overflow */
    free(heap_buf);
}

#ifndef HARNESS
int main(void) {
    char input[WRITE_SIZE];
    size_t n = 0;
    while (n < WRITE_SIZE) {
        int c = getchar();
        if (c == EOF) break;
        input[n++] = (char)c;
    }
    heap_write(input);
    return 0;
}
#endif
