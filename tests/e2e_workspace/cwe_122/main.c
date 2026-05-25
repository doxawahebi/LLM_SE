#include <stdlib.h>

void vulnerable(unsigned char *dst, size_t dst_size,
                unsigned char *src, size_t src_size);

int main(void) {
    unsigned char *dst = malloc(16);
    unsigned char *src = malloc(512);
    size_t n = 17;
    vulnerable(dst, 16, src, n);
    free(dst);
    free(src);
    return 0;
}
