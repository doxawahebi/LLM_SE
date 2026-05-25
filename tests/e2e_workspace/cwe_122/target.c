#include <stdlib.h>
#include <string.h>

void vulnerable(unsigned char *dst, size_t dst_size,
                unsigned char *src, size_t src_size) {
    memcpy(dst, src, src_size);   /* ← ℓ */
}
