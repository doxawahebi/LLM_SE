#include <string.h>

static void vulnerable(const char *input, size_t input_len) {
    char buf[16];
    memcpy(buf, input, input_len);   /* ← ℓ */
}

int main(void) {
    char input[512];
    vulnerable(input, 17);           /* exploit: 17 > 16 */
    return 0;
}
