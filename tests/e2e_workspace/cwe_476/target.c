#include <stdlib.h>

typedef struct { int x; } Node;

static int vulnerable(Node *p) {
    return p->x;           /* ← ℓ  null deref when p == NULL */
}

int main(void) {
    return vulnerable(NULL);   /* exploit: p = NULL */
}
