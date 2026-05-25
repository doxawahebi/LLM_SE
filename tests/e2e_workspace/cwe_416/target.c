#include <stdlib.h>
#include <string.h>

typedef struct { int value; } Item;

static int vulnerable(int trigger) {
    Item *p = malloc(sizeof(Item));
    p->value = 42;
    if (trigger) {
        free(p);           /* free */
    }
    return p->value;       /* ← ℓ  use-after-free when trigger != 0 */
}

int main(void) {
    return vulnerable(1);  /* exploit: trigger = 1 */
}
