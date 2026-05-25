# CWE-416: Use-After-Free

## Vulnerability

`vulnerable()` frees `p` when `trigger != 0`, then accesses `p->value`.
The read of `p->value` after `free(p)` is a use-after-free.

## Detection

- **Phase 1**: CodeQL query `cpp/cwe-416/use-after-free` flags the access
  to `p->value` after `free(p)` on the `trigger != 0` path.
- **Phase 2**: KLEE sets `trigger = 1` to reach the free, then detects
  the subsequent dereference.
- **Phase 3**: ASan confirms `heap-use-after-free` in `target.c`.

## Entry point

`vulnerable()` — called directly from `main()`, one guard condition
`if (trigger)`.

## Note

The Phase 2 free() stub MUST call the real `free()` per paper §4.2.
