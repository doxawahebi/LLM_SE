# CWE-476: Null Pointer Dereference

## Vulnerability

`vulnerable()` accesses `p->x` without checking whether `p` is NULL.
When `p = NULL`, the dereference causes a segfault.

## Detection

- **Phase 1**: CodeQL query `cpp/cwe-476/null-pointer-dereference` flags
  the unguarded dereference of `p`.
- **Phase 2**: KLEE makes `p` symbolic and finds `p = NULL` triggers a
  memory error.
- **Phase 3**: ASan/OS confirms the null dereference crash in `target.c`.

## Entry point

`vulnerable()` — called directly from `main()`, no guard conditions.
