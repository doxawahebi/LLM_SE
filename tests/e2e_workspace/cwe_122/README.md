# CWE-122: Heap-Based Buffer Overflow

## Vulnerability

`vulnerable()` calls `memcpy(dst, src, src_size)` without checking that
`src_size <= dst_size`. When `src_size = 17` and `dst` is only 16 bytes,
the copy writes 1 byte past the end of the heap allocation.

## Detection

- **Phase 1**: CodeQL query `local/cpp/cwe-120-overflow` flags the `memcpy`
  call because `src_size` is not guarded by `sizeof` or `strlen`.
- **Phase 2**: KLEE finds `src_size = 17` satisfies `src_size > 16` and
  triggers an out-of-bounds write.
- **Phase 3**: ASan confirms `heap-buffer-overflow` in `target.c`.

## Entry point

`vulnerable()` — called directly from `main()`, no guard conditions.
