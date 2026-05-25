# CWE-121: Stack-Based Buffer Overflow

## Vulnerability

`vulnerable()` calls `memcpy(buf, input, input_len)` without checking that
`input_len <= sizeof(buf)`. When `input_len = 17` and `buf` is only 16 bytes,
the copy writes 1 byte past the end of the stack buffer.

## Detection

- **Phase 1**: CodeQL query `local/cpp/cwe-120-overflow` flags the `memcpy`
  call because `input_len` is not guarded.
- **Phase 2**: KLEE finds `input_len = 17` triggers an out-of-bounds write.
- **Phase 3**: ASan confirms `stack-buffer-overflow` in `target.c`.

## Entry point

`vulnerable()` — called directly from `main()`, no guard conditions.
