"""CodeQL query suite for Sailor Phase 1.

Contains all 34 query definitions:
  • 13 standard queries  (referenced by CodeQL package path)
  • 21 custom  queries   (embedded .ql source strings)

Usage::

    from pathlib import Path
    from sailor.codeql.queries import CodeQLQuerySuite

    suite = CodeQLQuerySuite()
    custom_paths = suite.write_custom_queries(Path("/tmp/sailor_ql"))
    std_paths    = suite.resolve_standard_queries(Path("/opt/codeql"))
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import NamedTuple

logger = logging.getLogger("sailor.codeql.queries")


# ---------------------------------------------------------------------------
# Standard query paths (relative to CodeQL home)
# ---------------------------------------------------------------------------

class StandardQuery(NamedTuple):
    category: str
    cwe: str
    rel_path: str   # path inside <codeql-home>/ql/


STANDARD_QUERIES: list[StandardQuery] = [
    # Memory corruption — CWE-120, 121, 125, 476, 787 (6)
    StandardQuery("memory-corruption", "CWE-120",
                  "cpp/ql/src/Security/CWE/CWE-120/BufferCopyWithoutCheckingSize.ql"),
    StandardQuery("memory-corruption", "CWE-120",
                  "cpp/ql/src/Security/CWE/CWE-120/UnboundedWrite.ql"),
    StandardQuery("memory-corruption", "CWE-121",
                  "cpp/ql/src/Security/CWE/CWE-121/CWE-121.ql"),
    StandardQuery("memory-corruption", "CWE-125",
                  "cpp/ql/src/Security/CWE/CWE-125/BufferReadOverflow.ql"),
    StandardQuery("memory-corruption", "CWE-476",
                  "cpp/ql/src/Security/CWE/CWE-476/NullPointerDereferenceGoodWithNullTests.ql"),
    StandardQuery("memory-corruption", "CWE-787",
                  "cpp/ql/src/Security/CWE/CWE-787/PointerArithmetic.ql"),
    # Integer overflow — CWE-190 (4)
    StandardQuery("integer-overflow", "CWE-190",
                  "cpp/ql/src/Security/CWE/CWE-190/ArithmeticUncontrolled.ql"),
    StandardQuery("integer-overflow", "CWE-190",
                  "cpp/ql/src/Security/CWE/CWE-190/IntegerOverflowTainted.ql"),
    StandardQuery("integer-overflow", "CWE-190",
                  "cpp/ql/src/Security/CWE/CWE-190/ArithmeticWithExtremeValues.ql"),
    StandardQuery("integer-overflow", "CWE-190",
                  "cpp/ql/src/Security/CWE/CWE-190/ComparisonWithWiderType.ql"),
    # UAF / double-free — CWE-415, 416, 562 (3)
    StandardQuery("uaf-double-free", "CWE-415",
                  "cpp/ql/src/Security/CWE/CWE-415/DoubleFree.ql"),
    StandardQuery("uaf-double-free", "CWE-416",
                  "cpp/ql/src/Security/CWE/CWE-416/UseAfterFree.ql"),
    StandardQuery("uaf-double-free", "CWE-562",
                  "cpp/ql/src/Security/CWE/CWE-562/ReturnStackAllocatedMemory.ql"),
]


# ---------------------------------------------------------------------------
# Custom query source strings (21 total)
# ---------------------------------------------------------------------------

class CustomQuery(NamedTuple):
    name: str
    query_id: str
    cwe: str
    source: str


def _ql(name: str, query_id: str, cwe: str, source: str) -> CustomQuery:
    return CustomQuery(name=name, query_id=query_id, cwe=cwe, source=source)


CUSTOM_QUERIES: list[CustomQuery] = [

    # ── Buffer Overflow (6) ────────────────────────────────────────────────

    _ql(
        name="cwe-120-memcpy-unchecked-length",
        query_id="local/cpp/cwe-120-overflow",
        cwe="CWE-120",
        source='''\
/**
 * @name CWE-120: Unchecked length in memory-copy call
 * @id local/cpp/cwe-120-overflow
 * @kind problem
 * @severity error
 * @tags security external/cwe/cwe-120
 */
import cpp

predicate isWriteFunc(Function f) {
  f.getName().regexpMatch("(?i)^(memcpy|memmove|memset|strncpy|strncat)$")
}
predicate isSizeofLike(Expr e) { e instanceof SizeofExprOperator }
predicate isStringBound(Expr e) { e.toString().regexpMatch(".*(strlen|strnlen).*") }

from FunctionCall fc, Function f, Expr n
where fc.getTarget() = f
  and isWriteFunc(f)
  and n = fc.getArgument(2)
  and not isStringBound(n)
  and not isSizeofLike(n)
select fc, "CWE-120: Buffer Overflow via " + f.getName() + " (unchecked length)."
''',
    ),

    _ql(
        name="cwe-120-sprintf-fixed-buffer",
        query_id="local/cpp/cwe-120-sprintf",
        cwe="CWE-120",
        source='''\
/**
 * @name CWE-120: Use of sprintf without bounds checking
 * @id local/cpp/cwe-120-sprintf
 * @kind problem
 * @severity error
 * @tags security external/cwe/cwe-120
 */
import cpp

from FunctionCall fc
where fc.getTarget().hasName("sprintf")
select fc, "CWE-120: sprintf() may overflow destination buffer; prefer snprintf()."
''',
    ),

    _ql(
        name="cwe-120-gets-unbounded",
        query_id="local/cpp/cwe-120-gets",
        cwe="CWE-120",
        source='''\
/**
 * @name CWE-120: Use of gets() or fgets without length limit
 * @id local/cpp/cwe-120-gets
 * @kind problem
 * @severity error
 * @tags security external/cwe/cwe-120
 */
import cpp

from FunctionCall fc, Function f
where fc.getTarget() = f
  and f.getName().regexpMatch("^(gets|getwd)$")
select fc, "CWE-120: " + f.getName() + "() performs no bounds checking on the destination."
''',
    ),

    _ql(
        name="cwe-125-memcpy-source-unchecked",
        query_id="local/cpp/cwe-125-memcpy-src",
        cwe="CWE-125",
        source='''\
/**
 * @name CWE-125: Out-of-bounds read via memcpy with unchecked source length
 * @id local/cpp/cwe-125-memcpy-src
 * @kind problem
 * @severity error
 * @tags security external/cwe/cwe-125
 */
import cpp

predicate isReadFunc(Function f) {
  f.getName().regexpMatch("(?i)^(memcpy|memmove|memcmp|strncmp|bcopy)$")
}
predicate isSizeofLike(Expr e) { e instanceof SizeofExprOperator }
predicate isStringBound(Expr e) { e.toString().regexpMatch(".*(strlen|strnlen).*") }

from FunctionCall fc, Function f, Expr n
where fc.getTarget() = f
  and isReadFunc(f)
  and n = fc.getArgument(2)
  and not isStringBound(n)
  and not isSizeofLike(n)
select fc, "CWE-125: " + f.getName() + "() reads up to n bytes without validating source length."
''',
    ),

    _ql(
        name="cwe-787-memcpy-heap-unchecked",
        query_id="local/cpp/cwe-787-memcpy-heap",
        cwe="CWE-787",
        source='''\
/**
 * @name CWE-787: memcpy into heap buffer with non-sizeof size
 * @id local/cpp/cwe-787-memcpy-heap
 * @kind problem
 * @severity error
 * @tags security external/cwe/cwe-787
 */
import cpp

predicate isAllocFunc(Function f) {
  f.getName().regexpMatch("(malloc|calloc|realloc|xmalloc|g_malloc|bfd_alloc|bfd_zalloc)")
}
predicate isSizeofLike(Expr e) { e instanceof SizeofExprOperator }

from FunctionCall cpy, FunctionCall alloc
where cpy.getTarget().hasName("memcpy")
  and alloc.getTarget() instanceof Function
  and isAllocFunc(alloc.getTarget())
  and cpy.getEnclosingFunction() = alloc.getEnclosingFunction()
  and not isSizeofLike(cpy.getArgument(2))
select cpy, "CWE-787: memcpy into malloc'd buffer without sizeof-derived size argument."
''',
    ),

    _ql(
        name="cwe-823-pointer-arithmetic-unchecked",
        query_id="local/cpp/cwe-823-ptr-arith",
        cwe="CWE-823",
        source='''\
/**
 * @name CWE-823: Pointer arithmetic without offset validation
 * @id local/cpp/cwe-823-ptr-arith
 * @kind problem
 * @severity error
 * @tags security external/cwe/cwe-823
 */
import cpp

from PointerAddExpr pae
where not pae.getRightOperand() instanceof Literal
select pae,
  "CWE-823: Non-literal offset in pointer arithmetic — verify offset is within allocation bounds."
''',
    ),

    # ── Null Dereference (1) ────────────────────────────────────────────────

    _ql(
        name="cwe-476-null-deref-no-check",
        query_id="local/cpp/cwe-476-null-deref",
        cwe="CWE-476",
        source='''\
/**
 * @name CWE-476: Missing NULL check after heap allocation
 * @id local/cpp/cwe-476-null-deref
 * @kind problem
 * @severity error
 * @tags security external/cwe/cwe-476
 */
import cpp

predicate isAllocFunc(Function f) {
  f.getName().regexpMatch("(malloc|calloc|realloc|strdup|fopen|xmalloc|g_malloc|bfd_alloc)")
}

from FunctionCall fc, Variable v, PointerDereferenceExpr pde
where isAllocFunc(fc.getTarget())
  and exists(AssignExpr ae |
    ae.getRValue() = fc
    and ae.getLValue() = v.getAnAccess())
  and pde.getOperand() = v.getAnAccess()
  and not exists(IfStmt guard |
    guard.getCondition().(NotExpr).getOperand() = v.getAnAccess()
    or guard.getCondition() = v.getAnAccess())
select pde,
  "CWE-476: Dereference of '" + v.getName() + "' without NULL check after allocation call."
''',
    ),

    # ── Uncontrolled Recursion (1) ─────────────────────────────────────────

    _ql(
        name="cwe-674-unbounded-recursion",
        query_id="local/cpp/cwe-674-recursion",
        cwe="CWE-674",
        source='''\
/**
 * @name CWE-674: Unbounded direct recursion
 * @id local/cpp/cwe-674-recursion
 * @kind problem
 * @severity error
 * @tags security external/cwe/cwe-674
 */
import cpp

from Function f, FunctionCall fc
where fc.getTarget() = f
  and fc.getEnclosingFunction() = f
select fc,
  "CWE-674: Direct self-recursion in " + f.getName() + "() with no visible depth bound."
''',
    ),

    # ── Use-After-Free Variants (6) ────────────────────────────────────────

    _ql(
        name="cwe-416-uaf-dereference",
        query_id="local/cpp/cwe-416-deref",
        cwe="CWE-416",
        source='''\
/**
 * @name CWE-416: Use after free — pointer dereference
 * @id local/cpp/cwe-416-deref
 * @kind problem
 * @severity error
 * @tags security external/cwe/cwe-416
 */
import cpp

from FunctionCall free_call, PointerDereferenceExpr pde, Variable v
where free_call.getTarget().hasName("free")
  and free_call.getArgument(0) = v.getAnAccess()
  and pde.getOperand() = v.getAnAccess()
  and free_call.getEnclosingFunction() = pde.getEnclosingFunction()
  and free_call.getLocation().isBefore(pde.getLocation())
select pde, "CWE-416: Dereference of '" + v.getName() + "' after free()."
''',
    ),

    _ql(
        name="cwe-416-uaf-field-access",
        query_id="local/cpp/cwe-416-field",
        cwe="CWE-416",
        source='''\
/**
 * @name CWE-416: Use after free — struct field access via freed pointer
 * @id local/cpp/cwe-416-field
 * @kind problem
 * @severity error
 * @tags security external/cwe/cwe-416
 */
import cpp

from FunctionCall free_call, FieldAccess fa, Variable v
where free_call.getTarget().hasName("free")
  and free_call.getArgument(0) = v.getAnAccess()
  and fa.getQualifier() = v.getAnAccess()
  and free_call.getEnclosingFunction() = fa.getEnclosingFunction()
  and free_call.getLocation().isBefore(fa.getLocation())
select fa, "CWE-416: Field access through freed pointer '" + v.getName() + "'."
''',
    ),

    _ql(
        name="cwe-416-uaf-write",
        query_id="local/cpp/cwe-416-write",
        cwe="CWE-416",
        source='''\
/**
 * @name CWE-416: Use after free — write through freed pointer
 * @id local/cpp/cwe-416-write
 * @kind problem
 * @severity error
 * @tags security external/cwe/cwe-416
 */
import cpp

from FunctionCall free_call, AssignExpr ae, Variable v
where free_call.getTarget().hasName("free")
  and free_call.getArgument(0) = v.getAnAccess()
  and ae.getLValue().(PointerDereferenceExpr).getOperand() = v.getAnAccess()
  and free_call.getEnclosingFunction() = ae.getEnclosingFunction()
  and free_call.getLocation().isBefore(ae.getLocation())
select ae, "CWE-416: Write through freed pointer '" + v.getName() + "'."
''',
    ),

    _ql(
        name="cwe-416-uaf-passed-to-function",
        query_id="local/cpp/cwe-416-pass",
        cwe="CWE-416",
        source='''\
/**
 * @name CWE-416: Use after free — freed pointer passed to function
 * @id local/cpp/cwe-416-pass
 * @kind problem
 * @severity error
 * @tags security external/cwe/cwe-416
 */
import cpp

from FunctionCall free_call, FunctionCall use_call, Variable v
where free_call.getTarget().hasName("free")
  and free_call.getArgument(0) = v.getAnAccess()
  and use_call.getAnArgument() = v.getAnAccess()
  and use_call != free_call
  and free_call.getEnclosingFunction() = use_call.getEnclosingFunction()
  and free_call.getLocation().isBefore(use_call.getLocation())
select use_call, "CWE-416: Freed pointer '" + v.getName() + "' passed as argument."
''',
    ),

    _ql(
        name="cwe-416-uaf-return",
        query_id="local/cpp/cwe-416-return",
        cwe="CWE-416",
        source='''\
/**
 * @name CWE-416: Use after free — freed pointer returned
 * @id local/cpp/cwe-416-return
 * @kind problem
 * @severity error
 * @tags security external/cwe/cwe-416
 */
import cpp

from FunctionCall free_call, ReturnStmt ret, Variable v
where free_call.getTarget().hasName("free")
  and free_call.getArgument(0) = v.getAnAccess()
  and ret.getExpr() = v.getAnAccess()
  and free_call.getEnclosingFunction() = ret.getEnclosingFunction()
  and free_call.getLocation().isBefore(ret.getLocation())
select ret, "CWE-416: Return of freed pointer '" + v.getName() + "'."
''',
    ),

    _ql(
        name="cwe-416-uaf-comparison",
        query_id="local/cpp/cwe-416-compare",
        cwe="CWE-416",
        source='''\
/**
 * @name CWE-416: Use after free — comparison of freed pointer
 * @id local/cpp/cwe-416-compare
 * @kind problem
 * @severity error
 * @tags security external/cwe/cwe-416
 */
import cpp

from FunctionCall free_call, ComparisonOperation cmp, Variable v
where free_call.getTarget().hasName("free")
  and free_call.getArgument(0) = v.getAnAccess()
  and cmp.getAnOperand() = v.getAnAccess()
  and free_call.getEnclosingFunction() = cmp.getEnclosingFunction()
  and free_call.getLocation().isBefore(cmp.getLocation())
select cmp, "CWE-416: Comparison of freed pointer '" + v.getName() + "'."
''',
    ),

    # ── Stale Pointer / Type Confusion (5) ────────────────────────────────

    _ql(
        name="cwe-416-stale-after-realloc",
        query_id="local/cpp/cwe-416-realloc",
        cwe="CWE-416",
        source='''\
/**
 * @name CWE-416: Stale pointer after realloc
 * @id local/cpp/cwe-416-realloc
 * @kind problem
 * @severity error
 * @tags security external/cwe/cwe-416
 */
import cpp

from FunctionCall realloc_call, Variable old_ptr, VariableAccess stale
where realloc_call.getTarget().getName().regexpMatch("(realloc|xrealloc|g_realloc)")
  and realloc_call.getArgument(0) = old_ptr.getAnAccess()
  and stale.getTarget() = old_ptr
  and realloc_call.getEnclosingFunction() = stale.getEnclosingFunction()
  and realloc_call.getLocation().isBefore(stale.getLocation())
  and not exists(AssignExpr reassign |
    reassign.getLValue() = old_ptr.getAnAccess()
    and realloc_call.getLocation().isBefore(reassign.getLocation())
    and reassign.getLocation().isBefore(stale.getLocation()))
select stale,
  "CWE-416: '" + old_ptr.getName() + "' may be stale — realloc() may have moved the allocation."
''',
    ),

    _ql(
        name="cwe-416-type-confusion-after-cast",
        query_id="local/cpp/cwe-416-type-confusion",
        cwe="CWE-416",
        source='''\
/**
 * @name CWE-416: Type confusion — cast of freed pointer
 * @id local/cpp/cwe-416-type-confusion
 * @kind problem
 * @severity error
 * @tags security external/cwe/cwe-416
 */
import cpp

from FunctionCall free_call, CStyleCast cast, Variable v
where free_call.getTarget().hasName("free")
  and free_call.getArgument(0) = v.getAnAccess()
  and cast.getExpr() = v.getAnAccess()
  and free_call.getEnclosingFunction() = cast.getEnclosingFunction()
  and free_call.getLocation().isBefore(cast.getLocation())
select cast,
  "CWE-416: Type confusion — C-style cast of freed pointer '" + v.getName() + "'."
''',
    ),

    _ql(
        name="cwe-125-read-of-freed-buffer",
        query_id="local/cpp/cwe-125-freed-read",
        cwe="CWE-125",
        source='''\
/**
 * @name CWE-125: Out-of-bounds read of freed heap buffer
 * @id local/cpp/cwe-125-freed-read
 * @kind problem
 * @severity error
 * @tags security external/cwe/cwe-125
 */
import cpp

from FunctionCall free_call, FunctionCall read_call, Variable v
where free_call.getTarget().hasName("free")
  and free_call.getArgument(0) = v.getAnAccess()
  and read_call.getTarget().getName().regexpMatch("(memcpy|memmove|memcmp|strcmp|strlen|strncmp)")
  and read_call.getAnArgument() = v.getAnAccess()
  and free_call.getEnclosingFunction() = read_call.getEnclosingFunction()
  and free_call.getLocation().isBefore(read_call.getLocation())
select read_call,
  "CWE-125: Memory read function called on freed buffer '" + v.getName() + "'."
''',
    ),

    _ql(
        name="cwe-416-container-dangling-pointer",
        query_id="local/cpp/cwe-416-container",
        cwe="CWE-416",
        source='''\
/**
 * @name CWE-416: Dangling pointer after container modification
 * @id local/cpp/cwe-416-container
 * @kind problem
 * @severity error
 * @tags security external/cwe/cwe-416
 */
import cpp

from FunctionCall modify_call, PointerDereferenceExpr pde, Variable v
where modify_call.getTarget().getName().regexpMatch(".*(erase|remove|clear|resize|push_back|pop_back|shrink).*")
  and pde.getOperand() = v.getAnAccess()
  and modify_call.getEnclosingFunction() = pde.getEnclosingFunction()
  and modify_call.getLocation().isBefore(pde.getLocation())
select pde,
  "CWE-416: Dereference of '" + v.getName() + "' may be dangling after container modification."
''',
    ),

    _ql(
        name="cwe-416-stale-function-pointer",
        query_id="local/cpp/cwe-416-func-ptr",
        cwe="CWE-416",
        source='''\
/**
 * @name CWE-416: Stale function pointer invocation after free
 * @id local/cpp/cwe-416-func-ptr
 * @kind problem
 * @severity error
 * @tags security external/cwe/cwe-416
 */
import cpp

from FunctionCall free_call, ExprCall ec, Variable v
where free_call.getTarget().hasName("free")
  and free_call.getArgument(0) = v.getAnAccess()
  and ec.getExpr() = v.getAnAccess()
  and free_call.getEnclosingFunction() = ec.getEnclosingFunction()
  and free_call.getLocation().isBefore(ec.getLocation())
select ec,
  "CWE-416: Function pointer '" + v.getName() + "' invoked after free() — possible stale vtable."
''',
    ),

    # ── Lifetime Mismatch (2) ──────────────────────────────────────────────

    _ql(
        name="cwe-416-562-stack-address-returned",
        query_id="local/cpp/cwe-416-stack-return",
        cwe="CWE-416",
        source='''\
/**
 * @name CWE-416/562: Return of stack-local address
 * @id local/cpp/cwe-416-stack-return
 * @kind problem
 * @severity error
 * @tags security external/cwe/cwe-416 external/cwe/cwe-562
 */
import cpp

from ReturnStmt ret, AddressOfExpr addr, LocalVariable lv
where ret.getExpr() = addr
  and addr.getOperand() = lv.getAnAccess()
  and not lv.isStatic()
select ret,
  "CWE-416/562: Return of address of stack-local variable '" + lv.getName() +
  "' — lifetime ends on function return."
''',
    ),

    _ql(
        name="cwe-416-stack-address-in-heap-field",
        query_id="local/cpp/cwe-416-stack-heap",
        cwe="CWE-416",
        source='''\
/**
 * @name CWE-416: Stack-local address stored in heap-allocated struct field
 * @id local/cpp/cwe-416-stack-heap
 * @kind problem
 * @severity error
 * @tags security external/cwe/cwe-416
 */
import cpp

from AssignExpr ae, AddressOfExpr addr, LocalVariable lv, FieldAccess fa
where ae.getRValue() = addr
  and addr.getOperand() = lv.getAnAccess()
  and not lv.isStatic()
  and ae.getLValue() = fa
select ae,
  "CWE-416: Address of stack-local '" + lv.getName() +
  "' stored in struct field '" + fa.getTarget().getName() + "' — lifetime mismatch."
''',
    ),
]


# ---------------------------------------------------------------------------
# CodeQLQuerySuite
# ---------------------------------------------------------------------------

class CodeQLQuerySuite:
    """Container for all 34 Phase-1 CodeQL queries.

    Manages both embedded custom queries and references to standard library
    queries, and provides helpers to materialise them for use with
    :class:`~codeql.wrapper.CodeQLRunner`.

    Attributes:
        custom_queries: The 21 embedded custom query definitions.
        standard_queries: The 13 standard library query references.
    """

    def __init__(self) -> None:
        self.custom_queries: list[CustomQuery] = list(CUSTOM_QUERIES)
        self.standard_queries: list[StandardQuery] = list(STANDARD_QUERIES)

    # ------------------------------------------------------------------
    # Custom query file materialisation
    # ------------------------------------------------------------------

    def write_custom_queries(self, output_dir: Path) -> list[Path]:
        """Write all 21 custom .ql sources to *output_dir* and return their paths.

        Args:
            output_dir: Directory to write query files into.
                Created if it does not exist.

        Returns:
            List of :class:`~pathlib.Path` objects for the written .ql files,
            in the same order as :attr:`custom_queries`.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # qlpack.yml declares the codeql/cpp-all dependency so `import cpp` resolves.
        qlpack = output_dir / "qlpack.yml"
        qlpack.write_text(
            "name: sailor/custom-queries\nversion: 0.0.1\ndependencies:\n  codeql/cpp-all: \"*\"\n",
            encoding="utf-8",
        )

        paths: list[Path] = []
        for q in self.custom_queries:
            out = output_dir / f"{q.query_id.replace('/', '_')}.ql"
            out.write_text(q.source, encoding="utf-8")
            paths.append(out)
            logger.debug("Wrote custom query %s → %s", q.query_id, out)

        logger.info("Wrote %d custom .ql files to %s.", len(paths), output_dir)
        return paths

    # ------------------------------------------------------------------
    # Standard query path resolution
    # ------------------------------------------------------------------

    def resolve_standard_queries(self, codeql_home: Path) -> list[Path]:
        """Resolve standard query paths against *codeql_home*.

        Skips any query file that does not exist under *codeql_home* and
        logs a warning so the caller can proceed with partial results.

        Args:
            codeql_home: Root directory of the CodeQL installation (contains
                the ``ql/`` subdirectory).

        Returns:
            List of absolute :class:`~pathlib.Path` objects for all standard
            query files that exist on disk.
        """
        codeql_home = Path(codeql_home)
        paths: list[Path] = []
        for q in self.standard_queries:
            full = codeql_home / q.rel_path
            if full.is_file():
                paths.append(full)
                logger.debug("Resolved standard query %s → %s", q.cwe, full)
            else:
                logger.warning(
                    "Standard query not found (skipping): %s — "
                    "check codeql_home=%s",
                    q.rel_path,
                    codeql_home,
                )
        logger.info(
            "Resolved %d / %d standard queries.",
            len(paths),
            len(self.standard_queries),
        )
        return paths

    def all_query_paths(
        self,
        custom_dir: Path,
        codeql_home: Path | None = None,
    ) -> list[Path]:
        """Return all query paths — custom (written to *custom_dir*) and standard.

        Args:
            custom_dir: Directory to write custom .ql files.
            codeql_home: Optional CodeQL installation root.  Standard queries
                are skipped when this is ``None``.

        Returns:
            Combined list: custom query paths first, then standard query paths.
        """
        paths = self.write_custom_queries(custom_dir)
        if codeql_home is not None:
            paths += self.resolve_standard_queries(codeql_home)
        return paths
