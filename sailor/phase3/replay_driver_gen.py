"""Phase 3 — Replay Driver Generator.

Transforms the KLEE symbolic driver produced by Phase 2 into a concrete
replay driver by substituting witness values from a .ktest file.
"""

from __future__ import annotations

import logging
import re
import struct
from pathlib import Path

from sailor.models.schemas import WitnessInput, WitnessValue

logger = logging.getLogger("sailor.phase3.replay_driver_gen")

_KTEST_MAGIC = b"KTEST"

_KLEE_MAKE_SYMBOLIC_PAT = re.compile(
    r"klee_make_symbolic\s*\("
    r"([^,]+),"          # group 1: ptr expression
    r"\s*([^,]+),"       # group 2: size expression
    r'\s*"([^"]+)"\s*'   # group 3: symbolic variable name
    r"\)\s*;",
    re.DOTALL,
)


class ReplayDriverGenerator:
    """Transform a Phase 2 symbolic driver into a concrete replay driver.

    Args:
        witness: The :class:`WitnessInput` produced by Phase 2.
        output_dir: Directory where ``replay_driver.c`` will be written.
        project_preamble: Optional C source preamble (e.g. project includes)
            prepended to the replay driver. When set, any inline struct
            typedefs matching ``project_struct_names`` are removed so the
            project headers take precedence.
        project_struct_names: Names of typedef'd structs defined in the
            project preamble that should be stripped from the inline driver.
    """

    def __init__(
        self,
        witness: WitnessInput,
        output_dir: Path,
        project_preamble: str = "",
        project_struct_names: list[str] | None = None,
    ) -> None:
        self.witness = witness
        self.output_dir = output_dir
        self.project_preamble = project_preamble
        self.project_struct_names: list[str] = project_struct_names or []

    def generate(self) -> Path:
        """Transform the symbolic driver into a concrete replay driver.

        Loads the driver source from the witness harness, parses the first
        .ktest file to extract witness values, then applies all four
        transformations before writing the result to disk.

        Returns:
            Path to the generated ``replay_driver.c``.

        Raises:
            ValueError: If no .ktest files are present in the witness.
            FileNotFoundError: If the .ktest file path does not exist.
        """
        if not self.witness.ktest_paths:
            raise ValueError(
                f"WitnessInput {self.witness.spec_id!r} has no .ktest paths."
            )

        ktest_path = self.witness.ktest_paths[0]
        logger.info("Parsing ktest: %s", ktest_path)
        witness_values = self._parse_ktest(ktest_path)
        logger.debug(
            "Parsed %d witness values from %s", len(witness_values), ktest_path
        )

        source = self.witness.harness.driver_c
        source = self._add_ktest_include(source)
        source = self._replace_klee_make_symbolic(source, witness_values)
        source = self._remove_klee_assume(source)
        source = self._remove_klee_assert(source)
        source = self._remove_klee_warning(source)

        if self.project_preamble:
            source = self._inject_project_preamble(source)

        out_path = self.output_dir / "replay_driver.c"
        out_path.write_text(source, encoding="utf-8")
        logger.info("Wrote replay driver → %s", out_path)
        return out_path

    def _parse_ktest(self, ktest_path: str) -> list[WitnessValue]:
        """Parse a .ktest binary file produced by KLEE.

        Reads the KTEST binary format: magic header, version, args section,
        and a variable-length list of named symbolic objects.

        Args:
            ktest_path: Absolute path to the .ktest file.

        Returns:
            List of :class:`WitnessValue` objects, one per symbolic variable.

        Raises:
            ValueError: If the file does not begin with the KTEST magic bytes.
        """
        with open(ktest_path, "rb") as fh:
            magic = fh.read(5)
            if magic != _KTEST_MAGIC:
                raise ValueError(
                    f"Not a valid .ktest file (bad magic {magic!r}): {ktest_path}"
                )

            version = struct.unpack(">I", fh.read(4))[0]

            num_args = struct.unpack(">I", fh.read(4))[0]
            for _ in range(num_args):
                arg_len = struct.unpack(">I", fh.read(4))[0]
                fh.read(arg_len)

            if version >= 2:
                fh.read(4)  # symArgvs
                fh.read(4)  # symArgvLen

            num_objects = struct.unpack(">I", fh.read(4))[0]
            values: list[WitnessValue] = []
            for _ in range(num_objects):
                name_len = struct.unpack(">I", fh.read(4))[0]
                name = fh.read(name_len).decode("utf-8", errors="replace")

                data_len = struct.unpack(">I", fh.read(4))[0]
                data = fh.read(data_len)

                data_hex = data.hex()
                if data_len <= 8:
                    padded = data + b"\x00" * (8 - len(data))
                    data_interpreted: int | str = struct.unpack("<Q", padded)[0]
                else:
                    data_interpreted = data_hex

                values.append(
                    WitnessValue(
                        name=name,
                        size_bytes=data_len,
                        data_hex=data_hex,
                        data_interpreted=data_interpreted,
                    )
                )

        return values

    def _replace_klee_make_symbolic(
        self, source: str, witness_values: list[WitnessValue]
    ) -> str:
        """Replace each klee_make_symbolic call with a memcpy of witness bytes.

        Looks up each symbolic variable by name in *witness_values* and emits
        a ``memcpy`` call containing the concrete bytes as a C string literal.
        Calls whose name is not found in the witness are replaced with a
        comment to preserve the source structure.

        Args:
            source: C source text of the driver.
            witness_values: Concrete witness values parsed from the .ktest file.

        Returns:
            Transformed source text.
        """
        witness_map = {wv.name: wv for wv in witness_values}

        def _replace(m: re.Match) -> str:  # type: ignore[type-arg]
            ptr = m.group(1).strip()
            size = m.group(2).strip()
            name = m.group(3)

            wv = witness_map.get(name)
            if wv is None:
                logger.warning(
                    "No witness value for symbolic variable %r — leaving as comment.",
                    name,
                )
                return (
                    f"/* klee_make_symbolic({ptr}, {size}, \"{name}\")"
                    " — no witness value */"
                )

            data = bytes.fromhex(wv.data_hex)
            c_str = "".join(f"\\x{b:02x}" for b in data)
            return f'memcpy({ptr}, "{c_str}", {size});'

        return _KLEE_MAKE_SYMBOLIC_PAT.sub(_replace, source)

    def _remove_klee_assume(self, source: str) -> str:
        """Remove all klee_assume(...); statements.

        Args:
            source: C source text.

        Returns:
            Source text with all klee_assume calls removed.
        """
        return re.sub(
            r"klee_assume\s*\([^;]+\)\s*;", "", source, flags=re.DOTALL
        )

    def _remove_klee_assert(self, source: str) -> str:
        """Remove all klee_assert(...); statements.

        Args:
            source: C source text.

        Returns:
            Source text with all klee_assert calls removed.
        """
        return re.sub(
            r"klee_assert\s*\([^;]+\)\s*;", "", source, flags=re.DOTALL
        )

    def _remove_klee_warning(self, source: str) -> str:
        """Remove all klee_warning_once(...); statements.

        Args:
            source: C source text.

        Returns:
            Source text with all klee_warning_once calls removed.
        """
        return re.sub(
            r"klee_warning_once\s*\([^;]+\)\s*;", "", source, flags=re.DOTALL
        )

    def _inject_project_preamble(self, source: str) -> str:
        """Prepend the project preamble and strip conflicting inline struct defs.

        When a project preamble is provided (e.g. including the real project
        headers), inline ``typedef struct Name { ... } Name;`` blocks for names
        listed in ``project_struct_names`` are removed so the project-provided
        definitions take precedence.

        Args:
            source: C source text after ktest/klee transforms.

        Returns:
            Source text with preamble prepended and conflicting structs removed.
        """
        for name in self.project_struct_names:
            # Match: typedef struct [optional_tag] { ... (possibly nested) } name;
            pattern = (
                r"typedef\s+struct\s*(?:\w+\s*)?\{"
                r"(?:[^{}]|\{[^{}]*\})*"   # body, allow one level of nesting
                r"\}\s*"
                + re.escape(name)
                + r"\s*;"
            )
            source = re.sub(pattern, "", source, flags=re.DOTALL)

        return self.project_preamble + "\n" + source

    def _add_ktest_include(self, source: str) -> str:
        """Swap KLEE includes for standard C includes required by the replay driver.

        Removes ``#include <klee/klee.h>`` and inserts ``#include <string.h>``
        and ``#include <stdlib.h>`` at the top of the file so that ``memcpy``
        and related symbols are available.

        Args:
            source: C source text.

        Returns:
            Source text with updated include directives.
        """
        source = re.sub(r'#\s*include\s*[<"]klee/klee\.h[">]\s*\n?', "", source)

        replay_includes = "#include <string.h>\n#include <stdlib.h>\n"
        if "#include" in source:
            first_include = source.index("#include")
            source = source[:first_include] + replay_includes + source[first_include:]
        else:
            source = replay_includes + source

        return source
