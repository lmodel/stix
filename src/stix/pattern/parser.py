"""ANTLR-backed parser helpers for STIX pattern expressions."""
# https://github.com/antlr/website-antlr4/blob/gh-pages/download/antlr-4.9.3-complete.jar

from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from typing import Any

from antlr4 import CommonTokenStream, InputStream
from antlr4.error.ErrorListener import ErrorListener


@dataclass(frozen=True)
class PatternSyntaxError(ValueError):
    """Raised when a STIX pattern is syntactically invalid."""

    message: str

    def __str__(self) -> str:
        return self.message


class _RaisingErrorListener(ErrorListener):
    """Converts ANTLR syntax callbacks into Python exceptions."""

    def syntaxError(self, recognizer, offendingSymbol, line, column, msg, e):  # type: ignore[override]
        raise PatternSyntaxError(f"line {line}:{column} {msg}")


def _load_generated_parser_modules() -> tuple[Any, Any]:
    """Load generated STIXPattern lexer/parser modules.

    The generated modules are expected at:
    - stix.pattern.antlr.STIXPatternLexer
    - stix.pattern.antlr.STIXPatternParser
    """

    try:
        lexer_module = import_module("stix.pattern.antlr.STIXPatternLexer")
        parser_module = import_module("stix.pattern.antlr.STIXPatternParser")
    except ModuleNotFoundError:
        antlr_pkg_dir = Path(__file__).parent / "antlr"
        lexer_path = next(antlr_pkg_dir.rglob("STIXPatternLexer.py"), None)
        parser_path = next(antlr_pkg_dir.rglob("STIXPatternParser.py"), None)
        if not lexer_path or not parser_path:  # pragma: no cover - depends on local setup
            raise RuntimeError(
                "ANTLR parser artifacts are missing. Generate them from "
                "https://github.com/oasis-open/cti-stix2-json-schemas/blob/master/pattern_grammar/STIXPattern.g4 "
                "into src/stix/pattern/antlr/."
            )

        lexer_spec = spec_from_file_location("stix_pattern_lexer", lexer_path)
        parser_spec = spec_from_file_location("stix_pattern_parser", parser_path)
        if lexer_spec is None or parser_spec is None or lexer_spec.loader is None or parser_spec.loader is None:
            raise RuntimeError("Failed to load generated STIX parser modules from file paths.")

        lexer_module = module_from_spec(lexer_spec)
        parser_module = module_from_spec(parser_spec)
        lexer_spec.loader.exec_module(lexer_module)
        parser_spec.loader.exec_module(parser_module)
    # Importing generated ANTLR modules can fail at import-time when the jar
    # version used for generation does not match the runtime package version.
    except Exception as exc:  # pragma: no cover - depends on local runtime/generator versions
        raise RuntimeError(
            "Generated STIX ANTLR parser is incompatible with the installed "
            "antlr4-python3-runtime version. Use a matching ANTLR jar/runtime "
            "pair (this project's LinkML stack currently expects 4.9.x runtime)."
        ) from exc

    return lexer_module, parser_module


def parse_stix_pattern(pattern: str):
    """Parse a STIX pattern and return the ANTLR parse tree.

    Raises:
        PatternSyntaxError: If the pattern is syntactically invalid.
        RuntimeError: If generated parser artifacts are not present.
    """

    lexer_module, parser_module = _load_generated_parser_modules()
    lexer_cls = getattr(lexer_module, "STIXPatternLexer")
    parser_cls = getattr(parser_module, "STIXPatternParser")

    listener = _RaisingErrorListener()
    try:
        lexer = lexer_cls(InputStream(pattern))
        lexer.removeErrorListeners()
        lexer.addErrorListener(listener)

        parser = parser_cls(CommonTokenStream(lexer))
        parser.removeErrorListeners()
        parser.addErrorListener(listener)

        return parser.pattern()
    except TypeError as exc:  # pragma: no cover - depends on local runtime/generator versions
        raise RuntimeError(
            "Generated STIX ANTLR parser is incompatible with the installed "
            "antlr4-python3-runtime version. Use a matching ANTLR jar/runtime "
            "pair (this project's LinkML stack currently expects 4.9.x runtime)."
        ) from exc


def validate_stix_pattern(pattern: str) -> bool:
    """Return True if a STIX pattern parses successfully, else False."""

    try:
        parse_stix_pattern(pattern)
    except (PatternSyntaxError, RuntimeError):
        return False
    return True
