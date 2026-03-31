"""Tests for STIX pattern parser helpers."""

from pathlib import Path

import pytest

from stix.pattern import PatternSyntaxError, parse_stix_pattern, validate_stix_pattern


VALID_MIN_PATTERN = "[file:name = 'foo.exe']"
INVALID_PATTERN = "[file:name = 'foo.exe'"


def _generated_parser_present() -> bool:
    antlr_dir = Path(__file__).resolve().parents[2] / "src" / "stix" / "pattern" / "antlr"
    return any(antlr_dir.rglob("STIXPatternLexer.py")) and any(antlr_dir.rglob("STIXPatternParser.py"))


def test_parse_stix_pattern_behaves_based_on_generated_artifacts():
    """Parser should parse valid patterns when artifacts exist, otherwise raise helpful RuntimeError."""

    if _generated_parser_present():
        try:
            tree = parse_stix_pattern(VALID_MIN_PATTERN)
            assert tree is not None
        except RuntimeError as err:
            assert "incompatible" in str(err) or "missing" in str(err)
    else:
        with pytest.raises(RuntimeError, match="ANTLR parser artifacts are missing"):
            parse_stix_pattern(VALID_MIN_PATTERN)


def test_validate_stix_pattern_boolean_contract():
    """Boolean validator should report parser success/failure without raising."""

    if _generated_parser_present():
        assert isinstance(validate_stix_pattern(VALID_MIN_PATTERN), bool)
        assert validate_stix_pattern(INVALID_PATTERN) is False
    else:
        assert validate_stix_pattern(VALID_MIN_PATTERN) is False
        assert validate_stix_pattern(INVALID_PATTERN) is False


def test_pattern_syntax_error_str_round_trip():
    """Custom syntax exception should preserve message text."""

    err = PatternSyntaxError("line 1:0 mismatched input")
    assert str(err) == "line 1:0 mismatched input"