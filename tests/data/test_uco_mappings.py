"""Unit tests for UCO mappings declared in the STIX LinkML schema."""

from pathlib import Path


SCHEMA_PATH = Path(__file__).resolve().parents[2] / "src" / "stix" / "schema" / "stix.yaml"


def _schema_text() -> str:
    return SCHEMA_PATH.read_text(encoding="utf-8")


def test_uco_prefix_declared() -> None:
    """The preferred UCO prefix should be present in schema prefixes."""
    text = _schema_text()
    assert "unified_cyber_ontology: 'https://w3id.org/lmodel/uco-master/'" in text


def test_name_mapping_is_exact() -> None:
    """STIX name should keep an exact mapping to UCO name."""
    text = _schema_text()
    assert "  name:\n    description: Human-readable name." in text
    assert "exact_mappings:\n      - unified_cyber_ontology:name" in text


def test_description_mapping_is_not_exact() -> None:
    """STIX description should not claim exact equivalence with UCO description."""
    text = _schema_text()
    assert "  description:\n    description: Human-readable description." in text
    assert "close_mappings:\n      - unified_cyber_ontology:description" in text
    assert "exact_mappings:\n      - unified_cyber_ontology:description" not in text


def test_external_id_not_mapped_to_uco_name() -> None:
    """Identifier slots should not be mapped to UCO name."""
    text = _schema_text()
    assert "  external_id:\n    description: An identifier for the external reference content." in text
    assert "external_id:\n    description: An identifier for the external reference content.\n    range: string\n    related_mappings:\n      - unified_cyber_ontology:name" not in text


def test_source_name_uses_close_mapping() -> None:
    """source_name should keep a weaker close mapping to UCO name."""
    text = _schema_text()
    assert "  source_name:\n    description: Name of the external source." in text
    assert "source_name:\n    description: Name of the external source.\n    range: string\n    close_mappings:\n      - unified_cyber_ontology:name" in text
    assert "source_name:\n    description: Name of the external source.\n    range: string\n    narrow_mappings:\n      - unified_cyber_ontology:name" not in text
