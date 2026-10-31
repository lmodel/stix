"""Every mapping names a term that exists, by a CURIE whose prefix the schema binds."""

import hashlib
from pathlib import Path

import pytest
from linkml_runtime import SchemaView

ROOT = Path(__file__).parent.parent
SCHEMA = ROOT / "src" / "stix" / "schema" / "stix.yaml"
UCO_TERMS = Path(__file__).parent / "uco" / "uco-1.5.0-terms.txt"
# scripts/extract_uco_terms.py writes the list from UCO 1.5.0's own files,
# each checked against its git object hash; this pins what it wrote.
UCO_TERMS_SHA256 = "55f43064fde9c76c9bf87f56b0536d80ebacd5ed078ab017e475d765233e7c82"
UCO = "https://ontology.unifiedcyberontology.org/uco/"
MAPPING_KINDS = (
    "exact_mappings",
    "close_mappings",
    "broad_mappings",
    "narrow_mappings",
    "related_mappings",
)


def mappings():
    """Each mapping of each class, slot, enum and type, with the element it is on."""
    view = SchemaView(str(SCHEMA))
    elements = list(view.all_classes().values()) + list(view.all_slots().values())
    elements += list(view.all_enums().values()) + list(view.all_types().values())
    found = []
    for element in elements:
        if not str(element.from_schema).startswith("https://w3id.org/lmodel/stix"):
            continue  # linkml:types brings mappings of its own
        for kind in MAPPING_KINDS:
            for curie in getattr(element, kind) or []:
                found.append((element.name, kind, str(curie)))
    return view, found


VIEW, MAPPINGS = mappings()


def test_the_term_list_is_the_pinned_one():
    assert hashlib.sha256(UCO_TERMS.read_bytes()).hexdigest() == UCO_TERMS_SHA256


def test_there_are_mappings():
    assert len(MAPPINGS) > 40


@pytest.mark.parametrize("mapping", MAPPINGS, ids=lambda m: f"{m[0]}-{m[2]}")
def test_mapping_prefix_is_bound(mapping):
    element, kind, curie = mapping
    prefix, _, _ = curie.partition(":")
    assert prefix in VIEW.namespaces(), (
        f"{element} {kind} {curie}: the schema does not bind {prefix}"
    )


@pytest.mark.parametrize("mapping", MAPPINGS, ids=lambda m: f"{m[0]}-{m[2]}")
def test_mapping_names_a_uco_term(mapping):
    """The schema maps to UCO alone, and each term exists in UCO 1.5.0."""
    element, kind, curie = mapping
    iri = VIEW.expand_curie(curie)
    assert iri.startswith(UCO), (
        f"{element} {kind} {curie}: only UCO terms are checked here"
    )
    assert iri in set(UCO_TERMS.read_text().split()), (
        f"{element} {kind} {curie} is not a UCO 1.5.0 term"
    )
