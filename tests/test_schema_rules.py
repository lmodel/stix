"""Checks that the adapt copy can sit beside LOKF and the neighbours' copies."""

import hashlib
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent

# What a host may import beside this schema's adapt copy: LOKF's schema, pinned
# by the sidecar, and the adapt copies other lmodel repositories release. Each
# neighbour is the schema asset of a release, downloaded and checked against
# the release's .sha256 and its build-provenance attestation, and pinned here
# by that checksum.
COPY = ROOT / ".lokf" / "stix.yaml"
LOKF = ROOT / ".lokf" / "lokf.yaml"
NEIGHBOURS = {
    # lmodel/slsa v0.8.0, schema-v0.8.0-slsa.yaml
    "slsa.yaml": "16a3c50a4592dbeffeeee0e9d3d354efe71ae3efcc8eb272ed9b782117d8a024",
    # lmodel/github-actions v0.3.0, schema-v0.3.0-github-actions.yaml
    "github-actions.yaml": "52224e53939325f56d3470ed6ddd2041cdd53ae7cdb0ac72773829100798452e",
    # lmodel/oscal v0.1.2, schema-v0.1.2-oscal.yaml
    "oscal.yaml": "4eb56d7d1106463ed0a2255a29af14b8d619741acc29863d1e86eb3f8923c710",
    # lmodel/spdx v0.1.0, schema-v0.1.0-spdx.yaml
    "spdx.yaml": "3411cf5d19b1955f0362988c542984e4c817417c7b7b7892647aba1adf1ddd4a",
    # lmodel/nist-sp-800-218 v0.1.1, schema-v0.1.1-nist-sp-800-218.yaml
    "nist-sp-800-218.yaml": "479824cdd95e52226a35ff3a471b7ce93239635ccd5db7ac72a8143cdd1d8495",
    # lmodel/nist-sp-800-53 v0.1.0, schema-v0.1.0-nist-sp-800-53.yaml
    "nist-sp-800-53.yaml": "d32a989b5b855281cb45d707bf59cf52b125f05a09c54930e2b4d45c174c0d99",
    # lmodel/nist-sp-800-171 v0.1.0, schema-v0.1.0-nist-sp-800-171.yaml
    "nist-sp-800-171.yaml": "d204efa6653692da665f8604a8fb8bf445f04b37f41460a5ce2853a014b2982f",
    # lmodel/nist-csf-v2 v0.1.0, schema-v0.1.0-nist-csf-v2.yaml
    "nist-csf-v2.yaml": "5f6bba4c4721f65665c3a0a702ca6b15df5b488048fed454acfe4cc69f7ca9c7",
    # lmodel/in-toto v0.1.1, schema-v0.1.1-in-toto.yaml
    "in-toto.yaml": "feb2711d782643dfeb670648508540f29393c437aaceae5318849f62e8e14c6d",
}
NEIGHBOUR_DIR = ROOT / "tests" / "neighbours"
ELEMENT_KINDS = ("classes", "enums", "types", "subsets")

# Keys the copy shares with a neighbour. LinkML keeps one namespace, and the
# JSON-LD context gives each key one IRI across a composite, whether it is a
# slot or an attribute on either side, so a shared key projects under one
# vocabulary's IRI. STIX's property names are its JSON keys and stay, and
# lokf adapt renames only the keys LOKF defines, so these are listed; a new
# overlap fails the test. lokf issue #169 asks adapt for a --beside option
# that would rename a neighbour's keys too. No class is shared: every class
# and enum carries the Stix prefix.
SHARED_WITH_NEIGHBOURS = {name: set() for name in NEIGHBOURS}
SHARED_WITH_NEIGHBOURS["in-toto.yaml"] = {"content", "subject", "value"}
SHARED_WITH_NEIGHBOURS["slsa.yaml"] = {"content", "subject", "value"}
SHARED_WITH_NEIGHBOURS["spdx.yaml"] = {
    "comment",
    "key",
    "statement",
    "subject",
    "summary",
    "value",
}
SHARED_WITH_NEIGHBOURS["oscal.yaml"] = {
    "capabilities",
    "city",
    "country",
    "date",
    "end",
    "groups",
    "hashes",
    "number",
    "pattern",
    "postal_code",
    "protocols",
    "published",
    "roles",
    "start",
    "statement",
    "subject",
    "value",
    "values",
}

# The classes `just lokf-adapt` re-roots on Concept: StixObject, so that every
# STIX object type is a concept type, and the bundle. project.justfile says
# why the domain objects alone cannot be the roots.
ROOTS = {"StixObject", "StixBundle"}

MAPPING_KEYS = (
    "mappings",
    "exact_mappings",
    "close_mappings",
    "related_mappings",
    "narrow_mappings",
    "broad_mappings",
)


def _load(path):
    return yaml.safe_load(path.read_text())


def _expander(doc):
    """A function that expands a CURIE by the prefixes a schema file binds."""
    prefixes = doc.get("prefixes") or {}

    def expand(curie):
        prefix, _, local = curie.partition(":")
        return prefixes[prefix] + local if prefix in prefixes else curie

    return expand


def _names(path):
    """Each kind of element a schema file declares, and every slot and
    attribute name with the IRI it expands to."""
    doc = _load(path)
    expand = _expander(doc)
    default = doc.get("default_prefix")
    elements = {kind: set(doc.get(kind) or {}) for kind in ELEMENT_KINDS}
    slots = {}
    owners = [doc.get("slots") or {}]
    owners += [
        (cls or {}).get("attributes") or {}
        for cls in (doc.get("classes") or {}).values()
    ]
    for owner in owners:
        for name, slot in owner.items():
            uri = (slot or {}).get("slot_uri") or f"{default}:{name}"
            # The key a document and the JSON-LD context use is the alias.
            slots.setdefault((slot or {}).get("alias") or name, set()).add(expand(uri))
    return elements, slots


def _terms(doc):
    """The IRI of every class, slot, attribute, enum and type a schema file
    declares, each its own URI or the default prefix and its name."""
    expand = _expander(doc)
    default = doc.get("default_prefix")
    terms = set()
    for kind, uri_key in (
        ("classes", "class_uri"),
        ("slots", "slot_uri"),
        ("enums", "enum_uri"),
        ("types", "uri"),
    ):
        for name, element in (doc.get(kind) or {}).items():
            terms.add(expand((element or {}).get(uri_key) or f"{default}:{name}"))
    for cls in (doc.get("classes") or {}).values():
        for name, slot in ((cls or {}).get("attributes") or {}).items():
            terms.add(expand((slot or {}).get("slot_uri") or f"{default}:{name}"))
    return terms


def _mappings(node):
    """Every mapping value anywhere in a parsed schema file."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in MAPPING_KEYS:
                yield from value if isinstance(value, list) else [value]
            else:
                yield from _mappings(value)
    elif isinstance(node, list):
        for item in node:
            yield from _mappings(item)


def test_neighbours_are_the_released_assets():
    """Each neighbour copy is byte for byte the asset its release published."""
    assert {p.name for p in NEIGHBOUR_DIR.iterdir()} == set(NEIGHBOURS)
    for name, sha256 in NEIGHBOURS.items():
        digest = hashlib.sha256((NEIGHBOUR_DIR / name).read_bytes()).hexdigest()
        assert digest == sha256, name


def test_names_apart_from_lokf():
    """No class, enum, type or subset name of the copy is LOKF's, and a slot
    name the two share carries LOKF's IRI."""
    elements, slots = _names(COPY)
    their_elements, their_slots = _names(LOKF)
    for kind in ELEMENT_KINDS:
        assert not elements[kind] & their_elements[kind], kind
    for name in slots.keys() & their_slots.keys():
        assert slots[name] == their_slots[name], name


def test_names_apart_from_neighbours():
    """A class, enum, type or subset name is the copy's alone, and the only
    keys it shares with a neighbour are the listed ones."""
    elements, slots = _names(COPY)
    for name in NEIGHBOURS:
        their_elements, their_slots = _names(NEIGHBOUR_DIR / name)
        for kind in ELEMENT_KINDS:
            assert not elements[kind] & their_elements[kind], (name, kind)
        assert slots.keys() & their_slots.keys() == SHARED_WITH_NEIGHBOURS[name], name


def test_copy_roots_the_concept_classes():
    """The copy re-roots exactly the two root classes on Concept and imports
    nothing but the LinkML types and LOKF."""
    doc = _load(COPY)
    rooted = {
        name for name, cls in doc["classes"].items() if cls.get("is_a") == "Concept"
    }
    assert rooted == ROOTS
    assert doc["imports"] == ["linkml:types", "lokf"]


def test_mappings_use_a_bound_prefix():
    """Every mapping in the copy is a CURIE whose prefix the copy binds. A full
    address that no prefix covers makes every `lokf convert --schema` over the
    copy warn that it has no namespace."""
    doc = _load(COPY)
    prefixes = doc.get("prefixes") or {}
    mappings = list(_mappings(doc))
    assert mappings
    for mapping in mappings:
        prefix, sep, _ = mapping.partition(":")
        assert sep and prefix in prefixes, mapping


def test_mappings_into_a_neighbour_name_one_of_its_terms():
    """A mapping into a released neighbour's namespace names a class, slot,
    enum or type that the neighbour's copy declares, so a renamed or dropped
    term fails here rather than in a host's graph. The schema maps to UCO
    alone today (tests/test_mappings.py), so no mapping is checked here."""
    doc = _load(COPY)
    expand = _expander(doc)
    namespaces = {}
    for name in NEIGHBOURS:
        theirs = _load(NEIGHBOUR_DIR / name)
        default = theirs.get("default_prefix")
        namespace = (theirs.get("prefixes") or {}).get(default)
        if namespace:
            namespaces[namespace] = (name, _terms(theirs))
    checked = set()
    for mapping in _mappings(doc):
        iri = expand(mapping)
        for namespace, (name, terms) in namespaces.items():
            if iri.startswith(namespace):
                assert iri in terms, (mapping, name)
                checked.add(name)
    assert checked == set()
