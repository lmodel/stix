"""Data tests: every example against the JSON Schema the validator generates."""

import json
import re
from collections import deque
from functools import cache
from pathlib import Path

import jsonschema
import pytest
import yaml
from linkml.generators.jsonschemagen import JsonSchemaGenerator
from linkml.validator import validate
from linkml_runtime import SchemaView

ROOT = Path(__file__).parent.parent
SCHEMA = ROOT / "src" / "stix" / "schema" / "stix.yaml"
DATA = Path(__file__).parent / "data"
VALID = sorted((DATA / "valid").glob("*.yaml"))
INVALID = sorted((DATA / "invalid").glob("*.yaml"))


@cache
def definitions():
    """The class definitions of the JSON Schema that linkml-validate generates:
    closed classes, and every concrete descendant wherever a class is a range.
    Generating it once keeps the run short; test_validator_agrees checks that
    linkml-validate gives the same answers."""
    generator = JsonSchemaGenerator(
        str(SCHEMA),
        mergeimports=True,
        top_class="StixBundle",
        include_range_class_descendants=True,
    )
    return json.loads(generator.serialize())["$defs"]


def errors(instance, class_name):
    schema = {"$ref": f"#/$defs/{class_name}", "$defs": definitions()}
    return list(jsonschema.Draft202012Validator(schema).iter_errors(instance))


def pointer(error):
    return "/" + "/".join(str(part) for part in error.absolute_path)


def class_of(path):
    return path.stem.split("-")[0]


def places(error):
    """Where an error points: its own place, or, for an anyOf or oneOf that no
    branch met, the places inside each branch that could have been meant. An
    optional object's branches are the object and null, so its error points
    inside the object; a branch for another null or another STIX type, which
    the object's `type` rules out, is left aside."""
    if error.validator not in ("anyOf", "oneOf") or not error.context:
        return {pointer(error)}
    branches = {}
    for sub in error.context:
        branches.setdefault(sub.relative_schema_path[0], []).append(sub)
    found = set()
    for subs in branches.values():
        if any(s.validator == "type" and s.validator_value == "null" for s in subs):
            continue
        if any(
            s.validator == "const" and s.relative_path == deque(["type"]) for s in subs
        ):
            continue
        for sub in subs:
            found |= places(sub)
    return found or {pointer(error)}


def test_the_example_folders_hold_examples():
    """The parametrized tests below pass on an empty folder, so this one does not."""
    assert len(VALID) >= 60 and len(INVALID) >= 150, (len(VALID), len(INVALID))


@pytest.mark.parametrize("path", VALID, ids=lambda p: p.stem)
def test_valid_examples_validate(path):
    """Every valid example passes."""
    found = errors(yaml.safe_load(path.read_text()), class_of(path))
    assert not found, [f"{pointer(e)}: {e.message}" for e in found]


@pytest.mark.parametrize("path", INVALID, ids=lambda p: p.stem)
def test_counter_examples_fail_where_they_say(path):
    """Every counter-example fails at the place its first line names, as
    `# Fails at: <JSON pointer>`, and nowhere else but on the way to it, so a
    file that starts failing for another reason fails this test."""
    first = path.read_text().splitlines()[0]
    assert first.startswith("# Fails at: "), (
        f"{path.name}: the first line names where it fails"
    )
    where = first.removeprefix("# Fails at: ").strip()
    found = errors(yaml.safe_load(path.read_text()), class_of(path))
    reached = set().union(*(places(e) for e in found))
    report = [f"{pointer(e)}: {e.message[:200]}" for e in found]
    assert where in reached, (sorted(reached), report)
    on_the_way = {
        p for p in reached if where == p or where.startswith(p.rstrip("/") + "/")
    }
    assert reached == on_the_way, (sorted(reached - on_the_way), report)


def test_validator_agrees():
    """linkml-validate, which docs/index.md tells a user to run, accepts a valid
    example and rejects a counter-example at the same place."""
    good = DATA / "valid" / "StixIndicator-c2-ip.yaml"
    assert not validate(
        yaml.safe_load(good.read_text()), str(SCHEMA), "StixIndicator"
    ).results
    bad = DATA / "invalid" / "StixAttackPattern-id-of-another-type.yaml"
    report = validate(yaml.safe_load(bad.read_text()), str(SCHEMA), "StixAttackPattern")
    assert any(r.message.endswith(" in /id") for r in report.results), [
        r.message for r in report.results
    ]


def test_every_concept_class_has_an_example():
    """The adapt copy roots StixObject and StixBundle on LOKF's Concept, so each
    concrete class under them is a concept type and has a valid example."""
    view = SchemaView(str(SCHEMA))
    concept_types = {
        name
        for name in view.class_descendants("StixObject") + ["StixBundle"]
        if not view.get_class(name).abstract
    }
    examples = {class_of(path) for path in VALID}
    assert concept_types <= examples, sorted(concept_types - examples)


# The rules STIX states that no generated validator checks: some turn on a
# boolean or compare two properties, which LinkML cannot state, and some are
# beyond what its generators carry (docs/index.md lists them). These checks
# hold the valid examples to them here, and OASIS's examples in
# tests/test_upstream.py.


def objects(data):
    """A STIX object, or each object of a bundle, and the objects embedded in
    observed data."""
    for item in data.get("objects", [data]) if data.get("type") == "bundle" else [data]:
        yield item
        if item.get("type") == "observed-data":
            yield from item.get("objects", {}).values()


# Each pair of timestamps that STIX orders within one object: the types it
# applies to (None for any type with both), the earlier and the later, and
# whether the later must be strictly after the earlier.
TIME_ORDER = (
    (None, "created", "modified", False),
    (
        {"campaign", "infrastructure", "intrusion-set", "malware", "sighting"}
        | {"threat-actor"},
        "first_seen",
        "last_seen",
        False,
    ),
    ({"observed-data"}, "first_observed", "last_observed", False),
    ({"indicator"}, "valid_from", "valid_until", True),
    ({"relationship"}, "start_time", "stop_time", True),
    ({"network-traffic"}, "start", "end", False),
)
TIMESTAMP = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z")
# The forms OASIS's hashes-type.json gives the hashes STIX names. Any other
# key names a custom algorithm.
HASH_FORMS = {
    "MD5": "[a-fA-F0-9]{32}",
    "SHA-1": "[a-fA-F0-9]{40}",
    "SHA-256": "[a-fA-F0-9]{64}",
    "SHA-512": "[a-fA-F0-9]{128}",
    "SHA3-256": "[a-fA-F0-9]{64}",
    "SHA3-512": "[a-fA-F0-9]{128}",
    "SSDEEP": "[a-zA-Z0-9/+:.]{1,128}",
    "TLSH": "[a-zA-Z0-9]{70}",
}
CUSTOM_HASH = "[a-zA-Z0-9_-]{3,250}"
UUID = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}"
EXTENSION_KEY = f"([a-z][a-z0-9]*)+(-[a-z0-9]+)*-ext|extension-definition--{UUID}"
CVE_OR_CAPEC = r"CVE-\d{4}-(0\d{3}|[1-9]\d{3,})|CAPEC-\d+"
# The four Traffic Light Protocol marking definitions that STIX 2.1 fixes
# (section 7.2.1.4), by level, all created at the same time.
TLP = {
    "white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}
TLP_CREATED = "2017-01-20T00:00:00.000Z"
# The JSON schemas give a domain name's value as an idn-hostname and an email
# address's value as an email; jsonschema checks both forms, the first with
# the idna package.
FORMATS = jsonschema.FormatChecker()


@cache
def predefined_extensions():
    """Each predefined extension's key, with the class that renders it."""
    view = SchemaView(str(SCHEMA))
    return {
        c.annotations["stix_extension_name"].value: c.name
        for c in view.all_classes().values()
        if "stix_extension_name" in c.annotations
    }


def instant(value):
    """A timestamp as a key that sorts in time: its whole seconds, then its
    fraction padded to a fixed width."""
    match = TIMESTAMP.fullmatch(str(value))
    return match and (match.group(1), (match.group(2) or "").ljust(12, "0"))


def mappings(node):
    """Every mapping within a value, the value itself included."""
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from mappings(value)
    elif isinstance(node, list):
        for value in node:
            yield from mappings(value)


def rule_problems(item):
    """Each rule of the list in docs/index.md that a STIX object breaks."""
    kind = item.get("type") or ""
    problems = []
    if kind == "malware" and item.get("is_family") is True and "name" not in item:
        problems.append("a malware family has a name")
    if kind == "email-message":
        if item.get("is_multipart") is True and "body" in item:
            problems.append("a multipart email has no body")
        if item.get("is_multipart") is False and "body_multipart" in item:
            problems.append("an email that is not multipart has no body_multipart")
    if kind == "network-traffic" and item.get("is_active") is True and "end" in item:
        problems.append("active network traffic has no end")
    for types, earlier, later, strictly in TIME_ORDER:
        if (types is None or kind in types) and earlier in item and later in item:
            first, last = instant(item[earlier]), instant(item[later])
            if first and last and (last < first or (strictly and last == first)):
                problems.append(f"{later} comes after {earlier}")
    if not 3 <= len(kind) <= 250:
        problems.append("a type name has 3 to 250 characters")
    if kind == "observed-data" and "object_refs" in item:
        if all(
            r.split("--")[0] in ("relationship", "sighting")
            for r in item["object_refs"]
        ):
            problems.append("observed data refers to at least one observable")
    for node in mappings(item):
        if not node:
            problems.append("a dictionary has at least one key")
        for key in ("hashes", "file_header_hashes"):
            for algorithm, value in (node.get(key) or {}).items():
                form = HASH_FORMS.get(algorithm)
                if form is None and not re.fullmatch(CUSTOM_HASH, algorithm):
                    problems.append(
                        f"a hash algorithm's name has its form: {algorithm}"
                    )
                elif form and not re.fullmatch(form, str(value)):
                    problems.append(f"a {algorithm} hash has its form")
        if "source_name" in node and node["source_name"] not in ("cve", "capec"):
            if re.fullmatch(CVE_OR_CAPEC, str(node.get("external_id", ""))):
                problems.append("only a cve or capec reference uses its identifiers")
    for key, value in (item.get("extensions") or {}).items():
        if not re.fullmatch(EXTENSION_KEY, key):
            problems.append(
                f"an extension's key is an -ext name or an identifier: {key}"
            )
        elif key in predefined_extensions() and errors(
            value, predefined_extensions()[key]
        ):
            problems.append(f"{key} holds a {predefined_extensions()[key]}")
    if kind == "extension-definition" and "extension_properties" in item:
        if "toplevel-property-extension" not in item.get("extension_types", []):
            problems.append("extension_properties needs a toplevel-property-extension")
    if kind == "marking-definition":
        definition = item.get("definition") or {}
        if item.get("definition_type") in ("statement", "tlp"):
            if item["definition_type"] not in definition:
                problems.append("a marking's definition matches its definition type")
        level = definition.get("tlp")
        if level and (
            item.get("id") != TLP.get(level)
            or item.get("name") != f"TLP:{level.upper()}"
            or item.get("created") != TLP_CREATED
        ):
            problems.append("a TLP marking definition is one of the four STIX fixes")
    if kind == "domain-name" and not FORMATS.conforms(
        item.get("value"), "idn-hostname"
    ):
        problems.append("a domain name is a host name")
    if kind == "email-addr" and not FORMATS.conforms(item.get("value"), "email"):
        problems.append("an email address has its form")
    if kind == "windows-registry-key" and "key" in item:
        if not item["key"].upper().startswith("HKEY_"):
            problems.append("a registry key names its hive in full")
    return problems


@pytest.mark.parametrize("path", VALID, ids=lambda p: p.stem)
def test_valid_examples_keep_the_rules_no_validator_checks(path):
    data = yaml.safe_load(path.read_text())
    assert not [p for item in objects(data) for p in rule_problems(item)]


GOOD_TLP = {
    "type": "marking-definition",
    "id": TLP["green"],
    "created": TLP_CREATED,
    "name": "TLP:GREEN",
    "definition_type": "tlp",
    "definition": {"tlp": "green"},
}
# Each breach the check must find, with a word of the problem it reports.
BREACHES = [
    ({"type": "malware", "is_family": True}, "malware family"),
    ({"type": "email-message", "is_multipart": True, "body": "x"}, "multipart"),
    (
        {
            "type": "email-message",
            "is_multipart": False,
            "body_multipart": [{"body": "x"}],
        },
        "not multipart",
    ),
    ({"type": "network-traffic", "is_active": True, "end": "x"}, "active"),
    (
        {
            "type": "indicator",
            "created": "2026-01-15T09:30:00.100Z",
            "modified": "2026-01-15T09:30:00.02Z",
        },
        "modified comes after created",
    ),
    (
        {
            "type": "campaign",
            "first_seen": "2026-01-15T09:30:01Z",
            "last_seen": "2026-01-15T09:30:00.999Z",
        },
        "last_seen",
    ),
    (
        {
            "type": "indicator",
            "valid_from": "2026-01-15T09:30:00Z",
            "valid_until": "2026-01-15T09:30:00.000Z",
        },
        "valid_until",
    ),
    (
        {
            "type": "relationship",
            "start_time": "2026-02-01T00:00:00Z",
            "stop_time": "2026-01-01T00:00:00Z",
        },
        "stop_time",
    ),
    (
        {
            "type": "observed-data",
            "first_observed": "2026-02-01T00:00:00Z",
            "last_observed": "2026-01-01T00:00:00Z",
        },
        "last_observed",
    ),
    (
        {
            "type": "network-traffic",
            "start": "2026-02-01T00:00:00Z",
            "end": "2026-01-01T00:00:00Z",
        },
        "end",
    ),
    ({"type": "x-" + "a" * 250}, "type name"),
    (
        {
            "type": "observed-data",
            "object_refs": ["relationship--" + "0" * 8 + "-0000-4000-8000-" + "0" * 12],
        },
        "observable",
    ),
    ({"type": "file", "environment_variables": {}}, "dictionary"),
    ({"type": "file", "hashes": {"SHA-256": "abc"}}, "SHA-256"),
    ({"type": "file", "hashes": {"md": "abc"}}, "algorithm"),
    (
        {
            "type": "tool",
            "external_references": [
                {"source_name": "acme", "external_id": "CVE-2021-44228"}
            ],
        },
        "cve or capec",
    ),
    ({"type": "file", "extensions": {"ntfs": {"sid": "S-1-5-18"}}}, "-ext"),
    (
        {"type": "file", "extensions": {"ntfs-ext": {"version": "1.7"}}},
        "ntfs-ext holds",
    ),
    (
        {
            "type": "extension-definition",
            "extension_types": ["new-sdo"],
            "extension_properties": ["x_acme"],
        },
        "extension_properties",
    ),
    (
        {
            "type": "marking-definition",
            "definition_type": "statement",
            "definition": {"tlp": "red"},
        },
        "definition type",
    ),
    ({**GOOD_TLP, "id": TLP["red"]}, "TLP"),
    ({**GOOD_TLP, "created": "2026-01-15T09:30:00.000Z"}, "TLP"),
    ({"type": "windows-registry-key", "key": "HKLM\\Software\\Run"}, "hive"),
    ({"type": "domain-name", "value": "glass..example"}, "host name"),
    ({"type": "email-addr", "value": "glass.example"}, "email address"),
]


@pytest.mark.parametrize("item,word", BREACHES, ids=lambda b: str(b)[:40])
def test_the_rule_check_finds_each_breach(item, word):
    assert any(word in p for p in rule_problems(item)), rule_problems(item)


def test_the_rule_check_passes_a_fixed_tlp_marking():
    assert not rule_problems(GOOD_TLP)
