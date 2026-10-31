"""Data tests: every example against the JSON Schema the validator generates."""

import json
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


# Three rules of the JSON schemas turn on a boolean, which no LinkML generator
# carries (docs/index.md). These checks hold the examples to them.


def objects(data):
    """A STIX object, or each object of a bundle, and the objects embedded in
    observed data."""
    for item in data.get("objects", [data]) if data.get("type") == "bundle" else [data]:
        yield item
        if item.get("type") == "observed-data":
            yield from item.get("objects", {}).values()


def boolean_rule_problems(item):
    problems = []
    if (
        item.get("type") == "malware"
        and item.get("is_family") is True
        and "name" not in item
    ):
        problems.append("a malware family has a name")
    if item.get("type") == "email-message":
        if item.get("is_multipart") is True and "body" in item:
            problems.append("a multipart email has no body")
        if item.get("is_multipart") is False and "body_multipart" in item:
            problems.append("an email that is not multipart has no body_multipart")
    if (
        item.get("type") == "network-traffic"
        and item.get("is_active") is True
        and "end" in item
    ):
        problems.append("active network traffic has no end")
    return problems


@pytest.mark.parametrize("path", VALID, ids=lambda p: p.stem)
def test_valid_examples_keep_the_boolean_rules(path):
    data = yaml.safe_load(path.read_text())
    assert not [p for item in objects(data) for p in boolean_rule_problems(item)]


def test_boolean_rule_check_finds_each_breach():
    assert boolean_rule_problems({"type": "malware", "is_family": True})
    assert boolean_rule_problems(
        {"type": "email-message", "is_multipart": True, "body": "x"}
    )
    assert boolean_rule_problems(
        {"type": "email-message", "is_multipart": False, "body_multipart": [{}]}
    )
    assert boolean_rule_problems(
        {"type": "network-traffic", "is_active": True, "end": "x"}
    )
