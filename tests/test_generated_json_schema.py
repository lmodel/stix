"""The JSON Schema that gen-project writes accepts what the tests accept.

The other tests build their JSON Schema as linkml-validate does. gen-project
builds project/jsonschema/stix.schema.json from the settings in
.linkml/generators.yaml instead, so a setting there could make the generated
file reject what the tests accept, as it once did for every bundle. These
tests build the file from those settings, and check the committed file
itself, which the w3id rules serve from main.
"""

import copy
import json
from functools import cache
from pathlib import Path

import jsonschema
import pytest
import yaml
from linkml.generators.jsonschemagen import JsonSchemaGenerator

ROOT = Path(__file__).parent.parent
SCHEMA = ROOT / "src" / "stix" / "schema" / "stix.yaml"
CONFIG = ROOT / ".linkml" / "generators.yaml"
GENERATED = ROOT / "project" / "jsonschema" / "stix.schema.json"
EXAMPLES = ROOT / "upstream" / "examples"
CHOSEN = [
    EXAMPLES / "threat-reports" / "apt1.json",
    EXAMPLES / "threat-reports" / "poisonivy.json",
    EXAMPLES / "infrastructure.json",
    EXAMPLES / "indicator-to-campaign-relationship.json",
    EXAMPLES / "interop-objectmarking-test.json",
]


@cache
def from_settings():
    """The JSON Schema as gen-project writes it, from its own settings."""
    settings = yaml.safe_load(CONFIG.read_text())["generator_args"]["jsonschema"]
    return json.loads(JsonSchemaGenerator(str(SCHEMA), **settings).serialize())


def schemas():
    return [
        ("the generator's settings", from_settings()),
        (str(GENERATED.relative_to(ROOT)), json.loads(GENERATED.read_text())),
    ]


def errors(schema, data):
    """Validate a bundle against the schema's root, StixBundle, and a single
    object against the class its type names."""
    if data["type"] != "bundle":
        name = "Stix" + "".join(part.capitalize() for part in data["type"].split("-"))
        schema = {"$ref": f"#/$defs/{name}", "$defs": schema["$defs"]}
    return [
        e.message[:200]
        for e in jsonschema.validators.validator_for(schema)(schema).iter_errors(data)
    ]


@pytest.mark.parametrize("path", CHOSEN, ids=lambda p: p.name)
def test_oasis_examples_validate_against_the_generated_schema(path):
    data = json.loads(path.read_text())
    for label, schema in schemas():
        assert not errors(schema, data), label


def test_a_broken_bundle_fails_against_the_generated_schema():
    """An object of a bundle that breaks its class fails the whole bundle, so
    the test above is not passing for want of a check."""
    data = json.loads(CHOSEN[0].read_text())
    broken = copy.deepcopy(data)
    del broken["objects"][0]["created"]
    for label, schema in schemas():
        assert errors(schema, broken), label
