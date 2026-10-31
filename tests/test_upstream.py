"""The schema held to OASIS's STIX 2.1 JSON schemas and examples in upstream/."""

import json
from functools import cache
from pathlib import Path

import jsonschema
import pytest
from linkml.generators.jsonschemagen import JsonSchemaGenerator
from linkml_runtime import SchemaView

ROOT = Path(__file__).parent.parent
SCHEMA = ROOT / "src" / "stix" / "schema" / "stix.yaml"
UPSTREAM = ROOT / "upstream"
SCHEMAS = UPSTREAM / "schemas"
EXAMPLES = sorted((UPSTREAM / "examples").rglob("*.json"))

SPECIAL_NAMES = {
    "ipv4-addr": "StixIpv4Address",
    "ipv6-addr": "StixIpv6Address",
    "mac-addr": "StixMacAddress",
    "email-addr": "StixEmailAddress",
    "x509-certificate": "StixX509Certificate",
    "url": "StixUrl",
}


def class_for(stix_type):
    return SPECIAL_NAMES.get(stix_type) or "Stix" + "".join(
        p.capitalize() for p in stix_type.split("-")
    )


@cache
def view():
    return SchemaView(str(SCHEMA))


@cache
def definitions():
    generator = JsonSchemaGenerator(
        str(SCHEMA),
        mergeimports=True,
        top_class="StixBundle",
        include_range_class_descendants=True,
    )
    return json.loads(generator.serialize())["$defs"]


# --------------------------------------------------------------------------
# OASIS's examples validate unchanged.

# An example that breaks the JSON schema it sits beside would go here, with
# the reason; none does at the pinned commit.
KNOWN_DEPARTURES: dict[str, str] = {}


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_oasis_examples_validate_unchanged(path):
    data = json.loads(path.read_text())
    class_name = "StixBundle" if data["type"] == "bundle" else class_for(data["type"])
    schema = {"$ref": f"#/$defs/{class_name}", "$defs": definitions()}
    found = [
        f"/{'/'.join(map(str, e.absolute_path))}: {e.message[:200]}"
        for e in jsonschema.Draft202012Validator(schema).iter_errors(data)
    ]
    if path.name in KNOWN_DEPARTURES:
        assert found, f"{path.name} now validates; drop it from KNOWN_DEPARTURES"
    else:
        assert not found, found


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_oasis_examples_keep_the_boolean_rules(path):
    from tests.test_data import boolean_rule_problems, objects

    data = json.loads(path.read_text())
    assert not [p for item in objects(data) for p in boolean_rule_problems(item)]


# --------------------------------------------------------------------------
# Each object schema's properties are slots of the matching class, the
# required lists match, and each closed enumeration matches.


def load(rel):
    return json.loads((SCHEMAS / rel).read_text())


def properties_and_required(node, base_dir):
    """The properties and required names an object schema states, following
    its allOf references into the common bases. A oneOf or anyOf branch
    contributes its properties, and a name is required when every branch of
    a oneOf requires it."""
    props, required = set(node.get("properties", {})), set(node.get("required", []))
    for part in node.get("allOf", []):
        if "$ref" in part and not part["$ref"].startswith("#"):
            target = (base_dir / part["$ref"]).resolve()
            p, r = properties_and_required(
                json.loads(target.read_text()), target.parent
            )
            props |= p
            required |= r
        else:
            p, r = properties_and_required(part, base_dir)
            props |= p
            required |= r
    for key in ("oneOf", "anyOf"):
        branches = [
            properties_and_required(part, base_dir)
            for part in node.get(key, [])
            if isinstance(part, dict) and "$ref" not in part
        ]
        for p, _ in branches:
            props |= p
        if key == "oneOf" and branches:
            required |= set.intersection(*(r for _, r in branches))
    return props, required


def object_schemas():
    """Each object schema with its class: the domain, relationship and
    observable objects, the meta objects, the bundle, the embedded types and
    the predefined extensions."""
    pairs = []
    for folder in ("sdos", "sros", "observables"):
        for path in sorted((SCHEMAS / folder).glob("*.json")):
            pairs.append(
                (
                    f"{folder}/{path.name}",
                    class_for(path.stem),
                    load(f"{folder}/{path.name}"),
                    path.parent,
                )
            )
    common = SCHEMAS / "common"
    for name, cls in [
        ("marking-definition", "StixMarkingDefinition"),
        ("language-content", "StixLanguageContent"),
        ("extension-definition", "StixExtensionDefinition"),
        ("bundle", "StixBundle"),
        ("kill-chain-phase", "StixKillChainPhase"),
        ("external-reference", "StixExternalReference"),
        ("granular-marking", "StixGranularMarking"),
    ]:
        pairs.append((f"common/{name}.json", cls, load(f"common/{name}.json"), common))
    observables = SCHEMAS / "observables"
    for file, dictionary, key, cls in [
        ("file", "file-extensions-dictionary", "ntfs-ext", "StixNtfsExtension"),
        (
            "file",
            "file-extensions-dictionary",
            "raster-image-ext",
            "StixRasterImageExtension",
        ),
        ("file", "file-extensions-dictionary", "pdf-ext", "StixPdfExtension"),
        ("file", "file-extensions-dictionary", "archive-ext", "StixArchiveExtension"),
        (
            "file",
            "file-extensions-dictionary",
            "windows-pebinary-ext",
            "StixWindowsPeBinaryExtension",
        ),
        (
            "network-traffic",
            "network-traffic-extensions-dictionary",
            "http-request-ext",
            "StixHttpRequestExtension",
        ),
        (
            "network-traffic",
            "network-traffic-extensions-dictionary",
            "icmp-ext",
            "StixIcmpExtension",
        ),
        (
            "network-traffic",
            "network-traffic-extensions-dictionary",
            "socket-ext",
            "StixSocketExtension",
        ),
        (
            "network-traffic",
            "network-traffic-extensions-dictionary",
            "tcp-ext",
            "StixTcpExtension",
        ),
        (
            "process",
            "process-extensions-dictionary",
            "windows-process-ext",
            "StixWindowsProcessExtension",
        ),
        (
            "process",
            "process-extensions-dictionary",
            "windows-service-ext",
            "StixWindowsServiceExtension",
        ),
        (
            "user-account",
            "user-account-extensions-dictionary",
            "unix-account-ext",
            "StixUnixAccountExtension",
        ),
    ]:
        node = load(f"observables/{file}.json")["definitions"][dictionary][
            "patternProperties"
        ][f"^{key}$"]
        pairs.append((f"observables/{file}.json#{key}", cls, node, observables))
    for file, definition, cls in [
        ("file", "windows-pe-section", "StixWindowsPeSection"),
        ("file", "windows-pe-optional-header-type", "StixWindowsPeOptionalHeader"),
        ("email-message", "mime-part-type", "StixMimePart"),
        (
            "windows-registry-key",
            "windows-registry-value-type",
            "StixWindowsRegistryValue",
        ),
        ("x509-certificate", "x509-v3-extensions-type", "StixX509V3Extensions"),
    ]:
        node = load(f"observables/{file}.json")["definitions"][definition]
        pairs.append((f"observables/{file}.json#{definition}", cls, node, observables))
    ntfs = load("observables/file.json")["definitions"]["file-extensions-dictionary"][
        "patternProperties"
    ]["^ntfs-ext$"]
    stream = ntfs["allOf"][0]["properties"]["alternate_data_streams"]["items"]
    pairs.append(
        (
            "observables/file.json#alternate-data-stream",
            "StixAlternateDataStream",
            stream,
            observables,
        )
    )
    return pairs


# Each element on one side only, with the reason.
PROPERTY_DEPARTURES: dict[tuple[str, str], str] = {}
REQUIRED_DEPARTURES: dict[tuple[str, str], str] = {
    (
        "StixGranularMarking",
        "marking_ref",
    ): "STIX 2.1 requires exactly one of marking_ref and lang (section 7.2.3)",
}


def slot_names(cls):
    """The JSON keys of a class: each slot's alias, or its name."""
    return {s.alias or s.name for s in view().class_induced_slots(cls)}


def required_names(cls):
    return {s.alias or s.name for s in view().class_induced_slots(cls) if s.required}


@pytest.mark.parametrize("item", object_schemas(), ids=lambda i: i[0])
def test_properties_are_slots_of_the_class(item):
    source, cls, node, base = item
    json_props, _ = properties_and_required(node, base)
    slots = slot_names(cls)
    only_json = {p for p in json_props - slots if (cls, p) not in PROPERTY_DEPARTURES}
    only_linkml = {s for s in slots - json_props if (cls, s) not in PROPERTY_DEPARTURES}
    assert not only_json and not only_linkml, (sorted(only_json), sorted(only_linkml))


@pytest.mark.parametrize("item", object_schemas(), ids=lambda i: i[0])
def test_required_lists_match(item):
    source, cls, node, base = item
    _, json_required = properties_and_required(node, base)
    required = required_names(cls)
    only_json = {
        p for p in json_required - required if (cls, p) not in REQUIRED_DEPARTURES
    }
    only_linkml = {
        s for s in required - json_required if (cls, s) not in REQUIRED_DEPARTURES
    }
    assert not only_json and not only_linkml, (sorted(only_json), sorted(only_linkml))


def test_departure_lists_hold_only_live_entries():
    """An entry that no longer differs is dropped, so the lists stay short."""
    pairs = {
        cls: properties_and_required(node, base)
        for _, cls, node, base in object_schemas()
    }
    for cls, prop in PROPERTY_DEPARTURES:
        props, _ = pairs[cls]
        assert (prop in props) != (prop in slot_names(cls)), (cls, prop)
    for cls, prop in REQUIRED_DEPARTURES:
        _, required = pairs[cls]
        assert (prop in required) != (prop in required_names(cls)), (cls, prop)


def closed_enumerations():
    """Each closed enumeration of the JSON schemas, with the enum that renders it."""
    file_defs = load("observables/artifact.json")["definitions"]
    process = load("observables/process.json")["definitions"]
    socket = load("observables/network-traffic.json")["definitions"][
        "network-traffic-extensions-dictionary"
    ]["patternProperties"]["^socket-ext$"]["properties"]
    service = load("observables/process.json")["definitions"][
        "process-extensions-dictionary"
    ]["patternProperties"]["^windows-service-ext$"]["properties"]
    registry = load("observables/windows-registry-key.json")["definitions"][
        "windows-registry-value-type"
    ]
    marking = load("common/marking-definition.json")["definitions"]
    return [
        (
            "StixSpecVersion",
            load("common/core.json")["properties"]["spec_version"]["enum"],
        ),
        ("StixEncryptionAlgorithm", file_defs["encryption-algorithm-enum"]["enum"]),
        (
            "StixExtensionType",
            load("common/extension-definition.json")["definitions"][
                "extension-type-enum"
            ]["enum"],
        ),
        ("StixNetworkSocketAddressFamily", socket["address_family"]["enum"]),
        ("StixNetworkSocketType", socket["socket_type"]["enum"]),
        (
            "StixAgreement",
            load("sdos/opinion.json")["allOf"][1]["properties"]["opinion"]["enum"],
        ),
        ("StixWindowsIntegrityLevel", process["windows-integrity-level-enum"]["enum"]),
        ("StixWindowsRegistryDatatype", registry["properties"]["data_type"]["enum"]),
        ("StixWindowsServiceStartType", service["start_type"]["enum"]),
        ("StixWindowsServiceType", service["service_type"]["enum"]),
        ("StixWindowsServiceStatus", service["service_status"]["enum"]),
        (
            "StixTlpLevel",
            [
                marking[f"tlp_{c}"]["properties"]["definition"]["properties"]["tlp"][
                    "enum"
                ][0]
                for c in ("white", "green", "amber", "red")
            ],
        ),
    ]


@pytest.mark.parametrize("item", closed_enumerations(), ids=lambda i: i[0])
def test_closed_enumerations_match(item):
    enum, values = item
    assert set(view().get_enum(enum).permissible_values) == set(values)


# The "at least one property" rules: the JSON schemas' anyOf of required names
# against each class's any_of. The JSON schemas also name properties that
# STIX 2.1 does not give the object, which the schema leaves out.
AT_LEAST_ONE_DEPARTURES = {
    ("StixProcess", "name"): "STIX 2.1 gives a process no name",
    (
        "StixProcess",
        "created",
    ): "the property is created_time, which the schema names instead",
    (
        "StixProcess",
        "created_time",
    ): "the JSON schema names created, which a process does not have",
    (
        "StixWindowsProcessExtension",
        "integrity_level",
    ): "STIX 2.1 counts every property of the extension; the JSON schema omits it",
    (
        "StixProcess",
        "arguments",
    ): "STIX 2.1 gives a process no arguments; command_line holds them",
    (
        "StixWindowsRegistryKey",
        "modified",
    ): "the property is modified_time, which the schema names instead",
    (
        "StixWindowsRegistryKey",
        "modified_time",
    ): "the JSON schema names modified, which a key does not have",
    (
        "StixRasterImageExtension",
        "image_compression_algorithm",
    ): "STIX 2.1 dropped it from the extension",
}


def json_at_least_one(node):
    """The names of a JSON schema's anyOf whose branches each require one name."""
    names = set()
    for part in [node] + [p for p in node.get("allOf", []) if "$ref" not in p]:
        branches = part.get("anyOf", [])
        if branches and all(
            set(b) == {"required"} and len(b["required"]) == 1 for b in branches
        ):
            names |= {b["required"][0] for b in branches}
    return names


def linkml_at_least_one(cls):
    names = set()
    for expression in view().get_class(cls).any_of:
        conditions = expression.slot_conditions
        if len(conditions) == 1:
            names |= set(conditions)
    return names


@pytest.mark.parametrize("item", object_schemas(), ids=lambda i: i[0])
def test_at_least_one_rules_match(item):
    source, cls, node, base = item
    json_names, names = json_at_least_one(node), linkml_at_least_one(cls)
    if not json_names or len(json_names) < 2:
        return
    only_json = {
        n for n in json_names - names if (cls, n) not in AT_LEAST_ONE_DEPARTURES
    }
    only_linkml = {
        n for n in names - json_names if (cls, n) not in AT_LEAST_ONE_DEPARTURES
    }
    assert not only_json and not only_linkml, (sorted(only_json), sorted(only_linkml))


def test_ipv6_pattern_restores_the_lost_escapes():
    """OASIS's IPv6 pattern lost its backslashes; the schema's is the same
    pattern with them restored, and accepts an IPv4-mapped address."""
    upstream = load("observables/ipv6-addr.json")["allOf"][1]["properties"]["value"][
        "pattern"
    ]
    restored = (
        upstream.replace("^s*", "^\\s*")
        .replace(")?s*(", ")?\\s*(")
        .replace("2[0-4]d", "2[0-4]\\d")
        .replace("1dd", "1\\d\\d")
        .replace("[1-9]?d", "[1-9]?\\d")
        .replace("(.(25", "(\\.(25")
    )
    ours = view().get_class("StixIpv6Address").slot_usage["value"].pattern
    assert ours == restored
    assert jsonschema.Draft202012Validator({"pattern": ours}).is_valid(
        "::ffff:192.0.2.128"
    )
    assert not jsonschema.Draft202012Validator({"pattern": upstream}).is_valid(
        "::ffff:192.0.2.128"
    )


# --------------------------------------------------------------------------
# The header, the watch's pins and the copy agree.


@cache
def watch():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "watch_pins", ROOT / "scripts" / "check_upstream_release.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_copy_matches_the_pinned_blobs():
    """Every copied file has the git object hash the watch pins, and nothing
    else is in upstream/."""
    pinned = watch().PINNED_BLOBS
    present = {
        p.relative_to(UPSTREAM).as_posix() for p in UPSTREAM.rglob("*") if p.is_file()
    }
    assert present == set(pinned)
    for path, sha in pinned.items():
        assert watch().blob_sha(UPSTREAM / path) == sha, path


def test_header_pins_match_the_watch():
    """The header records the edition, its address and the commit the watch checks."""
    import yaml

    header = yaml.safe_load(SCHEMA.read_text())
    assert header["version"] == watch().PINNED_EDITION
    assert header["source"] == watch().PINNED_SOURCE
    assert header["annotations"]["json_schemas_commit"] == watch().PINNED_COMMIT
    tree = f"https://github.com/oasis-open/cti-stix2-json-schemas/tree/{watch().PINNED_COMMIT}"
    assert tree in header["see_also"]
