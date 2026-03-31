"""Coverage tests based on a local copy of upstream STIX JSON examples."""

import json
from pathlib import Path

import pytest

import stix.datamodel.stix as model


EXAMPLES_DIR = Path(__file__).parent / "upstream_examples"
EXAMPLE_PATHS = sorted(EXAMPLES_DIR.rglob("*.json"))


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _class_name_for_type(stix_type: str) -> str:
    return "".join(part.capitalize() for part in stix_type.split("-"))


def _class_for_type(stix_type: str):
    return getattr(model, _class_name_for_type(stix_type))


def _iter_example_objects() -> list[tuple[Path, dict]]:
    cases = []
    for path in EXAMPLE_PATHS:
        payload = _load_json(path)
        if payload.get("type") == "bundle":
            for obj in payload["objects"]:
                cases.append((path, obj))
        else:
            cases.append((path, payload))
    return cases


ALL_OBJECT_CASES = _iter_example_objects()


def _case_id(case: tuple[Path, dict]) -> str:
    path, payload = case
    return f"{path.relative_to(EXAMPLES_DIR)}::{payload['type']}::{payload['id']}"


def test_upstream_example_discovery_includes_nested_directories() -> None:
    assert EXAMPLE_PATHS
    assert any(path.parent.name == "threat-reports" for path in EXAMPLE_PATHS)


@pytest.mark.parametrize("path", EXAMPLE_PATHS, ids=lambda path: str(path.relative_to(EXAMPLES_DIR)))
def test_upstream_examples_have_expected_root_shape(path: Path) -> None:
    payload = _load_json(path)
    assert "type" in payload
    assert "id" in payload
    if payload["type"] == "bundle":
        assert isinstance(payload.get("objects"), list)
        assert payload["objects"]


@pytest.mark.parametrize("case", ALL_OBJECT_CASES, ids=_case_id)
def test_local_upstream_example_objects_instantiate(case: tuple[Path, dict]) -> None:
    _, payload = case
    target_class = _class_for_type(payload["type"])
    obj = target_class(**payload)
    assert obj
    assert obj.type == payload["type"]
    assert obj.id == payload["id"]