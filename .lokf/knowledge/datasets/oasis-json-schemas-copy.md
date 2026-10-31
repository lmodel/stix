---
type: Dataset
id: https://w3id.org/lmodel/stix/knowledge/datasets/oasis-json-schemas-copy
title: Copy of OASIS's STIX 2.1 JSON schemas
description: The copy under `upstream/` of OASIS's STIX 2.1 JSON schemas, examples and licence, taken from oasis-open/cti-stix2-json-schemas at commit `9af1db4` and checked file by file against pinned git object hashes. Tests hold the schema to it.
genre: reference
resource: upstream
derivedFrom:
  - https://w3id.org/lmodel/stix/knowledge/references/oasis-stix-json-schemas
sources:
  - id: check_upstream_release.py
    resource: scripts/check_upstream_release.py
    title: the pins
  - id: notice
    resource: NOTICE
    title: the section on OASIS's JSON schemas and examples
  - id: test_upstream.py
    resource: tests/test_upstream.py
    title: the tests and their departure lists
  - resource: upstream
    title: the copied files
  - resource: tests/test_generated_json_schema.py
    title: the examples it validates
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# Copy of OASIS's STIX 2.1 JSON schemas

`upstream/` holds the `schemas/` and `examples/` folders and the `LICENSE` of oasis-open/cti-stix2-json-schemas at commit `9af1db41b7b86c06324f899649ae83480134f66e`, 67 files in all.[^check_upstream_release.py] That repository publishes no releases, so the copy is pinned to a commit of its `master` branch, and the watch script pins each file's git object hash. The files are under OASIS's BSD-3-Clause licence, which `NOTICE` carries.[^notice]

The tests use the copy in three ways:

- `tests/test_upstream.py` checks that each object schema's properties are slots of the matching class, that the required lists match, and that each closed enumeration matches. It also validates OASIS's eight example files unchanged.[^test_upstream.py]
- `tests/test_generated_json_schema.py` validates five of the examples against the JSON Schema that `gen-project` writes.
- The watch reports when `master` changes, adds or drops a copied file, or changes the licence.

[^check_upstream_release.py]: scripts/check_upstream_release.py, the pins
[^notice]: NOTICE, the section on OASIS's JSON schemas and examples
[^test_upstream.py]: tests/test_upstream.py, the tests and their departure lists
