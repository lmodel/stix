---
type: Explanation
id: https://w3id.org/lmodel/stix/knowledge/explanations/element-names-and-shared-keys
title: Element names and shared keys
description: Why every class and enum carries the `Stix` prefix while STIX's property names stay as keys, how the adapt copy renames the keys LOKF defines, and which keys it still shares with released lmodel copies, such as `subject` and `value`.
genre: explanation
resource: tests/test_schema_rules.py
about:
  - https://w3id.org/lmodel/stix/knowledge/datasets/stix-linkml-schema
relatedTo:
  - https://w3id.org/lmodel/stix/knowledge/datasets/neighbour-adapt-copies
sources:
  - id: readme.md
    resource: README.md
    title: the Knowledge Trust Ladder (KTL) section
  - id: test_schema_rules.py
    resource: tests/test_schema_rules.py
    title: the shared-key lists
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# Element names and shared keys

A host imports `.lokf/stix.yaml` beside LOKF's `lokf.yaml` and other adapt copies, and LinkML merges them into one namespace, where the last definition of a name wins. So every class and enum carries the `Stix` prefix, and none shares a name with LOKF's or a released neighbour's.[^readme.md]

STIX's property names are its JSON keys, so they stay, each a top-level slot with a `stix:` slot URI. `lokf adapt` renames each key LOKF also defines with the `stix_` prefix, such as `stix_type` and `stix_name`, and keeps its IRI. Other keys stay shared, and each projects under one copy's IRI in a composite:

- in-toto and slsa: `content`, `subject` and `value`;
- spdx: `comment`, `key`, `statement`, `subject`, `summary` and `value`;
- oscal: eighteen keys, among them `hashes`, `pattern`, `statement`, `subject` and `value`.

`tests/test_schema_rules.py` pins these lists, so a new overlap fails.[^test_schema_rules.py] lokf issue #169 asks `adapt` for a `--beside` option that would rename them too.

[^readme.md]: README.md, the Knowledge Trust Ladder (KTL) section
[^test_schema_rules.py]: tests/test_schema_rules.py, the shared-key lists
