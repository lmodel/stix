---
type: Dataset
id: https://w3id.org/lmodel/stix/knowledge/datasets/neighbour-adapt-copies
title: Neighbours' adapt copies
description: "The released adapt copies of nine lmodel schemas under `tests/neighbours/`, each checked against its release's checksum and attestation, against which `tests/test_schema_rules.py` holds `.lokf/stix.yaml` apart: no shared class, enum or type, and only the listed shared keys."
genre: reference
resource: tests/neighbours
sources:
  - id: test_schema_rules.py
    resource: tests/test_schema_rules.py
    title: the pins and the shared-key lists
  - resource: tests/neighbours
    title: the nine copies
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# Neighbours' adapt copies

`tests/neighbours/` holds the schema assets of nine lmodel releases: slsa v0.8.0, github-actions v0.3.0, oscal v0.1.2, spdx v0.1.0, nist-sp-800-218 v0.1.1, nist-sp-800-53 v0.1.0, nist-sp-800-171 v0.1.0, nist-csf-v2 v0.1.0 and in-toto v0.1.1.[^test_schema_rules.py] Each was checked against its release's `.sha256` and its build-provenance attestation, and the test pins its SHA-256 digest.

The test checks that the adapt copy shares no class, enum or type name with LOKF's `lokf.yaml` or with any neighbour. It also checks that the copy shares only the listed keys with each neighbour, such as `subject` and `value`, which STIX's property names bring, so that a new overlap fails. [Element names and shared keys](../explanations/element-names-and-shared-keys.md) says why.

[^test_schema_rules.py]: tests/test_schema_rules.py, the pins and the shared-key lists
