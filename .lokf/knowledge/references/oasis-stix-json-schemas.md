---
type: Reference
id: https://w3id.org/lmodel/stix/knowledge/references/oasis-stix-json-schemas
title: OASIS STIX 2.1 JSON schemas
description: oasis-open/cti-stix2-json-schemas, the repository where OASIS publishes JSON schemas and examples for STIX 2.1 under the BSD-3-Clause licence, with no releases; `upstream/` copies it at a pinned commit.
genre: reference
resource: https://github.com/oasis-open/cti-stix2-json-schemas
sources:
  - id: notice
    resource: NOTICE
    title: the section on OASIS's JSON schemas and examples
  - id: check_upstream_release.py
    resource: scripts/check_upstream_release.py
    title: the pins
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# OASIS STIX 2.1 JSON schemas

oasis-open/cti-stix2-json-schemas holds JSON schemas for every STIX 2.1 object, with example bundles, under the BSD-3-Clause licence.[^notice] It publishes no releases, so `upstream/` copies its `schemas/`, `examples/` and `LICENSE` at commit `9af1db41b7b86c06324f899649ae83480134f66e` of `master`.[^check_upstream_release.py]

Some descriptions in the schema come from these JSON schemas under that licence. Where the JSON schemas and the OASIS Standard disagree, the schema follows the standard, and `tests/test_upstream.py` lists each difference.

[^notice]: NOTICE, the section on OASIS's JSON schemas and examples
[^check_upstream_release.py]: scripts/check_upstream_release.py, the pins
