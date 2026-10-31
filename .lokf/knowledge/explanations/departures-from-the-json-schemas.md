---
type: Explanation
id: https://w3id.org/lmodel/stix/knowledge/explanations/departures-from-the-json-schemas
title: Departures from OASIS's JSON schemas
description: "Where the schema follows the OASIS Standard rather than OASIS's JSON schemas: the IPv6 pattern's lost escapes, the at-least-one rules that name absent properties, and four vocabularies; and the rules no generated validator checks."
genre: explanation
resource: docs/about.md
about:
  - https://w3id.org/lmodel/stix/knowledge/datasets/stix-linkml-schema
relatedTo:
  - https://w3id.org/lmodel/stix/knowledge/datasets/oasis-json-schemas-copy
sources:
  - id: test_upstream.py
    resource: tests/test_upstream.py
    title: the departure lists
  - id: about.md
    resource: docs/about.md
    title: the Vocabularies and departures sections
  - resource: docs/index.md
    title: the What no generated validator checks section
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# Departures from OASIS's JSON schemas

The schema follows the OASIS Standard where OASIS's JSON schemas say otherwise, and `tests/test_upstream.py` lists each difference.[^test_upstream.py]

- The JSON schema's IPv6 pattern lost its backslashes, so it rejects an IPv4-mapped address such as `::ffff:192.0.2.128`. The schema's pattern restores them.
- The JSON schemas' "at least one property" rules name properties the objects do not have: `name`, `created` and `arguments` for a process, `modified` for a registry key and `image_compression_algorithm` for a raster image. The schema leaves them out, and names `modified_time` for a registry key.
- The account types, regions, report types and infrastructure types follow the standard's tables.[^about.md]

Some rules of the JSON schemas cannot be stated in a form LinkML's generators carry. Examples are a malware family's name and the keys of a dictionary. `docs/index.md` lists them, and the tests check the three boolean rules over the examples.

[^test_upstream.py]: tests/test_upstream.py, the departure lists
[^about.md]: docs/about.md, the Vocabularies and departures sections
