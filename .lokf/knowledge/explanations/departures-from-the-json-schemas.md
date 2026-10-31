---
type: Explanation
id: https://w3id.org/lmodel/stix/knowledge/explanations/departures-from-the-json-schemas
title: Departures from OASIS's JSON schemas
description: "Where the schema follows the OASIS Standard rather than OASIS's JSON schemas: the IPv6 pattern's lost escapes, the at-least-one rules, granular markings, a marking definition's created, the targets of three references, and four vocabularies; and the rules no generated validator checks."
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
  at: "2026-10-31T11:15:06Z"
status: draft
---

# Departures from OASIS's JSON schemas

The schema follows the OASIS Standard where OASIS's JSON schemas say otherwise, and `tests/test_upstream.py` lists each difference in the properties, the required lists and the at-least-one rules.[^test_upstream.py]

- The JSON schema's IPv6 pattern lost its backslashes, so it rejects an IPv4-mapped address such as `::ffff:192.0.2.128`. The schema's pattern restores them.
- The JSON schemas' "at least one property" rules name properties the objects do not have: `name`, `created` and `arguments` for a process, `modified` for a registry key and `image_compression_algorithm` for a raster image. The schema leaves them out, names `modified_time` for a registry key, and adds a process's `created_time` and the Windows process extension's `integrity_level`, which the JSON schemas leave out.
- A granular marking names exactly one of `marking_ref` and `lang`. The JSON schema requires `marking_ref`, which rejects a language marking.
- A marking definition's `created` is precise to the millisecond, like every other object's. The JSON schema takes any precision there.
- A sighting's `sighting_of_ref` points at a domain object, and a malware analysis's `analysis_sco_refs` and a file's `contains_refs` at observables. The JSON schemas take a wider set of identifiers.
- The account types, regions, report types and infrastructure types follow the standard's tables.[^about.md]

Some rules of STIX cannot be stated in a form LinkML's generators carry. Examples are a malware family's name and the keys of a dictionary. `docs/index.md` lists them, and the tests check each of them over the examples.

[^test_upstream.py]: tests/test_upstream.py, the departure lists
[^about.md]: docs/about.md, the Vocabularies and departures sections
