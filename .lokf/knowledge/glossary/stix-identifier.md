---
type: GlossaryTerm
id: https://w3id.org/lmodel/stix/knowledge/glossary/stix-identifier
title: STIX identifier
description: In STIX, every object's `id` is its type name, two hyphens and a UUID, such as `indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f`. The schema types it as `stix_identifier`, and each class narrows it to its own type prefix.
genre: reference
definition: "The identifier of a STIX object: its type name, two hyphens and a UUID."
definedBy:
  - https://w3id.org/lmodel/stix/knowledge/references/stix-2-1-specification
relatedTo:
  - https://w3id.org/lmodel/stix/knowledge/datasets/stix-core-module
resource: src/stix/schema/stix_core.yaml
sources:
  - id: stix_core.yaml
    resource: src/stix/schema/stix_core.yaml
    title: the type stix_identifier and the slot id
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# STIX identifier

A STIX identifier names one object: its type name, two hyphens and a UUID, such as `indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f`. The schema types `id` as `stix_identifier`, and each class narrows the pattern to its own prefix, so an attack pattern's `id` must start with `attack-pattern--`.[^stix_core.yaml] A reference slot such as `created_by_ref` carries the pattern of the class it points at.

[^stix_core.yaml]: src/stix/schema/stix_core.yaml, the type stix_identifier and the slot id
