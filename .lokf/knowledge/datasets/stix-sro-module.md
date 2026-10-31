---
type: Dataset
id: https://w3id.org/lmodel/stix/knowledge/datasets/stix-sro-module
title: stix_sro module
description: "The module `src/stix/schema/stix_sro.yaml`: the two STIX relationship objects, `StixRelationship` and `StixSighting`, and the slots that join other objects, such as `source_ref`, `target_ref` and `sighting_of_ref`."
genre: reference
resource: src/stix/schema/stix_sro.yaml
isPartOf:
  - https://w3id.org/lmodel/stix/knowledge/datasets/stix-linkml-schema
sources:
  - id: stix_sro.yaml
    resource: src/stix/schema/stix_sro.yaml
    title: the classes and the slots
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# stix_sro module

`src/stix/schema/stix_sro.yaml` imports `linkml:types`, `stix_core` and `stix_sdo`, and holds 2 classes and 10 slots.[^stix_sro.yaml]

- `StixRelationship` requires `relationship_type`, `source_ref` and `target_ref`. Its two references accept any object identifier except those of relationships, sightings, bundles, marking definitions and language content, so a custom object's identifier passes.
- `StixSighting` requires `sighting_of_ref`, and points at observed data in `observed_data_refs` and at identities or locations in `where_sighted_refs`.

[^stix_sro.yaml]: src/stix/schema/stix_sro.yaml, the classes and the slots
