---
type: Explanation
id: https://w3id.org/lmodel/stix/knowledge/explanations/closed-classes-and-custom-content
title: Closed classes and custom content
description: Why the schema's classes are closed, so that STIX's custom properties and custom objects validate only once a schema that imports this one declares them, as lmodel/attack does for MITRE's `x_mitre_` properties.
genre: explanation
resource: src/stix/schema/stix.yaml
about:
  - https://w3id.org/lmodel/stix/knowledge/datasets/stix-linkml-schema
sources:
  - id: schema-stix.yaml
    resource: src/stix/schema/stix.yaml
    title: the comments on closed classes and dictionaries
  - resource: docs/index.md
    title: the Custom properties and objects section
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# Closed classes and custom content

STIX allows custom properties, conventionally prefixed `x_`, and custom objects. The schema's classes are closed: an object validates only with the properties its class declares.[^schema-stix.yaml] So a misspelled key fails. A custom property fails too, until a schema that imports this one declares it, as a slot of a subclass or as a class of its own. lmodel/attack does this for MITRE's `x_mitre_` properties and `x-mitre-` objects.

The classes are not opened with LinkML's `extra_slots`, for two reasons the header's comments give: it would accept every misspelled key along with the custom ones, and LinkML 1.12.1's Pydantic generator ignores it. The schema uses `extra_slots` only for STIX's dictionaries, such as hashes and extensions, whose keys contain hyphens and so cannot be slots. [Validate STIX data](../playbooks/validate-stix-data.md) says how to check a file.

[^schema-stix.yaml]: src/stix/schema/stix.yaml, the comments on closed classes and dictionaries
