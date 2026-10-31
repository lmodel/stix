---
type: Playbook
id: https://w3id.org/lmodel/stix/knowledge/playbooks/validate-stix-data
title: Validate STIX data
description: How to validate a STIX bundle or object with `linkml-validate` (`-C StixBundle`, or the object's class), or with `project/jsonschema/stix.schema.json`, and why to validate before loading data into the generated Python models.
genre: how-to
resource: docs/index.md
relatedTo:
  - https://w3id.org/lmodel/stix/knowledge/explanations/closed-classes-and-custom-content
sources:
  - id: index.md
    resource: docs/index.md
    title: the Validating data section
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# Validate STIX data

1. Run `linkml-validate -s src/stix/schema/stix.yaml -C StixBundle bundle.json` for a bundle, or name the object's class, such as `-C StixIndicator`, for a single object.[^index.md]
2. Or use `project/jsonschema/stix.schema.json`, which `just gen-project` writes, with any JSON Schema validator. Its root is the bundle.
3. Declare custom properties and objects in a schema that imports this one before you validate data that has them.
4. Validate before you load data into the dataclasses or the Pydantic models, which check less and cannot hold a bundle's objects.

[^index.md]: docs/index.md, the Validating data section
