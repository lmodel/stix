---
type: Dataset
id: https://w3id.org/lmodel/stix/knowledge/datasets/stix-linkml-schema
title: stix LinkML schema
description: "The LinkML schema of STIX 2.1: the umbrella `src/stix/schema/stix.yaml` (schema id `https://w3id.org/lmodel/stix`, version 2.1) and its five modules, with 84 classes, 321 slots, 35 enums and 6 types. Its `lokf adapt` copy `.lokf/stix.yaml`, rooted on `StixObject` and `StixBundle`, is the bundle's domain schema."
genre: reference
resource: src/stix/schema/stix.yaml
version: "2.1"
license: Apache-2.0
derivedFrom:
  - https://w3id.org/lmodel/stix/knowledge/references/stix-2-1-specification
  - https://w3id.org/lmodel/stix/knowledge/references/oasis-stix-json-schemas
hasPart:
  - https://w3id.org/lmodel/stix/knowledge/datasets/stix-vocabularies-module
  - https://w3id.org/lmodel/stix/knowledge/datasets/stix-core-module
  - https://w3id.org/lmodel/stix/knowledge/datasets/stix-sco-module
  - https://w3id.org/lmodel/stix/knowledge/datasets/stix-sdo-module
  - https://w3id.org/lmodel/stix/knowledge/datasets/stix-sro-module
sources:
  - id: schema-stix.yaml
    resource: src/stix/schema/stix.yaml
    title: the header, the annotations and the comments
  - id: schema
    resource: src/stix/schema
    title: the six schema files
  - id: readme.md
    resource: README.md
    title: the What it models and Knowledge Trust Ladder (KTL) sections
  - id: project.justfile
    resource: project.justfile
    title: the knowledge bundle recipes
  - id: lokf-stix.yaml
    resource: .lokf/stix.yaml
    title: the notes lokf adapt wrote
  - resource: .lokf/justfile
    title: the schema line
  - resource: .lokf/pyproject.toml
    title: the tool.lokf table
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# stix LinkML schema

`src/stix/schema/stix.yaml` is the umbrella schema, titled "Structured Threat Information Expression (STIX)". Its header gives `version: "2.1"`, the OASIS Standard of 10 June 2021 as `source`, the Apache-2.0 licence, and the commit of OASIS's JSON schemas that `upstream/` copies.[^schema-stix.yaml] It imports five modules and holds one class, `StixBundle`, the tree root.

## Modules

- [stix_vocabularies](stix-vocabularies-module.md): the 35 enums.
- [stix_core](stix-core-module.md): the types, the shared slots, the abstract object bases, identity and the meta objects.
- [stix_sco](stix-sco-module.md): the cyber-observable objects and their predefined extensions.
- [stix_sdo](stix-sdo-module.md): the domain objects other than identity.
- [stix_sro](stix-sro-module.md): relationship and sighting.

Together the six files hold 84 classes, of which 5 are abstract, 321 slots, 35 enums and 6 types.[^schema] STIX's own property names are the keys, so STIX JSON validates unchanged, and every class and enum carries the `Stix` prefix.[^readme.md]

## As the bundle's domain schema

`.lokf/stix.yaml` is the copy `lokf adapt` writes from the umbrella. `project.justfile` roots it on `StixObject` and `StixBundle`, because lokf 0.9.0 requires every class that carries the identifier `id` to descend from LOKF's `Concept`.[^project.justfile] The copy renames the keys LOKF also defines, such as `type` to `stix_type`, and keeps their IRIs.[^lokf-stix.yaml] The `schema :=` line of `.lokf/justfile` and the `[tool.lokf]` table of `.lokf/pyproject.toml` both name the copy.

[^schema-stix.yaml]: src/stix/schema/stix.yaml, the header, the annotations and the comments
[^schema]: src/stix/schema, the six schema files
[^readme.md]: README.md, the What it models section
[^project.justfile]: project.justfile, the knowledge bundle recipes
[^lokf-stix.yaml]: .lokf/stix.yaml, the notes lokf adapt wrote
