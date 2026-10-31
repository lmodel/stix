---
type: Dataset
id: https://w3id.org/lmodel/stix/knowledge/datasets/generated-artefacts
title: Generated artefacts
description: "The files generated from the schema and committed: `project/` (JSON Schema, OWL, SHACL, JSON-LD context and the rest), the Python datamodel in `src/stix/datamodel/`, the merged schema in `docs/schema/stix.yaml`, and the adapt copy `.lokf/stix.yaml`."
genre: reference
resource: project
derivedFrom:
  - https://w3id.org/lmodel/stix/knowledge/datasets/stix-linkml-schema
sources:
  - id: justfile
    resource: justfile
    title: the gen-project and gen-doc recipes
  - id: contributing.md
    resource: CONTRIBUTING.md
    title: the Edit a module, then regenerate rule
  - id: generators.yaml
    resource: .linkml/generators.yaml
    title: the jsonschema settings
  - resource: project
    title: the generated files
  - resource: src/stix/datamodel
    title: the generated Python models
  - resource: docs/schema/stix.yaml
    title: the merged schema
  - resource: config.public.mk
    title: the schema name and the generators' settings file
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# Generated artefacts

`just gen-project` writes `project/`, with a JSON Schema, an OWL ontology, SHACL and ShEx shapes, a JSON-LD context, GraphQL, Protobuf, SQL, TypeScript, Java and an Excel workbook. It also writes the dataclasses and the Pydantic models under `src/stix/datamodel/`.[^justfile] `just gen-doc` writes the merged schema to `docs/schema/stix.yaml`, and `just lokf-adapt` writes `.lokf/stix.yaml`. None of them is edited by hand.[^contributing.md]

`.linkml/generators.yaml` holds the generators' settings. Its JSON Schema settings include each concrete descendant wherever a class is a range, so the generated file checks each object of a bundle against its own class.[^generators.yaml] `docs/index.md` says what the generated Python models leave unchecked, including a bundle's objects.

[^justfile]: justfile, the gen-project and gen-doc recipes
[^contributing.md]: CONTRIBUTING.md, the Edit a module, then regenerate rule
[^generators.yaml]: .linkml/generators.yaml, the jsonschema settings
