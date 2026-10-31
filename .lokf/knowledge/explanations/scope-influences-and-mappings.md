---
type: Explanation
id: https://w3id.org/lmodel/stix/knowledge/explanations/scope-influences-and-mappings
title: Scope, influences and mappings
description: What the schema models (STIX 2.1 at the OASIS Standard of 10 June 2021) and leaves out (the pattern grammar, custom content, Errata 01), what shaped it, and its mappings to the Unified Cyber Ontology (UCO) 1.5.0.
genre: explanation
resource: README.md
about:
  - https://w3id.org/lmodel/stix/knowledge/datasets/stix-linkml-schema
references:
  - https://w3id.org/lmodel/stix/knowledge/references/uco-1-5-0
  - https://w3id.org/lmodel/stix/knowledge/references/stix-2-1-specification
sources:
  - id: readme.md
    resource: README.md
    title: the Influences, Mappings and Not modelled here sections
  - resource: docs/about.md
    title: the What the schema leaves out section
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# Scope, influences and mappings

The schema renders one publication, STIX Version 2.1 at the OASIS Standard of 10 June 2021, and its release asset and governance files follow lmodel/slsa.[^readme.md]

## Mappings

Classes and slots name terms of the Unified Cyber Ontology (UCO) 1.5.0 where the meaning matches. The cyber-observable objects, their extensions and the shared objects, such as the bundle, the relationship and the external reference, carry `close_mappings`. `StixTool` carries `broad_mappings` to `uco-tool:Tool`, which UCO defines more widely. The domain objects that UCO has no term for stay unmapped.

## Not modelled

- The STIX patterning language: an indicator's `pattern` is a string, and nothing checks its grammar.
- Custom properties and custom objects, until a schema that imports this one declares them.
- Custom marking definition types, and the STIX 2.0 style of custom extension.
- STIX 2.1 Errata 01, a committee draft.
- The rules no validator can check, which `docs/index.md` lists.

[^readme.md]: README.md, the Influences, Mappings and Not modelled here sections
