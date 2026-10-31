---
type: GlossaryTerm
id: https://w3id.org/lmodel/stix/knowledge/glossary/marking-definition
title: Marking definition
description: In STIX, a marking definition states a data marking, such as a copyright statement or a Traffic Light Protocol (TLP) level, that objects apply through `object_marking_refs` or granular markings. The schema renders it as `StixMarkingDefinition`.
genre: reference
definition: A STIX meta object that states a marking, such as a statement or a Traffic Light Protocol level, which other objects reference.
definedBy:
  - https://w3id.org/lmodel/stix/knowledge/references/stix-2-1-specification
relatedTo:
  - https://w3id.org/lmodel/stix/knowledge/datasets/stix-core-module
resource: src/stix/schema/stix_core.yaml
sources:
  - id: stix_core.yaml
    resource: src/stix/schema/stix_core.yaml
    title: the class StixMarkingDefinition
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# Marking definition

A marking definition is a STIX meta object that states a data marking. Objects apply it to themselves through `object_marking_refs`, or to some of their properties through granular markings. The schema renders it as `StixMarkingDefinition`, whose `definition` is a statement (`StixStatementMarking`) or a Traffic Light Protocol level (`StixTlpMarking`). Unlike a domain object, it has no `modified`, because a marking definition cannot be versioned.[^stix_core.yaml]

[^stix_core.yaml]: src/stix/schema/stix_core.yaml, the class StixMarkingDefinition
