---
type: GlossaryTerm
id: https://w3id.org/lmodel/stix/knowledge/glossary/relationship-object
title: STIX Relationship Object (SRO)
description: "In STIX, a STIX Relationship Object (SRO) links other objects: `StixRelationship` joins a source to a target by a relationship type, and `StixSighting` records that a domain object was seen."
genre: reference
definition: "An object that links other STIX objects: a relationship, or a sighting of a domain object."
definedBy:
  - https://w3id.org/lmodel/stix/knowledge/references/stix-2-1-specification
relatedTo:
  - https://w3id.org/lmodel/stix/knowledge/datasets/stix-sro-module
resource: src/stix/schema/stix_sro.yaml
sources:
  - id: stix_sro.yaml
    resource: src/stix/schema/stix_sro.yaml
    title: the classes
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# STIX Relationship Object (SRO)

A STIX Relationship Object (SRO) links other STIX objects. STIX 2.1 defines two: a relationship, which joins a source object to a target object by a relationship type such as `uses`, and a sighting, which records that a domain object was seen. The schema renders them as `StixRelationship` and `StixSighting`, subclasses of the abstract `StixRelationshipObject`.[^stix_sro.yaml]

[^stix_sro.yaml]: src/stix/schema/stix_sro.yaml, the classes
