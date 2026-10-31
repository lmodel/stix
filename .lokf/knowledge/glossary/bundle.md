---
type: GlossaryTerm
id: https://w3id.org/lmodel/stix/knowledge/glossary/bundle
title: STIX bundle
description: In STIX, a bundle carries a set of STIX objects together for transport, and is not itself a STIX object. The schema renders it as `StixBundle`, the tree root, whose `objects` may be any concrete STIX object class.
genre: reference
definition: A container that carries STIX objects together for transport; it is not a STIX object itself.
definedBy:
  - https://w3id.org/lmodel/stix/knowledge/references/stix-2-1-specification
relatedTo:
  - https://w3id.org/lmodel/stix/knowledge/datasets/stix-linkml-schema
resource: src/stix/schema/stix.yaml
sources:
  - id: schema-stix.yaml
    resource: src/stix/schema/stix.yaml
    title: the class StixBundle
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# STIX bundle

A STIX bundle carries a set of STIX objects together for transport. It is not a STIX object itself, so in STIX 2.1 it has a type, an identifier and its objects, and no `spec_version`. The schema renders it as `StixBundle` in the umbrella `stix.yaml`, the tree root.[^schema-stix.yaml] The validator checks each object of a bundle against the concrete class whose type it pins.

[^schema-stix.yaml]: src/stix/schema/stix.yaml, the class StixBundle
