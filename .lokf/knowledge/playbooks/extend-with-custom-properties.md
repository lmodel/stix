---
type: Playbook
id: https://w3id.org/lmodel/stix/knowledge/playbooks/extend-with-custom-properties
title: Extend the schema with custom properties
description: "How to validate STIX data that carries custom properties or custom objects: write a LinkML schema that imports this one, declare each `x_` property as a slot of a subclass, and each custom object as a class with its own `type` and `id` pattern."
genre: how-to
resource: docs/index.md
relatedTo:
  - https://w3id.org/lmodel/stix/knowledge/explanations/closed-classes-and-custom-content
sources:
  - id: schema-stix.yaml
    resource: src/stix/schema/stix.yaml
    title: the comment on closed classes
  - resource: docs/index.md
    title: the Custom properties and objects section
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# Extend the schema with custom properties

1. Write a LinkML schema that imports the stix modules it needs, such as `stix_core` and `stix_sdo`.
2. Declare each custom property, such as `x_acme_score`, as a top-level slot with a slot URI in your own namespace.
3. Subclass the STIX class that carries it, such as `StixIndicator`, and list the slot there.
4. Declare a custom object as a class that is a `StixDomainObject` or `StixCyberObservableObject`. Pin its `type` with `equals_string`, and give its `id` the full pattern for its prefix, since a class's pattern replaces the type's.[^schema-stix.yaml]
5. Validate a bundle against your schema's bundle class or `StixBundle`, which then accepts your classes.

[^schema-stix.yaml]: src/stix/schema/stix.yaml, the comment on closed classes
