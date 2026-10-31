---
type: GlossaryTerm
id: https://w3id.org/lmodel/stix/knowledge/glossary/open-vocabulary
title: Open vocabulary
description: In STIX, an open vocabulary (a name ending in `-ov`) suggests values for a property but accepts any other string, while a closed enumeration (`-enum`) does not. The schema renders an open vocabulary as an enum that a slot names beside `string`.
genre: reference
definition: A list of suggested values for a STIX property that accepts any other string as well.
definedBy:
  - https://w3id.org/lmodel/stix/knowledge/references/stix-2-1-specification
relatedTo:
  - https://w3id.org/lmodel/stix/knowledge/datasets/stix-vocabularies-module
resource: src/stix/schema/stix_vocabularies.yaml
sources:
  - id: stix_vocabularies.yaml
    resource: src/stix/schema/stix_vocabularies.yaml
    title: the enum descriptions
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# Open vocabulary

In STIX 2.1 an open vocabulary, whose name ends in `-ov`, lists suggested values for a property, and a producer may use any other string. A closed enumeration, whose name ends in `-enum`, accepts only its listed values.

The schema renders both as enums with the `Stix` prefix in `stix_vocabularies`. A slot that takes an open vocabulary names the enum and `string` in `any_of`, so a value outside the list still validates. A slot that takes a closed enumeration names the enum as its range.[^stix_vocabularies.yaml]

[^stix_vocabularies.yaml]: src/stix/schema/stix_vocabularies.yaml, the enum descriptions
