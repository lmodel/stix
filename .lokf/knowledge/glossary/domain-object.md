---
type: GlossaryTerm
id: https://w3id.org/lmodel/stix/knowledge/glossary/domain-object
title: STIX Domain Object (SDO)
description: In STIX, a STIX Domain Object (SDO) is a higher-level concept of threat intelligence, such as a campaign, an indicator or a threat actor. The schema renders each as a subclass of `StixDomainObject`, which a knowledge concept may name as its type.
genre: reference
definition: A higher-level concept of cyber threat intelligence, such as an attack pattern, a malware family or a threat actor.
definedBy:
  - https://w3id.org/lmodel/stix/knowledge/references/stix-2-1-specification
relatedTo:
  - https://w3id.org/lmodel/stix/knowledge/datasets/stix-sdo-module
resource: src/stix/schema/stix_core.yaml
sources:
  - id: stix_core.yaml
    resource: src/stix/schema/stix_core.yaml
    title: the class StixDomainObject
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# STIX Domain Object (SDO)

A STIX Domain Object (SDO) is a higher-level concept of cyber threat intelligence, such as an attack pattern, a malware family or a threat actor. STIX 2.1 defines nineteen. The schema renders each as a subclass of the abstract `StixDomainObject`, eighteen in `stix_sdo` and `StixIdentity` in `stix_core`.[^stix_core.yaml] The README lists them for the *Known LOKF types* setting.

[^stix_core.yaml]: src/stix/schema/stix_core.yaml, the class StixDomainObject
