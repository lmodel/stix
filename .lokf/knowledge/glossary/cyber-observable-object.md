---
type: GlossaryTerm
id: https://w3id.org/lmodel/stix/knowledge/glossary/cyber-observable-object
title: STIX Cyber-observable Object (SCO)
description: In STIX, a STIX Cyber-observable Object (SCO) records a fact observed on a network or host, such as a file, an IP address or a process. The schema renders the eighteen as subclasses of `StixCyberObservableObject`.
genre: reference
definition: A fact observed on a network or host, such as a file, an address or a process, without saying who did what.
definedBy:
  - https://w3id.org/lmodel/stix/knowledge/references/stix-2-1-specification
relatedTo:
  - https://w3id.org/lmodel/stix/knowledge/datasets/stix-sco-module
resource: src/stix/schema/stix_sco.yaml
sources:
  - id: stix_sco.yaml
    resource: src/stix/schema/stix_sco.yaml
    title: the classes
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# STIX Cyber-observable Object (SCO)

A STIX Cyber-observable Object (SCO) records a fact observed on a network or host, such as a file, an IP address or a process, without saying who did what. STIX 2.1 defines eighteen, some with predefined extensions such as the NTFS extension of a file. The schema renders them as subclasses of the abstract `StixCyberObservableObject` in `stix_sco`.[^stix_sco.yaml]

[^stix_sco.yaml]: src/stix/schema/stix_sco.yaml, the classes
