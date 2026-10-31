---
type: Dataset
id: https://w3id.org/lmodel/stix/knowledge/datasets/stix-sdo-module
title: stix_sdo module
description: "The module `src/stix/schema/stix_sdo.yaml`: the STIX domain objects other than identity, such as `StixAttackPattern`, `StixIndicator`, `StixMalware` and `StixThreatActor`, and the dictionary of observed data's deprecated `objects`."
genre: reference
resource: src/stix/schema/stix_sdo.yaml
isPartOf:
  - https://w3id.org/lmodel/stix/knowledge/datasets/stix-linkml-schema
sources:
  - id: stix_sdo.yaml
    resource: src/stix/schema/stix_sdo.yaml
    title: the classes and the slots
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# stix_sdo module

`src/stix/schema/stix_sdo.yaml` imports `linkml:types`, `stix_vocabularies`, `stix_core` and `stix_sco`, and holds 19 classes and 64 slots.[^stix_sdo.yaml] Eighteen are domain objects, each a subclass of `StixDomainObject`: attack pattern, campaign, course of action, grouping, incident, indicator, infrastructure, intrusion set, location, malware, malware analysis, note, observed data, opinion, report, threat actor, tool and vulnerability. The nineteenth, `StixObservedObjects`, is the dictionary of cyber-observable objects that observed data may hold in its deprecated `objects` property.

The module imports `stix_sco` because some domain objects point at observables: malware at its samples and operating systems, and a malware analysis at its sample and its analysis environment.

[^stix_sdo.yaml]: src/stix/schema/stix_sdo.yaml, the classes and the slots
