---
type: Dataset
id: https://w3id.org/lmodel/stix/knowledge/datasets/stix-core-module
title: stix_core module
description: "The module `src/stix/schema/stix_core.yaml`: the identifier and timestamp types, the shared slots such as `id`, `type` and `created_by_ref`, the abstract bases `StixObject`, `StixCommonObject`, `StixDomainObject`, `StixRelationshipObject` and `StixCyberObservableObject`, identity, the meta objects, and the dictionaries for hashes and extensions."
genre: reference
resource: src/stix/schema/stix_core.yaml
isPartOf:
  - https://w3id.org/lmodel/stix/knowledge/datasets/stix-linkml-schema
sources:
  - id: stix_core.yaml
    resource: src/stix/schema/stix_core.yaml
    title: the types, the slots and the classes
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# stix_core module

`src/stix/schema/stix_core.yaml` imports `linkml:types` and `stix_vocabularies`, and holds 19 classes, 42 slots and 6 types.[^stix_core.yaml]

- **Types**: `stix_identifier`, three timestamp types (any precision, at least milliseconds, and whole seconds), `stix_hex` and `stix_binary`.
- **Bases**: `StixObject` is any STIX object, with `id`, `type`, `spec_version`, the markings and `extensions`. `StixCommonObject` adds STIX's common properties, such as `created` and `modified`, which it requires. `StixDomainObject`, `StixRelationshipObject` and `StixCyberObservableObject` are the three object kinds. All five are abstract.
- **Objects**: `StixIdentity` sits here because every object's `created_by_ref` points at one. `StixMarkingDefinition`, `StixLanguageContent` and `StixExtensionDefinition` are the meta objects.
- **Shared types**: `StixExternalReference`, `StixKillChainPhase`, `StixGranularMarking`, the marking definitions `StixStatementMarking` and `StixTlpMarking`, and `StixExtension`.
- **Dictionaries**: `StixHashes`, `StixExtensions`, `StixDictionary` and `StixLanguageContents` admit keys STIX leaves open through `extra_slots`.

Each class pins `type` to its STIX type name with `equals_string`, and narrows `id` with a pattern for its own type prefix.

[^stix_core.yaml]: src/stix/schema/stix_core.yaml, the types, the slots and the classes
