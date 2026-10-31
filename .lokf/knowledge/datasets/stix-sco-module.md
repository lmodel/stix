---
type: Dataset
id: https://w3id.org/lmodel/stix/knowledge/datasets/stix-sco-module
title: stix_sco module
description: "The module `src/stix/schema/stix_sco.yaml`: the 18 STIX cyber-observable objects, from `StixArtifact` to `StixX509Certificate`, the 12 predefined extensions such as `StixNtfsExtension`, and the types they embed."
genre: reference
resource: src/stix/schema/stix_sco.yaml
isPartOf:
  - https://w3id.org/lmodel/stix/knowledge/datasets/stix-linkml-schema
sources:
  - id: stix_sco.yaml
    resource: src/stix/schema/stix_sco.yaml
    title: the classes and the slots
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# stix_sco module

`src/stix/schema/stix_sco.yaml` imports `linkml:types`, `stix_vocabularies` and `stix_core`, and holds 43 classes and 205 slots.[^stix_sco.yaml] It has the 18 cyber-observable objects of STIX 2.1, each a subclass of `StixCyberObservableObject`. It also has the 12 predefined extensions, each with a `stix_extension_name` annotation such as `ntfs-ext`, and the types the objects embed, such as `StixWindowsPeSection` and `StixMimePart`.

A file, network traffic, a process and a user account each take their own extensions dictionary, such as `StixFileExtensions`. The dictionary accepts the predefined extensions of that object and any extension an extension definition defines. A reference slot, such as `parent_directory_ref`, ranges over the class STIX names and carries that class's identifier pattern.

[^stix_sco.yaml]: src/stix/schema/stix_sco.yaml, the classes and the slots
