---
type: GlossaryTerm
id: https://w3id.org/lmodel/stix/knowledge/glossary/extension
title: Extension
description: "In STIX, an object's `extensions` dictionary holds its extensions: the predefined extensions of some cyber-observable objects, such as `ntfs-ext`, and extensions an extension definition (`StixExtensionDefinition`) defines, keyed by that definition's identifier."
genre: reference
definition: "Additional properties on a STIX object: a predefined extension of a cyber-observable object, or one that an extension definition defines."
definedBy:
  - https://w3id.org/lmodel/stix/knowledge/references/stix-2-1-specification
relatedTo:
  - https://w3id.org/lmodel/stix/knowledge/datasets/stix-sco-module
  - https://w3id.org/lmodel/stix/knowledge/datasets/stix-core-module
resource: src/stix/schema/stix_sco.yaml
sources:
  - id: stix_sco.yaml
    resource: src/stix/schema/stix_sco.yaml
    title: the extension classes and dictionaries
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# Extension

An object's `extensions` property is a dictionary of its extensions. A file, network traffic, a process and a user account have predefined extensions, such as `ntfs-ext` for a file, which the schema renders as classes such as `StixNtfsExtension`.[^stix_sco.yaml] Any object may also carry an extension that an extension definition defines, keyed by the definition's identifier, with an `extension_type` and the properties its definition's schema states.

[^stix_sco.yaml]: src/stix/schema/stix_sco.yaml, the extension classes and dictionaries
