---
type: Dataset
id: https://w3id.org/lmodel/stix/knowledge/datasets/stix-vocabularies-module
title: stix_vocabularies module
description: "The module `src/stix/schema/stix_vocabularies.yaml`: STIX 2.1's open vocabularies and closed enumerations as 35 enums, such as `StixIndustrySector` (`industry-sector-ov`) and `StixAgreement` (`opinion-enum`), each naming its STIX vocabulary in an annotation."
genre: reference
resource: src/stix/schema/stix_vocabularies.yaml
isPartOf:
  - https://w3id.org/lmodel/stix/knowledge/datasets/stix-linkml-schema
sources:
  - id: stix_vocabularies.yaml
    resource: src/stix/schema/stix_vocabularies.yaml
    title: the enums and their annotations
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# stix_vocabularies module

`src/stix/schema/stix_vocabularies.yaml` holds 35 enums and imports only `linkml:types`.[^stix_vocabularies.yaml] Each enum carries the `Stix` prefix, a singular name, and a `stix_vocabulary` annotation with the name STIX gives the list, with the section of STIX 2.1 that defines it.

- 23 are open: a slot that names one of them takes the enum or any other string, so the enum documents the list without rejecting a value outside it. An example is `StixIndustrySector`, STIX's `industry-sector-ov`.
- 12 are closed and reject any other value, such as `StixAgreement`, STIX's `opinion-enum`, and `StixWindowsRegistryDatatype`.

The values follow the tables of the OASIS Standard where the JSON schemas differ, as [the departures from the JSON schemas](../explanations/departures-from-the-json-schemas.md) say. [Open vocabulary](../glossary/open-vocabulary.md) defines the term.

[^stix_vocabularies.yaml]: src/stix/schema/stix_vocabularies.yaml, the enums and their annotations
