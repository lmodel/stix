<a href="https://github.com/linkml/linkml-project-copier"><img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/copier-org/copier/master/img/badge/badge-grayscale-inverted-border-teal.json" alt="Copier Badge" style="max-width:100%;"/></a>

# stix

Structured Threat Information Expression (STIX) 2.1 (LinkML)

> **Two ways in.** This README is one; the other is a docent, a museum's name
> for a guide. Install
> [`ktl-docent`](https://github.com/noelmcloughlin/knowledge-trust-ladder) into
> whatever agent you already use, by a route from
> [the install page](https://w3id.org/ktl/docs/install/), and ask it anything
> about this project. It answers from `.lokf/knowledge/`,
> the checked part of what the project knows, and says how far each answer has
> been trusted (still a draft, checked by automation only, or confirmed by a
> named person). It opens the source for exact values, and records what it
> could not answer so the gap gets filled. The same docent serves a person at a
> prompt, an agent reading this file, or a chatbot that can load a skill.
> **Agents:** if `.lokf/knowledge/index.md` exists, read it first. `llms.txt`
> says how to weigh it.

## Documentation Website

[https://lmodel.github.io/stix](https://lmodel.github.io/stix)

## What it models

[Structured Threat Information Expression (STIX) Version 2.1](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html), the OASIS Standard of 10 June 2021 for exchanging cyber threat intelligence. The schema header's `version` is 2.1, and its `source` is that document. STIX's own property names are the schema's keys, so STIX JSON validates unchanged. The schema is five modules under the umbrella `stix.yaml`, so a schema that needs part of STIX can import that part alone:

* **Domain objects** (`stix_sdo`, and `StixIdentity` in `stix_core`): attack patterns, campaigns, courses of action, groupings, identities, incidents, indicators, infrastructure, intrusion sets, locations, malware, malware analyses, notes, observed data, opinions, reports, threat actors, tools and vulnerabilities.
* **Relationship objects** (`stix_sro`): `StixRelationship` and `StixSighting`.
* **Cyber-observable objects** (`stix_sco`): the eighteen, from `StixArtifact` to `StixX509Certificate`, with their predefined extensions, such as `StixNtfsExtension`.
* **Meta objects and shared types** (`stix_core`): marking definitions, language content, extension definitions, external references, kill chain phases, granular markings, hashes, and the abstract bases `StixObject`, `StixDomainObject`, `StixRelationshipObject` and `StixCyberObservableObject`.
* **Vocabularies** (`stix_vocabularies`): an open vocabulary, such as `StixIndustrySector` (`industry-sector-ov`), never rejects another string; a closed enumeration, such as `StixAgreement` (`opinion-enum`), does.
* **The bundle** (`stix`): `StixBundle`, the tree root, which holds any STIX objects.

`upstream/` copies OASIS's STIX 2.1 JSON schemas, examples and licence from [oasis-open/cti-stix2-json-schemas](https://github.com/oasis-open/cti-stix2-json-schemas) at commit `9af1db4`, since that repository publishes no releases. Tests hold the schema to the JSON schemas and validate OASIS's examples unchanged. A weekly workflow reports when OASIS changes the copy, publishes another edition or approves STIX 2.1 Errata 01, which is a committee draft today. Release tags number the schema's versions.

## Influences

None beyond STIX: the schema renders one publication, and its release asset and governance files follow [lmodel/slsa](https://github.com/lmodel/slsa).

## Mappings

Classes and slots name terms of the [Unified Cyber Ontology (UCO)](https://github.com/ucoProject/UCO) 1.5.0 where the meaning matches, under UCO's own namespaces: `close_mappings` for the cyber-observable objects, their extensions and the shared objects, such as `uco-observable:File` and `uco-core:Relationship`, and `broad_mappings` for `StixTool`. The domain objects that UCO has no term for stay unmapped. `tests/test_mappings.py` checks each mapped term against UCO's own term list.

## Not modelled here

* The STIX patterning language: an indicator's `pattern` is a string, and nothing checks its grammar.
* Custom properties and custom objects. The classes are closed, so a schema that imports this one declares them, as [lmodel/attack](https://github.com/lmodel/attack) does for MITRE's.
* Custom marking definition types, and the STIX 2.0 style of custom extension.
* STIX 2.1 Errata 01, until OASIS approves it.
* The rules no validator can check, which [docs/index.md](docs/index.md) lists.

## Repository Structure

* [docs/](docs/): the website's pages, with the generated schema pages in [elements/](docs/elements/)
* [examples/](examples/): usage examples
* [project/](project/): generated project files (do not edit them)
* [scripts/](scripts/): the upstream watch and the UCO term extractor
* [src/stix/schema/](src/stix/schema): the LinkML schema, its modules and the umbrella `stix.yaml` (edit these)
* [src/stix/datamodel/](src/stix/datamodel): the generated Python datamodel
* [tests/](tests/): Python tests, with example data in [data/](tests/data), the neighbours' adapt copies in [neighbours/](tests/neighbours) and UCO's term list in [uco/](tests/uco)
* [upstream/](upstream/): OASIS's JSON schemas and examples at the pinned commit (do not edit them)
* [website/](website/): the Astro Starlight site built from the README, `docs/`, the schema's pages and the knowledge bundle

## Developer Tools

Run `just` to list the project's [just](https://github.com/casey/just/) recipes.

## Knowledge Trust Ladder (KTL)

`.lokf/` holds this project's [KTL](https://w3id.org/ktl/) knowledge bundle, in the Linked Open Knowledge Format (LOKF). Its domain schema is `.lokf/stix.yaml`, which `lokf adapt` writes from `src/stix/schema/stix.yaml`. Edit the source, never the copy. A release carries the copy as `schema-<tag>-stix.yaml`, on the terms [CONTRIBUTING.md](CONTRIBUTING.md#releasing-maintainers) gives.

`just lokf-adapt` rewrites the copy, and `just lokf-adapt-check` says when it is stale. The copy roots `StixObject` and `StixBundle` on `Concept`, so a concept may name any STIX object class as its `type`. They are the roots because lokf 0.9.0 requires every class that carries the schema's identifier, `id`, to be a concept type. In Obsidian, add the domain objects to the *Known LOKF types* setting of the KTL Registrar and KTL Curator plugins:

```text
StixAttackPattern, StixCampaign, StixCourseOfAction, StixGrouping, StixIdentity, StixIncident, StixIndicator, StixInfrastructure, StixIntrusionSet, StixLocation, StixMalware, StixMalwareAnalysis, StixNote, StixObservedData, StixOpinion, StixReport, StixThreatActor, StixTool, StixVulnerability
```

In a concept, the concept's own `id`, `title` and `description` are LOKF's, and the STIX keys that LOKF also defines are renamed with the `stix_` prefix: `stix_type`, `stix_created`, `stix_name`, `stix_description`, `stix_definition`, `stix_version`, `stix_url`, `stix_body` and `stix_context`. Each keeps its `stix:` IRI.

A host imports the copy beside LOKF's schema, `lokf.yaml`, and beside other adapt copies. LinkML merges them into one namespace, where the last definition of a name wins silently. So no class, enum or type shares a name with LOKF's or with the released copies of slsa, github-actions, oscal, spdx, nist-sp-800-218, nist-sp-800-53, nist-sp-800-171, nist-csf-v2 and in-toto. STIX's own property names stay, so some keys are shared, and each projects under one copy's IRI in a composite of the two:

* in-toto and slsa: `content`, `subject` and `value`;
* spdx: `comment`, `key`, `statement`, `subject`, `summary` and `value`;
* oscal: `capabilities`, `city`, `country`, `date`, `end`, `groups`, `hashes`, `number`, `pattern`, `postal_code`, `protocols`, `published`, `roles`, `start`, `statement`, `subject`, `value` and `values`.

`tests/test_schema_rules.py` pins these lists and fails on a new shared name. [lokf #169](https://github.com/nicholsn/lokf/issues/169) asks `adapt` for a `--beside` option that would rename them too.

## License

The schema and the code are under the Apache License 2.0 ([LICENSE](LICENSE)).

The knowledge bundle in `.lokf/knowledge/` is under the Creative Commons Attribution 4.0 International licence (CC BY 4.0), as its `index.md` declares.

OASIS's JSON schemas and examples under `upstream/`, and the schema's descriptions taken from them, are under OASIS's BSD-3-Clause licence, which [NOTICE](NOTICE) carries. The STIX specification is copyright OASIS Open: the schema cites it and copies none of its text.

This is not an official OASIS project, and its use implies no endorsement by OASIS.

## Contributing and security

[CONTRIBUTING.md](CONTRIBUTING.md) is the checklist for pull requests and
releases, [AI_COVENANT.md](AI_COVENANT.md) sets the rules for AI-assisted work,
[SECURITY.md](SECURITY.md) says how to report a vulnerability, and
[CHANGELOG.md](CHANGELOG.md) records the changes.

## Credits

Built from the [linkml-project-copier](https://github.com/linkml/linkml-project-copier) template ([doi:10.5281/zenodo.15163584](https://doi.org/10.5281/zenodo.15163584)).
