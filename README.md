<a href="https://github.com/linkml/linkml-project-copier"><img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/copier-org/copier/master/img/badge/badge-grayscale-inverted-border-teal.json" alt="Copier Badge" style="max-width:100%;"/></a>

# stix

Structured Threat Information Expression (STIX) 2.1 (LinkML)

> **Only want to ask?** Install `ktl-docent` into any agent you use, by a route from [the install page](https://w3id.org/ktl/docs/install/), and ask it about this project. It answers from the bundle and says how far each answer has been checked.
>
> **Agents:** if `.lokf/knowledge/index.md` exists, read it first. `llms.txt` says how to weigh it.

## Documentation Website

[https://lmodel.github.io/stix](https://lmodel.github.io/stix)

## What it models

The schema models [Structured Threat Information Expression (STIX) Version 2.1](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html), the OASIS Standard of 10 June 2021 for exchanging cyber threat intelligence. STIX's own property names are the schema's keys, so STIX JSON validates unchanged. The schema is five modules under the umbrella `stix.yaml`, so a schema that needs part of STIX can import that part alone. The modules hold the domain objects (`stix_sdo`), the relationship objects (`stix_sro`), the cyber-observable objects (`stix_sco`), the meta objects and shared types (`stix_core`) and the vocabularies (`stix_vocabularies`).

`upstream/` copies OASIS's STIX 2.1 JSON schemas, examples and licence from [oasis-open/cti-stix2-json-schemas](https://github.com/oasis-open/cti-stix2-json-schemas) at commit `9af1db4`, and the tests hold the schema to them. A weekly workflow reports when OASIS changes the copy, publishes another edition or approves STIX 2.1 Errata 01.

## Mappings

* **[Unified Cyber Ontology (UCO)](https://github.com/ucoProject/UCO) 1.5.0**: `close_mappings` for the cyber-observable objects, their extensions and the shared objects, and `broad_mappings` for `StixTool`. `tests/test_mappings.py` checks each term against UCO's term list.

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

`.lokf/` holds this project's [KTL](https://w3id.org/ktl/) knowledge bundle. Its domain schema, `.lokf/stix.yaml`, is the copy `just lokf-adapt` writes from `src/stix/schema/stix.yaml`, and `just lokf-adapt-check` says when it is stale. Edit the source, never the copy. A release carries the copy as `schema-<tag>-stix.yaml`, on the terms [CONTRIBUTING.md](CONTRIBUTING.md#releasing-maintainers) gives.

The copy roots `StixObject` and `StixBundle` on `Concept`, so a concept may name any STIX object class as its `type`. In Obsidian, add the domain objects to the *Known LOKF types* setting of the KTL Registrar and KTL Curator plugins:

```text
StixAttackPattern, StixCampaign, StixCourseOfAction, StixGrouping, StixIdentity, StixIncident, StixIndicator, StixInfrastructure, StixIntrusionSet, StixLocation, StixMalware, StixMalwareAnalysis, StixNote, StixObservedData, StixOpinion, StixReport, StixThreatActor, StixTool, StixVulnerability
```

In a concept, the concept's own `id`, `title` and `description` are LOKF's, and the STIX keys that LOKF also defines are renamed with the `stix_` prefix: `stix_type`, `stix_created`, `stix_name`, `stix_description`, `stix_definition`, `stix_version`, `stix_url`, `stix_body` and `stix_context`. Each keeps its `stix:` IRI.

No class, enum or type shares a name with LOKF's schema or with another lmodel copy. STIX's property names stay, so some keys are shared with in-toto, slsa, spdx and oscal, and `tests/test_schema_rules.py` pins them. [lokf #169](https://github.com/nicholsn/lokf/issues/169) asks `adapt` for a `--beside` option that would rename them.

## License

The schema and the code are under the Apache License 2.0 ([LICENSE](LICENSE)), and the knowledge bundle in `.lokf/knowledge/` is under CC BY 4.0.

OASIS's JSON schemas and examples under `upstream/`, and the schema's descriptions taken from them, are under OASIS's BSD-3-Clause licence, which [NOTICE](NOTICE) carries. The STIX specification is copyright OASIS Open: the schema cites it and copies none of its text. This is not an official OASIS project, and its use implies no endorsement by OASIS.

## Contributing and security

[CONTRIBUTING.md](CONTRIBUTING.md) is the checklist for pull requests and
releases, [AI_COVENANT.md](AI_COVENANT.md) sets the rules for AI-assisted work,
[SECURITY.md](SECURITY.md) says how to report a vulnerability, and
[CHANGELOG.md](CHANGELOG.md) records the changes.

## Credits

Built from the [linkml-project-copier](https://github.com/linkml/linkml-project-copier) template ([doi:10.5281/zenodo.15163584](https://doi.org/10.5281/zenodo.15163584)).
