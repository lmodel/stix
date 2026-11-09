# Changelog

All notable changes to this project are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The `v0.0.0` tag is a baseline, not a release: it marks where versioning starts so the first real release is `0.1.0` rather than `1.0.0`. The schema stays below 1.0.0 until its shape settles, so a breaking change bumps the minor version. See [CONTRIBUTING.md](CONTRIBUTING.md#releasing-maintainers).

## [Unreleased]

### Security

- **The sidecar copies and the skills pin are at Knowledge Trust Ladder [v0.62.0](https://github.com/noelmcloughlin/knowledge-trust-ladder/compare/v0.60.0...v0.62.0).** The release changed `.github/workflows/knowledge-registrar.yaml`, `.github/workflows/knowledge-librarian.yaml`, `.github/workflows/knowledge-release.yaml`, `.github/workflows/knowledge-sync.yaml`, `.lokf/scripts/knowledge-librarian.sh`, `.lokf/scripts/knowledge-conventions.sh`, `.lokf/scripts/knowledge-conventions.py`, `.lokf/scripts/knowledge-preflight.sh`, `.lokf/scripts/knowledge-provenance.sh`, `.lokf/scripts/knowledge-apply.py`, `.lokf/scripts/knowledge-report.sh`, `.lokf/scripts/knowledge-sync.sh`, `.lokf/justfile`, `website/package-lock.json`, `website/package.json`, `website/scripts/sync.mjs` and `.github/workflows/knowledge-website.yaml` here.

## [0.2.0] - 2026-11-07

### Added

- **The schema as RDF Turtle and the merged schema**, in `project/rdf/` and `project/linkml/`, from `just gen-rdf` and `just gen-merged-schema`.

### Changed

- **The bundle's schema files sit in `.lokf/schema/`**: `lokf.yaml` and the `lokf adapt` copy `stix.yaml`, as KTL v0.62.0 lays them out.

## [0.1.1] - 2026-11-02

### Security

- **The sidecar copies and the skills pin are at Knowledge Trust Ladder [v0.60.0](https://github.com/noelmcloughlin/knowledge-trust-ladder/compare/v0.59.0...v0.60.0).** The release changed `.github/workflows/knowledge-registrar.yaml`, `.github/workflows/knowledge-librarian.yaml`, `.github/workflows/knowledge-release.yaml`, `.github/workflows/knowledge-sync.yaml`, `.lokf/scripts/knowledge-preflight.sh`, `.lokf/.gitignore`, `.lokf/justfile`, `website/package-lock.json`, `website/package.json`, `website/scripts/config.mjs`, `website/scripts/sync.mjs` and `.github/workflows/knowledge-website.yaml` here.

## [0.1.0] - 2026-10-31

### Added

- **A LinkML schema of Structured Threat Information Expression (STIX) Version 2.1, the OASIS Standard of 10 June 2021.** It holds the domain, relationship and cyber-observable objects, the predefined extensions, the meta objects, the vocabularies and enumerations, and the bundle, as five modules under one umbrella. STIX's own property names are its keys, so STIX JSON validates unchanged.
- **A copy of OASIS's STIX 2.1 JSON schemas and examples at a pinned commit, and a weekly upstream watch.** Tests hold the schema's properties, required lists and closed enumerations to the JSON schemas and validate OASIS's examples unchanged. The watch reports a changed, added or dropped file, a changed licence, another edition or an approved errata.
- **Mappings to the Unified Cyber Ontology (UCO) 1.5.0** where the meaning matches, each checked against UCO's own term list.
- **`.lokf/stix.yaml`, the schema's `lokf adapt` copy, rooted on `StixObject` and `StixBundle`.** The knowledge release attaches it as `schema-<tag>-stix.yaml`, and tests hold its names apart from those of the Linked Open Knowledge Format (LOKF) and of nine released lmodel copies.
- **An example of each class and a counter-example for each constraint**, held to the validator by `just test`. The tests also check every example against the rules that no validator states, such as the order of `created` and `modified`.
- **The repository's Knowledge Trust Ladder (KTL) knowledge bundle and its sidecar automation**, from the KTL v0.59.0 templates with the lokf floor at 0.9.0, and a knowledge website that replaces the mkdocs site.
- **`.github/release/package-lock.json`, which pins semantic-release and every package it pulls in.** The release job installs from it with `npm ci`, and Dependabot keeps it current.

### Changed

- **Classes and enums carry the `Stix` prefix** (`StixAttackPattern`, `StixFile`, `StixIndustrySector`), so none shares a name with LOKF or another lmodel schema, and each key is a top-level slot under `stix:`.
- **The classes are closed.** Custom properties and objects validate once a schema that imports this one declares them.
- **The Python project's name is `stix-linkml`**, because PyPI's `stix` is another project's. PyPI publishing stays off.

### Removed

- **The vendored STIX pattern parser and its ANTLR dependencies.** The schema does not check an indicator's pattern grammar.
- **The mappings to lmodel's old `uco-master` names and their test.** The schema maps to UCO 1.5.0's own terms instead.
- **The PyPI publishing workflow and the mkdocs site and its preview.** The knowledge website replaces the site.
