# Change Log

## 2026-10-31

* **Prose**: reworded 9 concept bodies in plain English. No fact, link, number or frontmatter changed.
* **Added**: stix LinkML schema, from `src/stix/schema/stix.yaml`.
* **Added**: stix_vocabularies module, from `src/stix/schema/stix_vocabularies.yaml`.
* **Added**: stix_core module, from `src/stix/schema/stix_core.yaml`.
* **Added**: stix_sco module, from `src/stix/schema/stix_sco.yaml`.
* **Added**: stix_sdo module, from `src/stix/schema/stix_sdo.yaml`.
* **Added**: stix_sro module, from `src/stix/schema/stix_sro.yaml`.
* **Added**: Copy of OASIS's STIX 2.1 JSON schemas, from `upstream`.
* **Added**: Examples and counter-examples, from `tests/data`.
* **Added**: Generated artefacts, from `project`.
* **Added**: UCO 1.5.0 term list, from `tests/uco/uco-1.5.0-terms.txt`.
* **Added**: Neighbours' adapt copies, from `tests/neighbours`.
* **Added**: STIX Version 2.1 (OASIS Standard), from <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html>.
* **Added**: OASIS STIX 2.1 JSON schemas, from <https://github.com/oasis-open/cti-stix2-json-schemas>.
* **Added**: Unified Cyber Ontology (UCO) 1.5.0, from <https://github.com/ucoProject/UCO/releases/tag/1.5.0>.
* **Added**: STIX Domain Object (SDO), from `src/stix/schema/stix_core.yaml`.
* **Added**: STIX Relationship Object (SRO), from `src/stix/schema/stix_sro.yaml`.
* **Added**: STIX Cyber-observable Object (SCO), from `src/stix/schema/stix_sco.yaml`.
* **Added**: STIX bundle, from `src/stix/schema/stix.yaml`.
* **Added**: Open vocabulary, from `src/stix/schema/stix_vocabularies.yaml`.
* **Added**: STIX identifier, from `src/stix/schema/stix_core.yaml`.
* **Added**: Marking definition, from `src/stix/schema/stix_core.yaml`.
* **Added**: Extension, from `src/stix/schema/stix_sco.yaml`.
* **Added**: Closed classes and custom content, from `src/stix/schema/stix.yaml`.
* **Added**: Scope, influences and mappings, from `README.md`.
* **Added**: Element names and shared keys, from `tests/test_schema_rules.py`.
* **Added**: Departures from OASIS's JSON schemas, from `docs/about.md`.
* **Added**: Regenerate and test, from `justfile`.
* **Added**: Validate STIX data, from `docs/index.md`.
* **Added**: Update the upstream pins, from `scripts/check_upstream_release.py`.
* **Added**: Extend the schema with custom properties, from `docs/index.md`.
* **Added**: Release, from `.releaserc.json`.
* **Added**: Security policy, from `SECURITY.md`.
* **Added**: Licence and attribution, from `NOTICE`.
* **Added**: AI covenant, from `AI_COVENANT.md`.
* **Added**: Documentation website, from `website/site.config.mjs`.
* **Added**: Build and test (main.yaml), from `.github/workflows/main.yaml`.
* **Added**: Lint and docs (lint-and-docs.yaml), from `.github/workflows/lint-and-docs.yaml`.
* **Added**: Upstream watch (upstream-watch.yaml), from `.github/workflows/upstream-watch.yaml`.
* **Added**: Semantic release (semantic-release.yml), from `.github/workflows/semantic-release.yml`.
* **Added**: Knowledge Librarian (knowledge-librarian.yaml), from `.github/workflows/knowledge-librarian.yaml`.
* **Added**: Knowledge Registrar (knowledge-registrar.yaml), from `.github/workflows/knowledge-registrar.yaml`.
* **Added**: Knowledge Release (knowledge-release.yaml), from `.github/workflows/knowledge-release.yaml`.
* **Added**: Knowledge sync (knowledge-sync.yaml), from `.github/workflows/knowledge-sync.yaml`.
* **Added**: Knowledge website (knowledge-website.yaml), from `.github/workflows/knowledge-website.yaml`.
* **Added**: Knowledge sources, from the repository's paths.
* **Removal**: the sidecar's placeholder service, which real concepts now replace.
* **Initialization**: Scaffolded the LOKF bundle for stix with placeholder
  services. Real concepts to follow.
