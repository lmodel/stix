---
lokf_version: "0.2"
okf_version: "0.2"
base_iri: https://w3id.org/lmodel/stix/knowledge/
context: https://w3id.org/lokf/context.jsonld
title: stix Knowledge Bundle
description: Structured Threat Information Expression (STIX) 2.1 (LinkML)
license: https://creativecommons.org/licenses/by/4.0/
publisher:
  type: Person
  id: https://w3id.org/lmodel/stix/knowledge/person/noel-mcloughlin
  name: Noel McLoughlin
---

# stix Knowledge Bundle

A [LOKF](https://lokf.nolan-nichols.com) knowledge base for stix. Every Markdown file under `knowledge/` is one concept; together they form a queryable knowledge graph, derived from this repository's code and docs.

# Services

* [Documentation website](services/documentation-site.md) - The knowledge website under `website/`, an Astro Starlight site built from the README, `docs/`, the schema's pages and the bundle, published at `https://lmodel.github.io/stix/` by `knowledge-website.yaml`, with redirects from the retired mkdocs addresses under `/elements/`.

# Datasets

* [stix LinkML schema](datasets/stix-linkml-schema.md) - The LinkML schema of STIX 2.1: the umbrella `src/stix/schema/stix.yaml` (schema id `https://w3id.org/lmodel/stix`, version 2.1) and its five modules, with 84 classes, 321 slots, 35 enums and 6 types. Its `lokf adapt` copy `.lokf/stix.yaml`, rooted on `StixObject` and `StixBundle`, is the bundle's domain schema.
* [stix_vocabularies module](datasets/stix-vocabularies-module.md) - The module `src/stix/schema/stix_vocabularies.yaml`: STIX 2.1's open vocabularies and closed enumerations as 35 enums, such as `StixIndustrySector` (`industry-sector-ov`) and `StixAgreement` (`opinion-enum`), each naming its STIX vocabulary in an annotation.
* [stix_core module](datasets/stix-core-module.md) - The module `src/stix/schema/stix_core.yaml`: the identifier and timestamp types, the shared slots such as `id`, `type` and `created_by_ref`, the abstract bases `StixObject`, `StixCommonObject`, `StixDomainObject`, `StixRelationshipObject` and `StixCyberObservableObject`, identity, the meta objects, and the dictionaries for hashes and extensions.
* [stix_sco module](datasets/stix-sco-module.md) - The module `src/stix/schema/stix_sco.yaml`: the 18 STIX cyber-observable objects, from `StixArtifact` to `StixX509Certificate`, the 12 predefined extensions such as `StixNtfsExtension`, and the types they embed.
* [stix_sdo module](datasets/stix-sdo-module.md) - The module `src/stix/schema/stix_sdo.yaml`: the STIX domain objects other than identity, such as `StixAttackPattern`, `StixIndicator`, `StixMalware` and `StixThreatActor`, and the dictionary of observed data's deprecated `objects`.
* [stix_sro module](datasets/stix-sro-module.md) - The module `src/stix/schema/stix_sro.yaml`: the two STIX relationship objects, `StixRelationship` and `StixSighting`, and the slots that join other objects, such as `source_ref`, `target_ref` and `sighting_of_ref`.
* [Copy of OASIS's STIX 2.1 JSON schemas](datasets/oasis-json-schemas-copy.md) - The copy under `upstream/` of OASIS's STIX 2.1 JSON schemas, examples and licence, taken from oasis-open/cti-stix2-json-schemas at commit `9af1db4` and checked file by file against pinned git object hashes. Tests hold the schema to it.
* [Examples and counter-examples](datasets/test-data.md) - The example data under `tests/data/`: 63 valid examples, one or more per class a concept may name as its type, and 158 counter-examples, one per constraint, each opening with a `# Fails at:` line that `tests/test_data.py` asserts.
* [Generated artefacts](datasets/generated-artefacts.md) - The files generated from the schema and committed: `project/` (JSON Schema, OWL, SHACL, JSON-LD context and the rest), the Python datamodel in `src/stix/datamodel/`, the merged schema in `docs/schema/stix.yaml`, and the adapt copy `.lokf/stix.yaml`.
* [UCO 1.5.0 term list](datasets/uco-term-list.md) - `tests/uco/uco-1.5.0-terms.txt`: the 1,176 class and property IRIs of the Unified Cyber Ontology (UCO) 1.5.0, which `scripts/extract_uco_terms.py` extracts from UCO's own files, checked by hash, and against which `tests/test_mappings.py` checks every mapping.
* [Neighbours' adapt copies](datasets/neighbour-adapt-copies.md) - The released adapt copies of nine lmodel schemas under `tests/neighbours/`, each checked against its release's checksum and attestation, against which `tests/test_schema_rules.py` holds `.lokf/stix.yaml` apart: no shared class, enum or type, and only the listed shared keys.

# References

* [STIX Version 2.1 (OASIS Standard)](references/stix-2-1-specification.md) - Structured Threat Information Expression (STIX) Version 2.1, the OASIS Standard of 10 June 2021 that the schema renders, at docs.oasis-open.org. STIX 2.1 Errata 01 exists only as a Committee Specification Draft, so the schema follows the approved standard.
* [OASIS STIX 2.1 JSON schemas](references/oasis-stix-json-schemas.md) - oasis-open/cti-stix2-json-schemas, the repository where OASIS publishes JSON schemas and examples for STIX 2.1 under the BSD-3-Clause licence, with no releases; `upstream/` copies it at a pinned commit.
* [Unified Cyber Ontology (UCO) 1.5.0](references/uco-1-5-0.md) - The Unified Cyber Ontology (UCO) 1.5.0, released by ucoProject under Apache-2.0, whose class and property IRIs the schema's mappings name under UCO's own namespaces, such as `https://ontology.unifiedcyberontology.org/uco/observable/`.

# Glossary

* [STIX Domain Object (SDO)](glossary/domain-object.md) - In STIX, a STIX Domain Object (SDO) is a higher-level concept of threat intelligence, such as a campaign, an indicator or a threat actor. The schema renders each as a subclass of `StixDomainObject`, which a knowledge concept may name as its type.
* [STIX Relationship Object (SRO)](glossary/relationship-object.md) - In STIX, a STIX Relationship Object (SRO) links other objects: `StixRelationship` joins a source to a target by a relationship type, and `StixSighting` records that a domain object was seen.
* [STIX Cyber-observable Object (SCO)](glossary/cyber-observable-object.md) - In STIX, a STIX Cyber-observable Object (SCO) records a fact observed on a network or host, such as a file, an IP address or a process. The schema renders the eighteen as subclasses of `StixCyberObservableObject`.
* [STIX bundle](glossary/bundle.md) - In STIX, a bundle carries a set of STIX objects together for transport, and is not itself a STIX object. The schema renders it as `StixBundle`, the tree root, whose `objects` may be any concrete STIX object class.
* [Open vocabulary](glossary/open-vocabulary.md) - In STIX, an open vocabulary (a name ending in `-ov`) suggests values for a property but accepts any other string, while a closed enumeration (`-enum`) does not. The schema renders an open vocabulary as an enum that a slot names beside `string`.
* [STIX identifier](glossary/stix-identifier.md) - In STIX, every object's `id` is its type name, two hyphens and a UUID, such as `indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f`. The schema types it as `stix_identifier`, and each class narrows it to its own type prefix.
* [Marking definition](glossary/marking-definition.md) - In STIX, a marking definition states a data marking, such as a copyright statement or a Traffic Light Protocol (TLP) level, that objects apply through `object_marking_refs` or granular markings. The schema renders it as `StixMarkingDefinition`.
* [Extension](glossary/extension.md) - In STIX, an object's `extensions` dictionary holds its extensions: the predefined extensions of some cyber-observable objects, such as `ntfs-ext`, and extensions an extension definition (`StixExtensionDefinition`) defines, keyed by that definition's identifier.

# Explanations

* [Closed classes and custom content](explanations/closed-classes-and-custom-content.md) - Why the schema's classes are closed, so that STIX's custom properties and custom objects validate only once a schema that imports this one declares them, as lmodel/attack does for MITRE's `x_mitre_` properties.
* [Scope, influences and mappings](explanations/scope-influences-and-mappings.md) - What the schema models (STIX 2.1 at the OASIS Standard of 10 June 2021) and leaves out (the pattern grammar, custom content, Errata 01), what shaped it, and its mappings to the Unified Cyber Ontology (UCO) 1.5.0.
* [Element names and shared keys](explanations/element-names-and-shared-keys.md) - Why every class and enum carries the `Stix` prefix while STIX's property names stay as keys, how the adapt copy renames the keys LOKF defines, and which keys it still shares with released lmodel copies, such as `subject` and `value`.
* [Departures from OASIS's JSON schemas](explanations/departures-from-the-json-schemas.md) - Where the schema follows the OASIS Standard rather than OASIS's JSON schemas: the IPv6 pattern's lost escapes, the at-least-one rules, granular markings, a marking definition's created, the targets of three references, and four vocabularies; and the rules no generated validator checks.

# Playbooks

* [Regenerate and test](playbooks/regenerate-and-test.md) - How to change the schema: edit a module under `src/stix/schema/`, then run `just gen-project`, `just gen-doc` and `just lokf-adapt`, commit the output, and run `just lint` and `just test`.
* [Validate STIX data](playbooks/validate-stix-data.md) - How to validate a STIX bundle or object with `linkml-validate` (`-C StixBundle`, or the object's class), or with `project/jsonschema/stix.schema.json`, and why to validate before loading data into the generated Python models.
* [Update the upstream pins](playbooks/update-upstream-pins.md) - How to move the schema to a new commit of OASIS's STIX JSON schemas when the upstream watch reports a change: replace `upstream/` whole, move the pins in `scripts/check_upstream_release.py` and the schema header, and run the tests.
* [Extend the schema with custom properties](playbooks/extend-with-custom-properties.md) - How to validate STIX data that carries custom properties or custom objects: write a LinkML schema that imports this one, declare each `x_` property as a slot of a subclass, and each custom object as a class with its own `type` and `id` pattern.
* [Release](playbooks/release.md) - How a release is made: entries under `## [Unreleased]` in CHANGELOG.md, a releasing commit type, and the merge to main, after which semantic-release tags the version and the knowledge release attaches `schema-<tag>-stix.yaml` and the bundle.
* [Knowledge sources](playbooks/knowledge-sources.md) - The map of where this bundle's knowledge comes from: each repository path the librarian reads, the classes it yields and how to re-check it, and the paths it leaves out on purpose, with the reason.

# Policies

* [Security policy](policies/security-policy.md) - How to report a vulnerability (GitHub's private vulnerability reporting), which release receives fixes (the latest), what executes in the repository and what holds each surface, the ruleset on `main`, and the two repository settings that are not yet in force.
* [Licence and attribution](policies/license-and-attribution.md) - The repository's licences: Apache-2.0 for the schema and code, CC BY 4.0 for the knowledge bundle, BSD-3-Clause for OASIS's JSON schemas and examples under `upstream/`, and the STIX specification cited, never copied.
* [AI covenant](policies/ai-covenant.md) - The rules for AI-assisted contributions: the contributor owns what they submit, an element says what STIX says and cites its section, the specification's text is never copied, `upstream/` is never edited, and the scheduled librarian's changes always go through a person's review.

# Workflows

* [Build and test (main.yaml)](workflows/main.md) - The Build and test workflow, `.github/workflows/main.yaml`: on a push to main and on every pull request, it runs `just test` on Python 3.10 to 3.14, and on 3.13 also `just lint` and `just lokf-adapt-check`.
* [Lint and docs (lint-and-docs.yaml)](workflows/lint-and-docs.md) - The Lint & docs workflow, `.github/workflows/lint-and-docs.yaml`: ShellCheck, actionlint, the word budgets of CONTRIBUTING.md and SECURITY.md, markdownlint, lychee and codespell, on pull requests, on main and every Monday.
* [Upstream watch (upstream-watch.yaml)](workflows/upstream-watch.md) - The Upstream watch workflow, `.github/workflows/upstream-watch.yaml`: every Monday it runs `scripts/check_upstream_release.py`, and on a finding opens or updates one issue.
* [Semantic release (semantic-release.yml)](workflows/semantic-release.md) - The Semantic release workflow, `.github/workflows/semantic-release.yml`: on a pull request to main it plans the release, and on a push to main it releases with semantic-release and dispatches the knowledge release.
* [Knowledge Librarian (knowledge-librarian.yaml)](workflows/knowledge-librarian.md) - The Knowledge Librarian workflow, `.github/workflows/knowledge-librarian.yaml`: every Monday it runs the ktl-librarian skill, pinned to KTL v0.59.0, with no write token, and opens a pull request with what changed; inert until `KNOWLEDGE_LIBRARIAN_ENABLED` is `true`.
* [Knowledge Registrar (knowledge-registrar.yaml)](workflows/knowledge-registrar.md) - The Knowledge Registrar workflow, `.github/workflows/knowledge-registrar.yaml`: the gate on every pull request that touches `.lokf/`, which validates the bundle, checks its references and conventions, and checks that each person's confirmation is backed by a review or a signed commit.
* [Knowledge Release (knowledge-release.yaml)](workflows/knowledge-release.md) - The Knowledge Release workflow, `.github/workflows/knowledge-release.yaml`: on a published release, once `KNOWLEDGE_RELEASE_ENABLED` is `true`, it attaches the bundle, the Copilot skill and the schema copy `schema-<tag>-stix.yaml`, each with a checksum and an attestation.
* [Knowledge sync (knowledge-sync.yaml)](workflows/knowledge-sync.md) - The Knowledge sync workflow, `.github/workflows/knowledge-sync.yaml`: every Monday it checks whether a newer KTL release changes the sidecar's copies or the skills pin, and opens one pull request that moves them together.
* [Knowledge website (knowledge-website.yaml)](workflows/knowledge-website.md) - The Knowledge website workflow, `.github/workflows/knowledge-website.yaml`: it builds and link-checks the site on every change to its inputs, and deploys it to GitHub Pages from main once `KNOWLEDGE_WEBSITE_ENABLED` is `true`.
