# Contributing to stix

*This file is a checklist, not a design log. Each rule is a line or two that links to where its reasoning lives: a code comment, a workflow header, or a linked page. `lint-and-docs.yaml` holds the file to a word budget so it stays that way.*

## What this project is

A LinkML schema of Structured Threat Information Expression (STIX) Version 2.1, the OASIS Standard for exchanging cyber threat intelligence. STIX JSON validates against it unchanged, and a knowledge bundle can type its concepts with STIX's domain objects.

| Path | Holds |
| --- | --- |
| `src/stix/schema/stix_*.yaml` | The schema's modules. Edit these. |
| `src/stix/schema/stix.yaml` | The umbrella schema, which imports the modules and holds the bundle. |
| `upstream/` | OASIS's JSON schemas, examples and licence at the pinned commit. Never edit. |
| `src/stix/datamodel/`, `project/`, `docs/schema/` | Artefacts generated from the schema. |
| `docs/` | The website's own pages. |
| `tests/` | Python tests, and valid and invalid example data. |
| `.lokf/knowledge/` | This repository's knowledge bundle. |

## Development setup

You need Python 3.10+, [uv](https://docs.astral.sh/uv/) and [just](https://github.com/casey/just).

```bash
git clone https://github.com/lmodel/stix.git
cd stix
uv sync --group dev
just --list
```

### Agent skills (optional, only for this repo's `.lokf/` bundle)

The bundle is maintained with the Knowledge Trust Ladder (KTL) skills, **installed, never committed**; continuous integration (CI) installs the librarian skill at run time, pinned to a release. [The install page](https://w3id.org/ktl/docs/install/) lists every route; with npm:

```bash
npx skills add noelmcloughlin/knowledge-trust-ladder --skill ktl-librarian --yes   # derive concepts
npx skills add noelmcloughlin/knowledge-trust-ladder --skill ktl-curator --yes     # confirm them as a person
```

## Before opening a pull request

- **Edit a module, then regenerate.** Run `just gen-project`, `just gen-doc` and `just lokf-adapt`, and commit the output; `src/stix/datamodel/`, `docs/schema/` and `.lokf/stix.yaml` are generated.
- **Render what STIX 2.1 defines**, name its section in the pull request, and copy none of its text ([AI_COVENANT.md](AI_COVENANT.md)). `tests/test_upstream.py` holds the schema to OASIS's JSON schemas.
- **Leave `upstream/` as OASIS published it.** Replace it whole from one commit of oasis-open/cti-stix2-json-schemas, moving the pins in `scripts/check_upstream_release.py` and the schema header; `upstream-watch.yaml` checks it.
- **Keep names apart.** A host imports this adapt copy beside the Linked Open Knowledge Format (LOKF) schema and the released neighbours' copies in `tests/neighbours/`, where a shared name carries one Internationalized Resource Identifier (IRI); `tests/test_schema_rules.py` checks.
- **Run the tests**: `just test` (schema generation, `pytest` and the examples under `tests/data/`). Example data goes in `tests/data/valid/` and `tests/data/invalid/`, named `ClassName-suffix.yaml`, with an invalid example per constraint.
- **Follow the schema's conventions**: UpperCamelCase classes and enums with the `Stix` prefix, STIX's own property names as top-level slots with a `stix:` slot URI, a short description on every element. `just lint` checks, under `.linkmllint.yaml`.
- **Run the pre-commit hooks** on what you staged (`uvx pre-commit run`): ruff, yamllint, codespell, typos and the `uv.lock` check.
- **Lock files are part of the change.** CI installs with `uv sync --locked`; a dependency edit that does not update `uv.lock` (or `.lokf/uv.lock`) fails the run.
- **Knowledge-bundle changes**: `cd .lokf && just lokf-validate` must pass, and `knowledge-registrar.yaml` runs on any `.lokf/**` change.
- **`lint-and-docs.yaml` runs** ShellCheck, actionlint, markdownlint (`.markdownlint-cli2.jsonc`), lychee (`lychee.toml`) and codespell over every `*.md`.
- **Actions are pinned to commit hashes**, the version in a trailing comment, and bumped by Dependabot, never by hand to a tag.
- **The skills pin moves with the sidecar copies.** When moving `TRUST_LADDER_SKILLS_REF` in `.github/workflows/knowledge-librarian.yaml`, copy the other `knowledge-*.yaml` workflows and `.lokf/scripts/` and `.lokf/m365/` from that release's `skills/ktl-sidecar/templates/` in the same pull request.
- **If your change alters behaviour** (not just wording), add an entry under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md).
- Keep changes focused, and fill in the pull request template.

## Code of conduct

The [Contributor Covenant](CODE_OF_CONDUCT.md) applies.

## Using AI tools

Artificial intelligence (AI) assistance is welcome; [AI_COVENANT.md](AI_COVENANT.md) sets the rules, for people and the scheduled `knowledge-librarian` agent alike. You are the author of what you submit, and a claim about what STIX defines must be checked against the specification.

## Reporting issues

Use the [issue tracker](https://github.com/lmodel/stix/issues) for problems with the schema and requests for new elements. A problem in STIX itself or in OASIS's JSON schemas belongs with the [OASIS CTI Technical Committee](https://github.com/oasis-open/cti-stix2-json-schemas/issues).

## Releasing (maintainers)

- Write `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md) as you go; the release job refuses an empty one (`.github/scripts/changelog-release.mjs check`).
- Type the commit ([Conventional Commits](https://www.conventionalcommits.org/)) for what the change *is*. Only `feat:`, `fix:`, `security:` and a breaking `!` start a release; other types leave their entries for the next release that does. A pull request that would release must carry a releasing type in its title too, since a squash merge takes its subject from it.
- On merge, [`semantic-release.yml`](.github/workflows/semantic-release.yml) retitles the section to `## [X.Y.Z] - YYYY-MM-DD`, commits `CHANGELOG.md`, tags `vX.Y.Z` and publishes the GitHub Release. No file is bumped. Once `KNOWLEDGE_RELEASE_ENABLED` is `true`, it dispatches `.github/workflows/knowledge-release.yaml`, which attaches the schema copy and the bundle when the bundle or the schema changed.
- That step runs behind the `release` GitHub Environment; configure required reviewers on it in Settings → Environments, or every qualifying merge is released unattended.
- Below 1.0.0: push the `v0.0.0` baseline tag on `main` before the first releasing merge, which then releases 0.1.0; both release jobs refuse to run without a `v*` tag, as semantic-release would otherwise start at 1.0.0. `.releaserc.json` maps `breaking: true` to `minor`; reaching 1.0.0 means removing that rule in a pull request of its own.
- A branch rule requiring pull requests, status checks or signed commits would reject the release job's own push to `main`; leave them off. [SECURITY.md](SECURITY.md) says what holds `main` instead, and the shared design is on [KTL's releasing page](https://github.com/noelmcloughlin/knowledge-trust-ladder/blob/main/docs/releasing.md).

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE). OASIS's JSON schemas and examples under `upstream/` are under their BSD-3-Clause licence; [NOTICE](NOTICE) lists them, so update it when you add something new from elsewhere.
