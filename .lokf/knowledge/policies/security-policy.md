---
type: Policy
id: https://w3id.org/lmodel/stix/knowledge/policies/security-policy
title: Security policy
description: How to report a vulnerability (GitHub's private vulnerability reporting), which release receives fixes (the latest), what executes in the repository and what holds each surface, the ruleset on `main`, and the two repository settings that are not yet in force.
genre: reference
resource: SECURITY.md
sources:
  - id: security.md
    resource: SECURITY.md
    title: every section
  - resource: .github/dependabot.yml
    title: the update entries
generated:
  by: process:ktl-librarian
  at: "2026-10-31T11:01:57Z"
status: draft
---

# Security policy

`SECURITY.md` asks for a vulnerability to be reported through GitHub's private vulnerability reporting, not in a public issue. One person maintains the repository, so a first reply takes days. There is no bounty, and only the latest release receives fixes.[^security.md]

The repository releases the schema and the Python models generated from it. Nothing is published to PyPI. A release carries three assets, each with its `.sha256` and a build-provenance attestation: the adapt copy, the knowledge bundle as a zip and a Microsoft 365 Copilot skill zip. The upstream watch reads the tree of OASIS's repository and docs.oasis-open.org's listings. It sends the workflow's token to api.github.com alone, refuses an answer over 5 MiB, and writes nothing but its report.

The policy's table names each workflow and what holds it:

- read-only checks on pull requests;
- the release job, only on a push to `main` in the `release` Environment;
- the Pages scopes, only in the website's deploy job;
- a librarian agent with no write token.

Every workflow declares `permissions: {}`, pins its actions to commit hashes and runs harden-runner in audit mode. A ruleset on `main` blocks deletion and force-pushes and keeps the history linear. Two settings are not yet in force: required reviewers on the `release` Environment, and secret scanning with push protection.

[^security.md]: SECURITY.md, every section
