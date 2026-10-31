---
type: Policy
id: https://w3id.org/lmodel/stix/knowledge/policies/ai-covenant
title: AI covenant
description: "The rules for AI-assisted contributions: the contributor owns what they submit, an element says what STIX says and cites its section, the specification's text is never copied, `upstream/` is never edited, and the scheduled librarian's changes always go through a person's review."
genre: reference
resource: AI_COVENANT.md
sources:
  - id: ai_covenant.md
    resource: AI_COVENANT.md
    title: the note specific to this project and the repository-owned automation
  - resource: CODE_OF_CONDUCT.md
    title: the Contributor Covenant
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# AI covenant

`AI_COVENANT.md` makes the contributor the author of whatever an AI tool helped write.[^ai_covenant.md] For this project it adds four rules:

- An element says what STIX says: cite the section of STIX 2.1 it renders, and never give a STIX term a meaning its source lacks.
- The specification is OASIS's text: cite it, never copy it.
- `upstream/` is upstream text: replace it whole from one commit, never edit it.
- The namespace is this project's: everything lives under `stix:`, and STIX's property names stay as keys.

The scheduled librarian commits under a bot identity, opens a pull request a person must approve, and runs with no write token; a `human:` verdict records only what that person said.

[^ai_covenant.md]: AI_COVENANT.md, the note specific to this project and the repository-owned automation
