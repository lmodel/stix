---
type: Policy
id: https://w3id.org/lmodel/stix/knowledge/policies/license-and-attribution
title: Licence and attribution
description: "The repository's licences: Apache-2.0 for the schema and code, CC BY 4.0 for the knowledge bundle, BSD-3-Clause for OASIS's JSON schemas and examples under `upstream/`, and the STIX specification cited, never copied."
genre: reference
resource: NOTICE
sources:
  - id: license
    resource: LICENSE
    title: the Apache License 2.0
  - id: notice
    resource: NOTICE
    title: every section
  - resource: upstream/LICENSE
    title: OASIS's BSD-3-Clause licence
  - resource: website/NOTICE
    title: the part adapted from the LOKF toolkit's site
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# Licence and attribution

- The schema and the code are under the Apache License 2.0.[^license]
- The knowledge bundle in `.lokf/knowledge/` is under CC BY 4.0, as its `index.md` declares.
- OASIS's JSON schemas and examples under `upstream/`, and the descriptions taken from them, are under OASIS's BSD-3-Clause licence, which `NOTICE` reproduces.[^notice]
- The STIX specification is copyright OASIS Open, with portions copyright the United States Government. The schema cites it and copies none of its text.
- The template's scaffolding is under the MIT licence of linkml-project-copier, and the sidecar's scripts and the website derive from Knowledge Trust Ladder (KTL) templates under Apache-2.0.

This is not an official OASIS project, and its use implies no endorsement by OASIS.

[^license]: LICENSE, the Apache License 2.0
[^notice]: NOTICE, every section
