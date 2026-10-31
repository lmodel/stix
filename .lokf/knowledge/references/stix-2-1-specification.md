---
type: Reference
id: https://w3id.org/lmodel/stix/knowledge/references/stix-2-1-specification
title: STIX Version 2.1 (OASIS Standard)
description: Structured Threat Information Expression (STIX) Version 2.1, the OASIS Standard of 10 June 2021 that the schema renders, at docs.oasis-open.org. STIX 2.1 Errata 01 exists only as a Committee Specification Draft, so the schema follows the approved standard.
genre: reference
resource: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html
sources:
  - id: schema-stix.yaml
    resource: src/stix/schema/stix.yaml
    title: the header and the comments
  - id: notice
    resource: NOTICE
    title: the first section
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# STIX Version 2.1 (OASIS Standard)

STIX Version 2.1 is the OASIS Standard of 10 June 2021, which the OASIS Cyber Threat Intelligence (CTI) Technical Committee publishes. The schema's header names it as `source`, with `version: "2.1"`.[^schema-stix.yaml] The specification is copyright OASIS Open, so the schema cites it and copies none of its text.[^notice]

The header's comments say that STIX 2.1 Errata 01 exists only as a Committee Specification Draft of 2 April 2025. The schema follows the approved standard, and the values the draft adds to four open vocabularies validate anyway. The upstream watch reports a new stage of the errata or another edition at docs.oasis-open.org.

[^schema-stix.yaml]: src/stix/schema/stix.yaml, the header and the comments
[^notice]: NOTICE, the first section
