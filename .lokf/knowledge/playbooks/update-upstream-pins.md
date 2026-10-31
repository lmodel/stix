---
type: Playbook
id: https://w3id.org/lmodel/stix/knowledge/playbooks/update-upstream-pins
title: Update the upstream pins
description: "How to move the schema to a new commit of OASIS's STIX JSON schemas when the upstream watch reports a change: replace `upstream/` whole, move the pins in `scripts/check_upstream_release.py` and the schema header, and run the tests."
genre: how-to
resource: scripts/check_upstream_release.py
relatedTo:
  - https://w3id.org/lmodel/stix/knowledge/datasets/oasis-json-schemas-copy
sources:
  - id: check_upstream_release.py
    resource: scripts/check_upstream_release.py
    title: the docstring and the pins
  - resource: tests/test_watch.py
    title: the stubbed answers
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# Update the upstream pins

The upstream watch opens an issue when OASIS changes, adds or drops a copied file, changes the licence, or publishes another edition or an approved errata.[^check_upstream_release.py]

1. Read the change, and decide whether the schema follows it.
2. Replace `upstream/` whole from one commit of oasis-open/cti-stix2-json-schemas; never edit a file in it.
3. Move `PINNED_COMMIT` and `PINNED_BLOBS` in `scripts/check_upstream_release.py`, and the `json_schemas_commit` annotation and the tree address in the schema header. `tests/test_upstream.py` holds them equal.
4. Run `just test`, and update the schema where the JSON schemas changed.

[^check_upstream_release.py]: scripts/check_upstream_release.py, the docstring and the pins
