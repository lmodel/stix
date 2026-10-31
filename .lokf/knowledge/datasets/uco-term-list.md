---
type: Dataset
id: https://w3id.org/lmodel/stix/knowledge/datasets/uco-term-list
title: UCO 1.5.0 term list
description: "`tests/uco/uco-1.5.0-terms.txt`: the 1,176 class and property IRIs of the Unified Cyber Ontology (UCO) 1.5.0, which `scripts/extract_uco_terms.py` extracts from UCO's own files, checked by hash, and against which `tests/test_mappings.py` checks every mapping."
genre: reference
resource: tests/uco/uco-1.5.0-terms.txt
derivedFrom:
  - https://w3id.org/lmodel/stix/knowledge/references/uco-1-5-0
sources:
  - id: extract_uco_terms.py
    resource: scripts/extract_uco_terms.py
    title: the docstring and the pins
  - id: test_mappings.py
    resource: tests/test_mappings.py
    title: the tests
  - resource: tests/uco
    title: the term list
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# UCO 1.5.0 term list

`tests/uco/uco-1.5.0-terms.txt` lists 1,176 IRIs, one to a line: every OWL class, object property and datatype property that UCO 1.5.0's fifteen namespace files declare.[^extract_uco_terms.py] `scripts/extract_uco_terms.py` writes it. It downloads those files from ucoProject/UCO at the commit the `1.5.0` tag names, refuses any file whose git object hash differs from its pin, and parses them with rdflib.

`tests/test_mappings.py` pins the list's SHA-256 digest. It checks that every mapping in the schema names a term of UCO 1.5.0 through a prefix the schema binds.[^test_mappings.py]

[^extract_uco_terms.py]: scripts/extract_uco_terms.py, the docstring and the pins
[^test_mappings.py]: tests/test_mappings.py, the tests
