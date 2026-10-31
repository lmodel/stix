---
type: Dataset
id: https://w3id.org/lmodel/stix/knowledge/datasets/test-data
title: Examples and counter-examples
description: "The example data under `tests/data/`: 60 valid examples, one or more per class a concept may name as its type, and 152 counter-examples, one per constraint, each opening with a `# Fails at:` line that `tests/test_data.py` asserts."
genre: reference
resource: tests/data
sources:
  - id: data
    resource: tests/data
    title: the valid and invalid folders
  - id: test_data.py
    resource: tests/test_data.py
    title: the tests
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# Examples and counter-examples

`tests/data/valid/` holds 60 valid examples, and `tests/data/invalid/` holds 152 counter-examples.[^data] Each file is named after the class it is validated against, such as `StixIndicator-c2-ip.yaml`.

`tests/test_data.py` validates every file against the JSON Schema that `linkml-validate` generates.[^test_data.py] A valid example must pass. A counter-example must fail at the place its first line names, as `# Fails at: <JSON pointer>`, and its second line says why it is invalid.

The test also checks that each concrete class under `StixObject`, and `StixBundle`, has a valid example, because each is a concept type of the adapt copy. Over the examples, it checks the three rules that turn on a boolean, which no generated validator checks.

[^data]: tests/data, the valid and invalid folders
[^test_data.py]: tests/test_data.py, the tests
