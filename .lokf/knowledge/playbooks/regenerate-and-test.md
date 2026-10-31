---
type: Playbook
id: https://w3id.org/lmodel/stix/knowledge/playbooks/regenerate-and-test
title: Regenerate and test
description: "How to change the schema: edit a module under `src/stix/schema/`, then run `just gen-project`, `just gen-doc` and `just lokf-adapt`, commit the output, and run `just lint` and `just test`."
genre: how-to
resource: justfile
sources:
  - id: contributing.md
    resource: CONTRIBUTING.md
    title: the Before opening a pull request checklist
  - id: justfile
    resource: justfile
    title: the lint and test recipes
  - resource: .linkmllint.yaml
    title: the lint rules
generated:
  by: process:ktl-librarian
  at: "2026-10-31T02:00:22Z"
status: draft
---

# Regenerate and test

1. Edit a module under `src/stix/schema/`, never a generated file.[^contributing.md]
2. Run `just gen-project`, `just gen-doc` and `just lokf-adapt`, and commit what they write: `project/`, `src/stix/datamodel/`, `docs/schema/` and `.lokf/stix.yaml`.
3. Run `just lint`, which fails on a warning as well as an error, and `just test`, which regenerates the project into `tmp/`, runs the Python tests and runs the examples.[^justfile]
4. Add a valid example for a new class and a counter-example for a new constraint under `tests/data/`.

[^contributing.md]: CONTRIBUTING.md, the Before opening a pull request checklist
[^justfile]: justfile, the lint and test recipes
