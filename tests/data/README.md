# Example data for stix

- `valid/` holds data that conforms to the schema: an example for each class
  a knowledge concept may name as its type, and more for the extensions and
  the embedded types. `tests/test_data.py` checks that each one validates.
- `invalid/` holds a counter-example for each constraint. Its first line,
  `# Fails at: <JSON pointer>`, names where the validator reports it, and the
  second says why it is invalid; `tests/test_data.py` checks both.
- `problem/` holds data the schema does not yet handle correctly, split into
  `valid/` and `invalid/`.

Name each file `ClassName-what-it-shows.yaml`: the part before the first `-`
is the class the file is validated against. OASIS's own examples sit in
`upstream/examples/`, and `tests/test_upstream.py` validates them unchanged.
