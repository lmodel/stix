## Add your own just recipes here. This is imported by the main justfile.

# Overriding recipes from the root justfile by adding a recipe with the same
# name in this file is not possible until a known issue in just is fixed,
# https://github.com/casey/just/issues/2540

# Runs the standardized Python test flow from justfile (_test-python).
[group('model development')]
test-custom:
	# Use this entrypoint for project-level test automation hooks.
	just _test-python


# Runs only the upstream example-focused tests for quick targeted checks.
[group('model development')]
test-upstream-examples:
	uv run python -m pytest -q tests/data/test_upstream_examples.py

