## Add your own just recipes here. This is imported by the main justfile.

# Overriding recipes from the root justfile by adding a recipe with the same
# name in this file is not possible until a known issue in just is fixed,
# https://github.com/casey/just/issues/2540

# ============ Knowledge bundle: the adapted domain schema ============

# `.lokf/schema/stix.yaml` is the copy `lokf adapt` writes from the schema so that it
# can sit beside `.lokf/schema/lokf.yaml` (`lokf adapt --help` lists the moves). The
# roots are the classes re-rooted on LOKF's Concept: StixObject, so that every
# STIX object type is a concept type, and StixBundle. lokf 0.9.0 drops the
# schema's identifier, id, for LOKF's own and refuses any class that carries
# it without descending from Concept, so rooting the domain objects alone
# fails. The recipes run the `lokf` the sidecar's floor pins (0.9.0 or
# later); LOKF_CMD runs another, such as a checkout:
# LOKF_CMD="uv run --project ../lokf lokf" just lokf-adapt
lokf_cmd := env_var_or_default("LOKF_CMD", "uv run --project .lokf lokf")
lokf_adapt_roots := "--root StixObject --root StixBundle"

# Rewrite .lokf/schema/stix.yaml from the schema (run after every schema change)
[group('knowledge bundle')]
lokf-adapt:
  {{lokf_cmd}} adapt {{source_schema_path}} {{lokf_adapt_roots}} --lokf .lokf/schema/lokf.yaml -o .lokf/schema/stix.yaml

# Fail when .lokf/schema/stix.yaml is stale against the schema or .lokf/schema/lokf.yaml
[group('knowledge bundle')]
lokf-adapt-check:
  {{lokf_cmd}} adapt {{source_schema_path}} {{lokf_adapt_roots}} --lokf .lokf/schema/lokf.yaml -o .lokf/schema/stix.yaml --check

# ============ Artefacts gen-project does not write ============

# Write one LinkML YAML with every import merged, as the copier template's recipe does
[group('model development - extended')]
gen-merged-schema:
  mkdir -p {{dest}}/linkml
  uv run gen-linkml --mergeimports -o {{dest}}/linkml/{{schema_name}}.merged.linkml.yaml {{source_schema_path}}

# Write the schema as RDF Turtle; gen-project's rdf generator is switched off in LinkML
[group('model development - extended')]
gen-rdf:
  mkdir -p {{dest}}/rdf
  uv run gen-rdf --mergeimports {{source_schema_path}} > {{dest}}/rdf/{{schema_name}}.ttl
