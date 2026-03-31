## Add your own just recipes here. This is imported by the main justfile.

# Overriding recipes from the root justfile by adding a recipe with the same
# name in this file is not possible until a known issue in just is fixed,
# https://github.com/casey/just/issues/2540

[group('model development')]
gen-stix-pattern-parser:
	-mkdir -p src/stix/pattern/antlr
	@if [ -z "${ANTLR4_JAR:-}" ]; then \
		echo "Set ANTLR4_JAR to a local antlr-4.x-complete.jar path before running this recipe."; \
		exit 1; \
	fi
	@echo "Note: keep ANTLR jar version compatible with antlr4-python3-runtime (<4.10 due LinkML dependency constraints)."
	@TMP_DIR="$(mktemp -d /tmp/stixpattern.XXXXXX)"; \
	TMP_G4="$TMP_DIR/STIXPattern.g4"; \
	trap 'rm -rf "$TMP_DIR"' EXIT; \
	curl -fsSL https://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/master/pattern_grammar/STIXPattern.g4 -o "$TMP_G4"; \
	uv run java -jar "$ANTLR4_JAR" \
		-Xexact-output-dir \
		-Dlanguage=Python3 \
		-visitor \
		-no-listener \
		-o src/stix/pattern/antlr \
		"$TMP_G4"

