#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["rdflib>=7.1"]
# ///
"""List the class and property IRIs of UCO 1.5.0, for the schema's mappings.

The schema maps some STIX classes and slots to terms of the Unified Cyber
Ontology (UCO). tests/test_mappings.py checks that each mapped term exists in
UCO 1.5.0, against tests/uco/uco-1.5.0-terms.txt, which this script writes.
It downloads the fifteen namespace files of ucoProject/UCO at the commit the
1.5.0 tag names, checks each against its pinned git object hash, and lists
every IRI that a file declares an OWL class, object property or datatype
property, one to a line, sorted.

Usage::

    uv run scripts/extract_uco_terms.py [OUTPUT]

OUTPUT defaults to tests/uco/uco-1.5.0-terms.txt. Move the pinned hash in
tests/test_mappings.py with the file.
"""

from __future__ import annotations

import hashlib
import sys
import urllib.request
from pathlib import Path

from rdflib import OWL, RDF, Graph

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "tests" / "uco" / "uco-1.5.0-terms.txt"
RAW = "https://raw.githubusercontent.com/ucoProject/UCO"
UCO = "https://ontology.unifiedcyberontology.org/uco/"

# The commit tag 1.5.0 names, and each namespace file's git object hash there.
COMMIT = "7ebb3957e9e9a2e1bb9c66cd1ede8c912a726344"
PINNED_BLOBS = {
    "ontology/uco/action/action.ttl": "408bc73a0c85cb81e5df9a8d64859df2cb989b01",
    "ontology/uco/analysis/analysis.ttl": "16f6a702dbed6985ef4ab2206c8fde1718497cc7",
    "ontology/uco/configuration/configuration.ttl": "bdb1e7ea6e1b1053ca4290ae6951ac1e011eb751",
    "ontology/uco/core/core.ttl": "22ce16f1395f8dbf617a8dd1122b25912b060da4",
    "ontology/uco/identity/identity.ttl": "0f0ba6eaa29aaa337bb769c1eed6ab40b8e59234",
    "ontology/uco/location/location.ttl": "2e1cb15a9bfc5ec06ea3caba4c670074079bd829",
    "ontology/uco/marking/marking.ttl": "741c4ed6ad9e48b23331cad8284fa6c47eea77d9",
    "ontology/uco/observable/observable.ttl": "1b81df70b09d3f849c7e75684a551c428579015a",
    "ontology/uco/pattern/pattern.ttl": "cb972e32b036559cc0b3672773bd3f24ee1b8316",
    "ontology/uco/role/role.ttl": "1465b15917ea0ef70947499426fd966c95ef0193",
    "ontology/uco/time/time.ttl": "3993a505ef577882b7d655bb180eaf22a1359592",
    "ontology/uco/tool/tool.ttl": "16c61a4a46a3f705cdd80410d9d6cb5f47e6c96c",
    "ontology/uco/types/types.ttl": "5a0401292d226afcf742130a8836c6f38a00aa2d",
    "ontology/uco/victim/victim.ttl": "d7e637fa5f9dd57d647a08e102444b3b603a9ff2",
    "ontology/uco/vocabulary/vocabulary.ttl": "4862b4bab32a69e4fe3c6a0ad1de00272f5cfa8b",
}


def fetch(path: str) -> bytes:
    """A file of UCO at the pinned commit, refused unless it is the pinned blob."""
    req = urllib.request.Request(
        f"{RAW}/{COMMIT}/{path}", headers={"User-Agent": "lmodel-stix"}
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read()
    sha = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
    if sha != PINNED_BLOBS[path]:
        raise SystemExit(f"{path}: got blob {sha}, pinned {PINNED_BLOBS[path]}")
    return data


def terms() -> list[str]:
    graph = Graph()
    for path in sorted(PINNED_BLOBS):
        graph.parse(data=fetch(path), format="turtle")
    found = set()
    for kind in (OWL.Class, OWL.ObjectProperty, OWL.DatatypeProperty):
        found |= {
            str(s) for s in graph.subjects(RDF.type, kind) if str(s).startswith(UCO)
        }
    return sorted(found)


def main(argv: list[str]) -> int:
    output = Path(argv[0]) if argv else OUTPUT
    output.parent.mkdir(parents=True, exist_ok=True)
    found = terms()
    output.write_text("".join(f"{iri}\n" for iri in found), encoding="utf-8")
    print(f"{len(found)} terms written to {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
