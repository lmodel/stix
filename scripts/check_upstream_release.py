#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Check the copy of OASIS's STIX 2.1 JSON schemas against its upstream.

The schema renders STIX Version 2.1, the OASIS Standard of 10 June 2021.
``upstream/`` copies the schemas, examples and licence of
oasis-open/cti-stix2-json-schemas at one commit of its master branch, since
that repository publishes no releases. Four things can change without any
change in this repository:

- master changes, adds or drops a file under ``schemas/`` or ``examples/``;
- master changes the licence;
- OASIS publishes another edition of STIX, or approves an errata of 2.1;
- the copied files drift from the files they were taken from.

This script asks the GitHub API for master's tree and compares each pinned
path's git object hash with the pin, so nothing is downloaded but listings.
It reads the folder listings of docs.oasis-open.org for STIX's editions and
for the stages of STIX 2.1 Errata 01, which exists only as a committee draft.
It compares every local file with its pin offline.

It prints a Markdown report, writes it to ``--report`` when given, and exits
0 when nothing needs a person's attention. It exits 1 when:

- a pinned file changed, was dropped, or the copy differs from its pin;
- master adds a file under ``schemas/`` or ``examples/``;
- the licence changed;
- another edition or errata stage appears;
- a check could not finish.

Set ``GITHUB_TOKEN`` to raise the API rate limit; it is sent to
api.github.com alone and never on to a redirect. Usage::

    python scripts/check_upstream_release.py [--report FILE]
"""

from __future__ import annotations

import argparse
import hashlib
import html.parser
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COPY = ROOT / "upstream"
API = "https://api.github.com/repos/oasis-open/cti-stix2-json-schemas"
DOCS = "https://docs.oasis-open.org/cti/stix/"
USER_AGENT = "lmodel-stix-upstream-check"

# The edition the schema renders. The schema header's version and source
# carry the same values, and tests/test_upstream.py holds them equal.
PINNED_EDITION = "2.1"
PINNED_SOURCE = "https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html"

# The branch and the commit the copy was taken from. Move the commit with
# PINNED_BLOBS and the schema header's json_schemas_commit annotation.
BRANCH = "master"
PINNED_COMMIT = "9af1db41b7b86c06324f899649ae83480134f66e"

# The folders the copy holds whole, and the licence beside them.
COPIED_FOLDERS = ("schemas/", "examples/")
LICENCE = "LICENSE"

# Each copied file, by its path in the repository and in upstream/, with its
# git object hash at PINNED_COMMIT.
PINNED_BLOBS = {
    "LICENSE": "8245b41473a351372c9e419213520ee964fff1e7",
    "examples/README.md": "87edfd05dbc7ddcf5ddc362c8f6a3b7f05d029a5",
    "examples/indicator-for-c2-ip-address.json": "389c7ddeda32421cafa97f0945a00fe306a4f138",
    "examples/indicator-to-campaign-relationship.json": "a221db7279322894d805b9578b843f124d358bdc",
    "examples/indicators-for-C2-with-COA.json": "69ad94eb1252d2d7c73d47b4ab2a08b9801ace9f",
    "examples/infrastructure.json": "a439d83e59af27553806aa4ac7d004c664ae8b93",
    "examples/interop-objectmarking-test.json": "8dbba8db6e859cdf60eab1aa6c14cb8f5d9a7a54",
    "examples/malicious-email-indicator-with-attachment.json": "6a058c383cfcc667b6565407408f6ea18df76279",
    "examples/threat-reports/apt1.json": "d3f235f746d94b7a3e10d16589a1f5273ee8dd28",
    "examples/threat-reports/poisonivy.json": "93347ec4106ff67c7dbcda587657d432731933e0",
    "schemas/common/binary.json": "21177bc442044630d1c938171300963a4a642a7a",
    "schemas/common/bundle.json": "d016cfdfdfd537c926b38ba9ae307604c1420509",
    "schemas/common/core.json": "e898440fa67557c7c7a94ca07db44222b7ab0ad1",
    "schemas/common/cyber-observable-core.json": "4114b945cd5584417480878c4000fb470dfa33ef",
    "schemas/common/dictionary.json": "530d4647d939d2dea7b0299c069d05cb1716c3fb",
    "schemas/common/extension-definition.json": "1dccf8846dcbf867050abb11eb237cc3070b771b",
    "schemas/common/extension.json": "f483c3e744b43db1b5aa9a109a983cc390b3177e",
    "schemas/common/external-reference.json": "3b0abe365c48c021cf118b8f81536f34d850ab19",
    "schemas/common/granular-marking.json": "56332c8163cd2702106b03eaec06c13c122dd830",
    "schemas/common/hashes-type.json": "5af86a9977d8ca66d8dc67a8141fa71feff57581",
    "schemas/common/hex.json": "ea34c1b9bc9ff63cfd3525806a5d0607ddbae009",
    "schemas/common/identifier.json": "4e9c9fc51a1a59a1ea4e365dbb7616f08d08b678",
    "schemas/common/kill-chain-phase.json": "9bb6f7ff9b48aceab806387dcb64ea8027da00fd",
    "schemas/common/language-content.json": "aae1733b43108ef1c8f86d5e52fd12cdef9ae8c9",
    "schemas/common/marking-definition.json": "32fa703ef06b5504c73aff16b443e9b5065a786b",
    "schemas/common/properties.json": "210bfd71eb684a9e7542ae11206b49e5d112b8d4",
    "schemas/common/timestamp.json": "82c697a496d18d1a97e6b413f17fe89669fa60a4",
    "schemas/common/url-regex.json": "a7a96ab7ae1e2f1c9d16319f9c0d3cf4dbab8153",
    "schemas/observables/artifact.json": "d215123e1229dfd80af67ee4fd0cbf826fc5397a",
    "schemas/observables/autonomous-system.json": "b138c2c19cbb9b2da868cdde927f93eb11885ee6",
    "schemas/observables/directory.json": "e5c85c991008be9de22bbc749456577961a90c0a",
    "schemas/observables/domain-name.json": "22804a5878a73583bfd9668f3cc46a5177d1a4d0",
    "schemas/observables/email-addr.json": "c3894d2e505686545bb770fbf603c3bc90f0a25f",
    "schemas/observables/email-message.json": "b00d9582ff0c010623169c2e30645aea8f20c69a",
    "schemas/observables/file.json": "b7af12e50fe1bffd8b565200a1dab0f38fbdddf1",
    "schemas/observables/ipv4-addr.json": "4c4e9834246f8dbf016a746cd042174177db5217",
    "schemas/observables/ipv6-addr.json": "e79dc36e55b72d2138540d3e7aa5371abe444ca3",
    "schemas/observables/mac-addr.json": "eb12e87278d524c871f5f071352c547881b484fb",
    "schemas/observables/mutex.json": "ab3c7254fa7c59300004a0cea1395ece7a370019",
    "schemas/observables/network-traffic.json": "0b70d7db65a7cd358f0cd27034929accd4f17ed5",
    "schemas/observables/process.json": "215d0e78d4a28633e0bfb343eb2740ff6e92c876",
    "schemas/observables/software.json": "fec65fcdf3f232d84ff935f0eb0938a8ebe3551a",
    "schemas/observables/url.json": "a26e8703a5929c4224f422d744e8c8cae175efef",
    "schemas/observables/user-account.json": "a66e42a3d64567a637da6e9dc7364e4d7318ab09",
    "schemas/observables/windows-registry-key.json": "a6a891b04084776d48e7d436b2eda4560141e98a",
    "schemas/observables/x509-certificate.json": "0ca0284478ad1f0babb22b99cfac20db2f1b4e2a",
    "schemas/sdos/attack-pattern.json": "e8bc659ce4655751b8c39700c5207b72572a802f",
    "schemas/sdos/campaign.json": "d5d652d0ffbbc23f56e5bc919ec198c3ce28d7b5",
    "schemas/sdos/course-of-action.json": "30bae8833473405c8e3969aac385e594dbf2c4fc",
    "schemas/sdos/grouping.json": "1aae14ffc7009b29e3c3f88368f700bc90a7bd0f",
    "schemas/sdos/identity.json": "1da402f5daadc14f14c237f00692c09e90c97b12",
    "schemas/sdos/incident.json": "08805f42c83c5c7d332b9542f076bbad5298aa41",
    "schemas/sdos/indicator.json": "a19a60f7262f6669402b1470a3819acc069e4629",
    "schemas/sdos/infrastructure.json": "7f06973b8abe7d4bd5d9bf5eae7d4aa7ce366810",
    "schemas/sdos/intrusion-set.json": "db99276bf34e96f4780cfc74a94bdb2a4d6b5ff6",
    "schemas/sdos/location.json": "7675dc12554d93e8f5ea6c772f84f51455252313",
    "schemas/sdos/malware-analysis.json": "90ead7b5cfeba870a535c097789c912e2174a7b7",
    "schemas/sdos/malware.json": "d4267b51bff12e60896ce3e51e0a7618c6b03f2c",
    "schemas/sdos/note.json": "12490b6170a76dcad0ba914cd2e9312c3bce588a",
    "schemas/sdos/observed-data.json": "9f9ce0e2738e6b8e3ea0f83ff584b68bb9cf57b4",
    "schemas/sdos/opinion.json": "a28aaa4d4a973d68ec90f24e628f5c42fe64260f",
    "schemas/sdos/report.json": "448d97f0ebabeedb08089ee059aa211c16ccaa26",
    "schemas/sdos/threat-actor.json": "fc9bd876f9ec59844f5e5b15a2924fcf6a861666",
    "schemas/sdos/tool.json": "cc47deef1bb1cd495b8e5f09fada314c0fafa997",
    "schemas/sdos/vulnerability.json": "40838e89565e807fe225890bf9d92b88f037872b",
    "schemas/sros/relationship.json": "2957c5a267df3629df23b60632e6fc8ed21bdb92",
    "schemas/sros/sighting.json": "c3ee579c1df5796b7e239259697641057d8e41be",
}

# The folders of docs.oasis-open.org/cti/stix/ (one per edition), of its
# v2.1/ folder (one per stage), and of the stages of STIX 2.1 Errata 01, as
# they stood when the copy was pinned.
KNOWN_EDITIONS = {"v1.2.1", "v2.0", "v2.1"}
KNOWN_STAGES = {
    "cs01",
    "cs02",
    "cs03",
    "csd01",
    "csd05",
    "csprd01",
    "csprd02",
    "csprd03",
    "errata01",
    "images",
    "os",
    "styles",
}
KNOWN_ERRATA_STAGES = {"csd01", "images", "styles"}


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    if url.startswith(API):
        req.add_header("Accept", "application/vnd.github+json")
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            # urllib copies ordinary headers onto a redirect, so the token goes in
            # an unredirected one and reaches api.github.com alone.
            req.add_unredirected_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


def blob_sha(path: Path) -> str:
    """The git object hash of a file, as the GitHub API reports it."""
    data = path.read_bytes()
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def _tree(ref: str) -> dict[str, str]:
    """Each file of the repository at a ref, with its git object hash."""
    answer = json.loads(_get(f"{API}/git/trees/{ref}?recursive=1"))
    if answer.get("truncated"):
        raise OSError(f"the tree at {ref} is too large for one listing")
    return {e["path"]: e["sha"] for e in answer["tree"] if e["type"] == "blob"}


class _Links(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.folders: set[str] = set()

    def handle_starttag(self, tag, attrs):
        href = dict(attrs).get("href") or ""
        if (
            tag == "a"
            and href.endswith("/")
            and "/" not in href[:-1]
            and not href.startswith(".")
        ):
            self.folders.add(href[:-1])


def _folders(url: str) -> set[str]:
    """The folder names that a directory listing links to."""
    parser = _Links()
    parser.feed(_get(url).decode("utf-8", "replace"))
    return parser.folders


def check_copy() -> tuple[list[str], bool]:
    """Report whether every copied file is the pinned blob, offline."""
    problems, matching = [], 0
    for path, sha in sorted(PINNED_BLOBS.items()):
        local = COPY / path
        if not local.is_file():
            problems.append(f"`upstream/{path}` is missing")
        elif blob_sha(local) != sha:
            problems.append(f"`upstream/{path}` differs from the pinned blob")
        else:
            matching += 1
    for local in sorted(p for p in COPY.rglob("*") if p.is_file()):
        path = local.relative_to(COPY).as_posix()
        if path not in PINNED_BLOBS:
            problems.append(f"`upstream/{path}` is in the copy but not pinned")
    report = [
        f"- {matching} of {len(PINNED_BLOBS)} copied files match their pins byte for byte."
    ]
    if problems:
        report.append(f"- **{len(problems)} problem(s) with the copy:**")
        report += [f"  - {p}" for p in problems]
    return report, bool(problems)


def check_master() -> tuple[list[str], bool]:
    """Report each pinned file that master changed or dropped, each file it
    added beside them, and a changed licence."""
    head = json.loads(_get(f"{API}/commits/{BRANCH}"))["sha"]
    report = [
        f"- Pinned commit: `{PINNED_COMMIT[:12]}` of oasis-open/cti-stix2-json-schemas; "
        f"{BRANCH} is at `{head[:12]}`."
    ]
    if head == PINNED_COMMIT:
        report.append(f"- {BRANCH} has not moved.")
        return report, False
    tree = _tree(head)
    changed = sorted(
        p
        for p, sha in PINNED_BLOBS.items()
        if p in tree and tree[p] != sha and p != LICENCE
    )
    dropped = sorted(p for p in PINNED_BLOBS if p not in tree)
    added = sorted(
        p for p in tree if p.startswith(COPIED_FOLDERS) and p not in PINNED_BLOBS
    )
    licence = LICENCE in tree and tree[LICENCE] != PINNED_BLOBS[LICENCE]
    for label, paths in (("changes", changed), ("drops", dropped), ("adds", added)):
        if paths:
            report.append(
                f"- **{BRANCH} {label} {len(paths)} file(s):** "
                + ", ".join(f"`{p}`" for p in paths)
                + "."
            )
    if licence:
        report.append(
            f"- **{BRANCH} changes the licence.** Read it before copying anything from the new commit."
        )
    attention = bool(changed or dropped or added or licence)
    if attention:
        report.append(
            "- Read the changes, decide whether the schema follows them, replace `upstream/` from "
            "one commit, and move the pins here and in the schema header."
        )
    else:
        report.append(
            f"- {BRANCH} moved, but no copied file, no file beside them and not the licence."
        )
    return report, attention


def check_edition() -> tuple[list[str], bool]:
    """Report another edition of STIX, a new stage of 2.1, or a new stage of
    STIX 2.1 Errata 01, which would mean OASIS approved it."""
    report = [f"- Pinned edition: STIX {PINNED_EDITION}, {PINNED_SOURCE}."]
    found = []
    for url, known, what in (
        (DOCS, KNOWN_EDITIONS, "edition folder"),
        (f"{DOCS}v2.1/", KNOWN_STAGES, "STIX 2.1 stage"),
        (f"{DOCS}v2.1/errata01/", KNOWN_ERRATA_STAGES, "Errata 01 stage"),
    ):
        for name in sorted(_folders(url) - known):
            found.append(f"a new {what}, `{url}{name}/`")
    if found:
        report.append(
            "- **OASIS publishes "
            + "; ".join(found)
            + ".** Read it, decide whether the schema "
            "moves to it, and move the pins."
        )
        return report, True
    report.append(
        "- docs.oasis-open.org shows no other edition, and Errata 01 is still a committee draft."
    )
    return report, False


# Each check, by the name the report gives it when it cannot finish.
CHECKS = (("copy", check_copy), ("master", check_master), ("edition", check_edition))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--report", type=Path, help="Also write the Markdown report to this file"
    )
    args = parser.parse_args(argv)
    lines, attention = [], False
    for label, check in CHECKS:
        try:
            found, needs = check()
        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            ValueError,
            KeyError,
        ) as err:
            found, needs = [f"- **The {label} check could not finish: {err}.**"], True
        lines += found
        attention = attention or needs
    text = "\n".join(lines) + "\n"
    print(text, end="")
    if args.report:
        args.report.write_text(text, encoding="utf-8")
    return 1 if attention else 0


if __name__ == "__main__":
    sys.exit(main())
