"""Checks the upstream watch's decisions against stubbed answers.

scripts/check_upstream_release.py asks the GitHub API about
oasis-open/cti-stix2-json-schemas and reads docs.oasis-open.org's folder
listings. These tests replace its one network call, `_get`, with a table of
answers, so they run offline. They show what the report says when master
changes, adds or drops a file, the licence changes, OASIS publishes another
edition or approves the errata, the copy drifts, or the network fails.
"""

import importlib.util
import json
import shutil
import urllib.error
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
SCRIPT = ROOT / "scripts" / "check_upstream_release.py"
HEAD = "5" * 40


@pytest.fixture
def watch():
    """A fresh copy of the script, so no test sees another's answers."""
    spec = importlib.util.spec_from_file_location("watch_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def listing(names):
    """A directory listing as docs.oasis-open.org serves it."""
    links = "".join(f'<a href="{n}/">{n}/</a>' for n in sorted(names))
    return f'<html><body><a href="../">../</a><a href="/cti/stix/">self</a>{links}</body></html>'


def _answers(watch, head):
    """What the sources answer when nothing has changed since the pin, with
    master at `head`, keyed by the address the script asks."""
    api = watch.API
    tree = [
        {"path": p, "type": "blob", "sha": s} for p, s in watch.PINNED_BLOBS.items()
    ]
    tree.append({"path": "README.md", "type": "blob", "sha": "6" * 40})
    return {
        f"{api}/commits/{watch.BRANCH}": {"sha": head},
        f"{api}/git/trees/{head}?recursive=1": {"truncated": False, "tree": tree},
        watch.DOCS: listing(watch.KNOWN_EDITIONS),
        f"{watch.DOCS}v2.1/": listing(watch.KNOWN_STAGES),
        f"{watch.DOCS}v2.1/errata01/": listing(watch.KNOWN_ERRATA_STAGES),
    }


def _stub(watch, answers):
    """Make `_get` answer from the table: an exception is raised, a missing
    address is a 404, a string is a page, and anything else is JSON."""

    def get(url):
        if url not in answers:
            raise urllib.error.HTTPError(url, 404, "Not Found", None, None)
        answer = answers[url]
        if isinstance(answer, Exception):
            raise answer
        if isinstance(answer, str):
            return answer.encode()
        return json.dumps(answer).encode()

    watch._get = get


def _run(watch, tmp_path):
    report = tmp_path / "report.md"
    code = watch.main(["--report", str(report)])
    return code, report.read_text(encoding="utf-8")


def _tree(answers, watch, head=HEAD):
    return answers[f"{watch.API}/git/trees/{head}?recursive=1"]["tree"]


def test_nothing_changed(watch, tmp_path):
    """With master at the pin and no new edition, the watch reports the copy
    current and exits 0."""
    _stub(watch, _answers(watch, watch.PINNED_COMMIT))
    code, text = _run(watch, tmp_path)
    assert code == 0, text
    assert (
        f"{len(watch.PINNED_BLOBS)} of {len(watch.PINNED_BLOBS)} copied files match"
        in text
    )
    assert "master has not moved." in text
    assert "Errata 01 is still a committee draft" in text


def test_master_moved_without_touching_the_copy(watch, tmp_path):
    """A new commit that changes only files outside the copy is no reason to fail."""
    _stub(watch, _answers(watch, HEAD))
    code, text = _run(watch, tmp_path)
    assert code == 0, text
    assert "master moved, but no copied file" in text


def test_a_changed_an_added_and_a_dropped_file(watch, tmp_path):
    answers = _answers(watch, HEAD)
    tree = _tree(answers, watch)
    changed, dropped = "schemas/sdos/tool.json", "examples/infrastructure.json"
    for entry in tree:
        if entry["path"] == changed:
            entry["sha"] = "7" * 40
    tree[:] = [e for e in tree if e["path"] != dropped]
    tree.append({"path": "schemas/sdos/asset.json", "type": "blob", "sha": "8" * 40})
    _stub(watch, answers)
    code, text = _run(watch, tmp_path)
    assert code == 1
    assert f"**master changes 1 file(s):** `{changed}`." in text
    assert f"**master drops 1 file(s):** `{dropped}`." in text
    assert "**master adds 1 file(s):** `schemas/sdos/asset.json`." in text


def test_a_changed_licence(watch, tmp_path):
    answers = _answers(watch, HEAD)
    for entry in _tree(answers, watch):
        if entry["path"] == "LICENSE":
            entry["sha"] = "9" * 40
    _stub(watch, answers)
    code, text = _run(watch, tmp_path)
    assert code == 1
    assert "**master changes the licence.**" in text


def test_a_new_edition_and_an_approved_errata(watch, tmp_path):
    answers = _answers(watch, watch.PINNED_COMMIT)
    answers[watch.DOCS] = listing(watch.KNOWN_EDITIONS | {"v2.2"})
    answers[f"{watch.DOCS}v2.1/errata01/"] = listing(watch.KNOWN_ERRATA_STAGES | {"os"})
    _stub(watch, answers)
    code, text = _run(watch, tmp_path)
    assert code == 1
    assert f"a new edition folder, `{watch.DOCS}v2.2/`" in text
    assert f"a new Errata 01 stage, `{watch.DOCS}v2.1/errata01/os/`" in text


def test_a_drifted_copy(watch, tmp_path, monkeypatch):
    """A copied file that differs from its pin, and a file nobody pinned, are
    reported without any network."""
    copy = tmp_path / "upstream"
    shutil.copytree(watch.COPY, copy)
    (copy / "schemas" / "sdos" / "tool.json").write_text("{}\n", encoding="utf-8")
    (copy / "schemas" / "extra.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(watch, "COPY", copy)
    _stub(watch, _answers(watch, watch.PINNED_COMMIT))
    code, text = _run(watch, tmp_path)
    assert code == 1
    assert "`upstream/schemas/sdos/tool.json` differs from the pinned blob" in text
    assert "`upstream/schemas/extra.json` is in the copy but not pinned" in text


def test_a_network_failure_still_writes_a_report(watch, tmp_path):
    """A check that cannot reach its source is reported as unfinished, sets
    attention, and leaves the other checks to run."""
    answers = _answers(watch, watch.PINNED_COMMIT)
    answers[watch.DOCS] = urllib.error.URLError("Connection refused")
    _stub(watch, answers)
    code, text = _run(watch, tmp_path)
    assert code == 1
    assert (
        "**The edition check could not finish: <urlopen error Connection refused>.**"
        in text
    )
    assert "master has not moved." in text


def test_the_token_never_follows_a_redirect(watch, monkeypatch):
    """The token goes to api.github.com alone, in a header urllib drops on a
    redirect, and never to docs.oasis-open.org."""
    seen = []

    class Answer:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b"{}"

    def urlopen(req, timeout):
        seen.append(req)
        return Answer()

    monkeypatch.setenv("GITHUB_TOKEN", "secret")
    monkeypatch.setattr(watch.urllib.request, "urlopen", urlopen)
    watch._get(f"{watch.API}/commits/master")
    watch._get(watch.DOCS)
    api, docs = seen
    assert api.unredirected_hdrs.get("Authorization") == "Bearer secret"
    assert "Authorization" not in api.headers
    assert (
        "Authorization" not in docs.unredirected_hdrs
        and "Authorization" not in docs.headers
    )
