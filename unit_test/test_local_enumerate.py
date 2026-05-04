"""Unit tests for the offline ``--local`` enumeration mode."""

from __future__ import annotations

import logging
import os
import textwrap
from pathlib import Path
from unittest import mock

import pytest

from gatox.caching.cache_manager import CacheManager
from gatox.cli import cli
from gatox.cli.output import Output
from gatox.enumerate.local_enumerate import (
    LocalApiStub,
    LocalEnumerator,
    discover_repos,
    parse_origin_url,
    repo_identity,
)
from gatox.workflow_graph.graph_builder import WorkflowGraphBuilder
from gatox.workflow_graph.node_factory import NodeFactory

Output(True)


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_singletons():
    """Reset the singletons that the enumeration pipeline mutates."""
    CacheManager._instance = None
    WorkflowGraphBuilder._instance = None
    NodeFactory.NODE_CACHE = {}
    yield
    CacheManager._instance = None
    WorkflowGraphBuilder._instance = None
    NodeFactory.NODE_CACHE = {}


def _write_workflow(repo_dir: Path, name: str, body: str) -> Path:
    wf_dir = repo_dir / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    path = wf_dir / name
    path.write_text(textwrap.dedent(body).lstrip("\n"), encoding="utf-8")
    return path


def _write_git_origin(repo_dir: Path, slug: str, branch: str = "main") -> None:
    git_dir = repo_dir / ".git"
    git_dir.mkdir(parents=True, exist_ok=True)
    (git_dir / "config").write_text(
        f'[remote "origin"]\n\turl = https://github.com/{slug}.git\n',
        encoding="utf-8",
    )
    (git_dir / "HEAD").write_text(f"ref: refs/heads/{branch}\n", encoding="utf-8")


# --------------------------------------------------------------------------
# parse_origin_url + repo_identity
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://github.com/foo/bar.git", ("foo", "bar")),
        ("https://github.com/foo/bar", ("foo", "bar")),
        ("git@github.com:foo/bar.git", ("foo", "bar")),
        ("ssh://git@github.com/foo/bar.git", ("foo", "bar")),
        ("https://github.com/foo/bar/", ("foo", "bar")),
        ("https://github.com/foo-bar/baz_qux.git", ("foo-bar", "baz_qux")),
    ],
)
def test_parse_origin_url_variants(url, expected):
    cfg = f'[remote "origin"]\n\turl = {url}\n'
    assert parse_origin_url(cfg) == expected


def test_parse_origin_url_ignores_non_origin_remote():
    cfg = textwrap.dedent("""
        [remote "upstream"]
            url = https://github.com/upstream/repo.git
        [remote "origin"]
            url = https://example.com/some/internal.git
        """)
    assert parse_origin_url(cfg) is None


def test_parse_origin_url_non_github_returns_none():
    cfg = '[remote "origin"]\n\turl = https://gitlab.com/foo/bar.git\n'
    assert parse_origin_url(cfg) is None


def test_repo_identity_uses_origin(tmp_path: Path):
    repo = tmp_path / "checkout"
    repo.mkdir()
    _write_git_origin(repo, "alpha/beta", branch="dev")
    slug, branch, synthetic = repo_identity(repo)
    assert slug == "alpha/beta"
    assert branch == "dev"
    assert synthetic is False


def test_repo_identity_falls_back_to_synthetic(tmp_path: Path):
    repo = tmp_path / "no-git-here"
    repo.mkdir()
    slug, branch, synthetic = repo_identity(repo)
    assert slug == "local::no-git-here"
    assert branch == "main"
    assert synthetic is True


def test_repo_identity_synthetic_when_origin_is_non_github(tmp_path: Path):
    repo = tmp_path / "weird"
    repo.mkdir()
    git_dir = repo / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text(
        '[remote "origin"]\n\turl = https://gitlab.com/x/y.git\n',
        encoding="utf-8",
    )
    (git_dir / "HEAD").write_text("ref: refs/heads/trunk\n", encoding="utf-8")
    slug, branch, synthetic = repo_identity(repo)
    assert slug == "local::weird"
    assert branch == "trunk"
    assert synthetic is True


# --------------------------------------------------------------------------
# discover_repos
# --------------------------------------------------------------------------


def test_discover_single_repo(tmp_path: Path):
    repo = tmp_path
    _write_workflow(repo, "ci.yml", "name: x\non: push\njobs: {}\n")
    found = discover_repos(repo)
    assert found == [repo]


def test_discover_multi_repo_dir(tmp_path: Path):
    a = tmp_path / "alpha"
    b = tmp_path / "bravo"
    c = tmp_path / "charlie"
    a.mkdir()
    b.mkdir()
    c.mkdir()
    _write_workflow(a, "a.yml", "name: a\non: push\njobs: {}\n")
    _write_workflow(b, "b.yml", "name: b\non: push\njobs: {}\n")
    # charlie has no workflows -> excluded
    found = discover_repos(tmp_path)
    assert sorted(found) == sorted([a, b])


def test_discover_recursive(tmp_path: Path):
    nested = tmp_path / "outer" / "inner" / "repo"
    nested.mkdir(parents=True)
    _write_workflow(nested, "x.yml", "name: x\non: push\njobs: {}\n")
    # Non-recursive must miss the nested repo
    assert discover_repos(tmp_path) == []
    # Recursive picks it up
    assert discover_repos(tmp_path, recursive=True) == [nested]


def test_discover_missing_root_raises(tmp_path: Path):
    missing = tmp_path / "nope"
    with pytest.raises(FileNotFoundError):
        discover_repos(missing)


# --------------------------------------------------------------------------
# LocalApiStub records skips
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_local_api_stub_skip_logging(caplog):
    caplog.set_level(logging.DEBUG, logger="gatox.enumerate.local_enumerate")
    stub = LocalApiStub()
    await stub.retrieve_raw_action("foo/bar", "action.yml", "main")
    await stub.retrieve_repo_file("foo/bar", "x.yml", "v1")
    await stub.get_all_environment_protection_rules("foo/bar")
    await stub.get_secrets("foo/bar")

    assert stub.is_app_token() is False
    assert stub.skip_counter["external_action_resolution"] == 1
    assert stub.skip_counter["callee_workflow_resolution"] == 1
    assert stub.skip_counter["branch_protection_rules"] == 1
    assert stub.skip_counter["repository_secrets"] == 1

    msgs = " ".join(rec.message for rec in caplog.records)
    assert "external_action_resolution" in msgs
    assert "callee_workflow_resolution" in msgs
    assert "branch_protection_rules" in msgs
    assert "repository_secrets" in msgs


@pytest.mark.asyncio
async def test_local_api_stub_resolves_registered_repo(tmp_path):
    """Intra-scan-set composite actions and reusable workflows resolve from
    the filesystem instead of falling through to the skip path."""
    repo_dir = tmp_path / "myrepo"
    (repo_dir / ".github" / "actions" / "setup").mkdir(parents=True)
    (repo_dir / ".github" / "actions" / "setup" / "action.yml").write_text(
        "name: setup\nruns:\n  using: composite\n  steps: []\n", encoding="utf-8"
    )
    (repo_dir / ".github" / "workflows").mkdir(parents=True)
    (repo_dir / ".github" / "workflows" / "reusable.yml").write_text(
        "on: workflow_call\njobs: {}\n", encoding="utf-8"
    )

    stub = LocalApiStub()
    stub.register_repo_root("foo/bar", repo_dir)

    # Composite action lookup resolves directory -> action.yml.
    contents = await stub.retrieve_raw_action(
        "foo/bar", ".github/actions/setup", "main"
    )
    assert contents is not None and "composite" in contents

    # Direct file lookup also works.
    contents = await stub.retrieve_repo_file(
        "foo/bar", ".github/workflows/reusable.yml", "main"
    )
    assert contents is not None and "workflow_call" in contents

    # No skip counter increments for the local hits.
    assert stub.skip_counter["external_action_resolution"] == 0
    assert stub.skip_counter["callee_workflow_resolution"] == 0

    # Unregistered repo still skips.
    other = await stub.retrieve_raw_action("other/repo", "action.yml", "main")
    assert other is None
    assert stub.skip_counter["external_action_resolution"] == 1


@pytest.mark.asyncio
async def test_local_api_stub_rejects_path_traversal(tmp_path):
    repo_dir = tmp_path / "r"
    repo_dir.mkdir()
    (tmp_path / "secret.txt").write_text("DO NOT LEAK", encoding="utf-8")

    stub = LocalApiStub()
    stub.register_repo_root("foo/bar", repo_dir)

    # Relative parent traversal must not escape the repo root.
    contents = await stub.retrieve_raw_action("foo/bar", "../secret.txt", "main")
    assert contents is None
    # Absolute paths are rejected too.
    contents = await stub.retrieve_raw_action(
        "foo/bar", str(tmp_path / "secret.txt"), "main"
    )
    assert contents is None


# --------------------------------------------------------------------------
# End-to-end LocalEnumerator
# --------------------------------------------------------------------------


PWN_WORKFLOW = """
name: vulnerable
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo "${{ github.event.pull_request.title }}"
"""


@pytest.mark.asyncio
async def test_local_enumerator_scans_single_repo(tmp_path: Path, caplog):
    repo = tmp_path / "alpha"
    repo.mkdir()
    _write_git_origin(repo, "owner/alpha")
    _write_workflow(repo, "ci.yml", PWN_WORKFLOW)

    caplog.set_level(logging.DEBUG, logger="gatox.enumerate.local_enumerate")
    enumerator = LocalEnumerator(repo)
    repos = await enumerator.enumerate()

    assert len(repos) == 1
    assert repos[0].name == "owner/alpha"
    # injection visitor should produce at least one finding for this YAML
    assert repos[0].get_risks(), "expected the injection visitor to flag findings"

    # banner skip counter should include run_log_analysis at minimum
    assert enumerator.skip_counter["run_log_analysis"] >= 1
    # debug-level skip lines were emitted
    assert any(
        "[local] skipping run-log analysis" in rec.message for rec in caplog.records
    )


@pytest.mark.asyncio
async def test_local_enumerator_multi_repo_dir(tmp_path: Path):
    a = tmp_path / "alpha"
    b = tmp_path / "bravo"
    a.mkdir()
    b.mkdir()
    _write_git_origin(a, "owner/alpha")
    _write_git_origin(b, "owner/bravo")
    _write_workflow(a, "ci.yml", PWN_WORKFLOW)
    _write_workflow(b, "ci.yml", PWN_WORKFLOW)

    enumerator = LocalEnumerator(tmp_path)
    repos = await enumerator.enumerate()

    names = sorted(r.name for r in repos)
    assert names == ["owner/alpha", "owner/bravo"]


@pytest.mark.asyncio
async def test_local_enumerator_synthetic_name(tmp_path: Path):
    repo = tmp_path / "no-origin"
    repo.mkdir()
    _write_workflow(
        repo,
        "lint.yml",
        "name: lint\non:\n  push:\njobs:\n  one:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
    )
    enumerator = LocalEnumerator(repo)
    repos = await enumerator.enumerate()
    assert len(repos) == 1
    assert repos[0].name == "local::no-origin"


# --------------------------------------------------------------------------
# Cross-repo stitching: workflow_call + workflow_run
# --------------------------------------------------------------------------


CALLER_WORKFLOW = """
name: caller
on:
  pull_request_target:
jobs:
  call:
    uses: owner/callee/.github/workflows/reusable.yml@main
    secrets: inherit
"""

CALLEE_WORKFLOW = """
name: reusable
on:
  workflow_call:
jobs:
  do:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
"""


@pytest.mark.asyncio
async def test_local_enumerator_workflow_call_cross_repo(tmp_path: Path):
    caller = tmp_path / "caller"
    callee = tmp_path / "callee"
    caller.mkdir()
    callee.mkdir()
    _write_git_origin(caller, "owner/caller")
    _write_git_origin(callee, "owner/callee")
    _write_workflow(caller, "caller.yml", CALLER_WORKFLOW)
    _write_workflow(callee, "reusable.yml", CALLEE_WORKFLOW)

    enumerator = LocalEnumerator(tmp_path)
    repos = await enumerator.enumerate()
    by_name = {r.name: r for r in repos}
    assert "owner/caller" in by_name
    assert "owner/callee" in by_name

    # The callee workflow must NOT have triggered an API lookup for resolution
    # because it was loaded into the cache from disk. If cross-repo stitching
    # broke we'd see the "callee_workflow_resolution" skip incremented.
    assert enumerator.skip_counter.get("callee_workflow_resolution", 0) == 0


PRODUCER_WORKFLOW = """
name: ci
on:
  push:
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo build
"""

CONSUMER_WORKFLOW = """
name: consumer
on:
  workflow_run:
    workflows: ["ci"]
    types: [completed]
jobs:
  poke:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.workflow_run.head_branch }}"
"""


@pytest.mark.asyncio
async def test_local_enumerator_workflow_run_cross_repo(tmp_path: Path):
    producer = tmp_path / "producer"
    consumer = tmp_path / "consumer"
    producer.mkdir()
    consumer.mkdir()
    _write_git_origin(producer, "owner/producer")
    _write_git_origin(consumer, "owner/consumer")
    _write_workflow(producer, "ci.yml", PRODUCER_WORKFLOW)
    _write_workflow(consumer, "consumer.yml", CONSUMER_WORKFLOW)

    enumerator = LocalEnumerator(tmp_path)
    repos = await enumerator.enumerate()
    names = sorted(r.name for r in repos)
    assert names == ["owner/consumer", "owner/producer"]

    # The graph should contain the consumer workflow node tagged workflow_run
    graph = WorkflowGraphBuilder().graph
    consumer_workflow_nodes = [
        n
        for n in graph.nodes
        if "WorkflowNode" in n.get_tags()
        and "workflow_run" in n.get_tags()
        and "consumer" in n.name
    ]
    assert consumer_workflow_nodes, "consumer workflow_run node missing"


# --------------------------------------------------------------------------
# CLI integration tests (validate_arguments / mutex / no-token path)
# --------------------------------------------------------------------------


def _scrub_gh_token():
    """Helper: ensure GH_TOKEN is unset for this test."""
    if "GH_TOKEN" in os.environ:
        del os.environ["GH_TOKEN"]


@pytest.mark.asyncio
async def test_cli_local_no_token_required(tmp_path: Path):
    """``--local`` must not prompt for or require GH_TOKEN."""
    repo = tmp_path / "demo"
    repo.mkdir()
    _write_git_origin(repo, "owner/demo")
    _write_workflow(repo, "ci.yml", PWN_WORKFLOW)

    _scrub_gh_token()
    # If GH_TOKEN were required, ``input`` would be called and SystemExit
    # would be raised when an invalid placeholder is returned.
    with mock.patch("builtins.input") as mocked_input:
        await cli.cli(["enumerate", "--local", str(repo)])
    mocked_input.assert_not_called()


@pytest.mark.asyncio
async def test_cli_local_mutex_with_target(tmp_path: Path, capfd):
    repo = tmp_path / "demo"
    repo.mkdir()
    _write_git_origin(repo, "owner/demo")
    _write_workflow(repo, "ci.yml", PWN_WORKFLOW)
    _scrub_gh_token()

    with pytest.raises(SystemExit):
        await cli.cli(["enumerate", "--local", str(repo), "--target", "exampleorg"])
    _, err = capfd.readouterr()
    assert "--local cannot be combined with" in err


@pytest.mark.asyncio
async def test_cli_local_mutex_with_repository(tmp_path: Path, capfd):
    repo = tmp_path / "demo"
    repo.mkdir()
    _write_git_origin(repo, "owner/demo")
    _write_workflow(repo, "ci.yml", PWN_WORKFLOW)
    _scrub_gh_token()

    with pytest.raises(SystemExit):
        await cli.cli(
            [
                "enumerate",
                "--local",
                str(repo),
                "--repository",
                "owner/demo",
            ]
        )
    _, err = capfd.readouterr()
    assert "--local cannot be combined with" in err


@pytest.mark.asyncio
async def test_cli_local_path_does_not_exist(tmp_path: Path, capfd):
    _scrub_gh_token()
    missing = tmp_path / "nope"
    with pytest.raises(SystemExit):
        await cli.cli(["enumerate", "--local", str(missing)])
    _, err = capfd.readouterr()
    assert "does not exist" in err
