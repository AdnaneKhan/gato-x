"""
Copyright 2025, Adnan Khan

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from collections import Counter
from pathlib import Path

from gatox.caching.cache_manager import CacheManager
from gatox.cli.output import Output
from gatox.enumerate.recommender import Recommender
from gatox.github.api import Api
from gatox.models.repository import Repository
from gatox.models.workflow import Workflow
from gatox.workflow_graph.graph_builder import WorkflowGraphBuilder
from gatox.workflow_graph.visitors.artifact_poisoning_visitor import (
    ArtifactPoisoningVisitor,
)
from gatox.workflow_graph.visitors.dispatch_toctou_visitor import DispatchTOCTOUVisitor
from gatox.workflow_graph.visitors.injection_visitor import InjectionVisitor
from gatox.workflow_graph.visitors.pwn_request_visitor import PwnRequestVisitor
from gatox.workflow_graph.visitors.review_injection_visitor import (
    ReviewInjectionVisitor,
)
from gatox.workflow_graph.visitors.runner_visitor import RunnerVisitor
from gatox.workflow_graph.visitors.visitor_utils import VisitorUtils

logger = logging.getLogger(__name__)

# GitHub origin URL patterns - extract owner/repo
# Matches https://github.com/owner/repo[.git], git@github.com:owner/repo[.git],
# ssh://git@github.com/owner/repo[.git]
_GITHUB_ORIGIN_RE = re.compile(
    r"github\.com[:/]+([A-Za-z0-9][A-Za-z0-9._-]*)/([A-Za-z0-9][A-Za-z0-9._-]*?)(?:\.git)?/?$"
)


class LocalApiStub(Api):
    """No-op stand-in for ``gatox.github.api.Api`` used by the local enumerator.

    Every method that the workflow graph builder or visitors might call against
    a real ``Api`` is implemented here so that the offline enumeration code path
    never makes a network request. Each call emits a DEBUG-level log line
    naming the check that was skipped and increments a counter that the
    enumerator uses to report a summary banner.

    Subclasses :class:`Api` so that the stub satisfies static type checks at
    call sites that expect an ``Api`` instance (e.g.
    ``VisitorUtils.add_repo_results``). The parent ``__init__`` is intentionally
    bypassed because we never make network calls and don't want to construct an
    ``httpx.AsyncClient`` or require a PAT.
    """

    def __init__(self):
        # Skip ``Api.__init__`` on purpose — no network client is created in
        # local mode. We still set the attributes that downstream code may
        # touch so that attribute access doesn't surprise callers.
        self.skip_counter: Counter[str] = Counter()
        # Provide token-shape attributes that some callers inspect
        self.is_app = False
        self.pat = ""
        self.transport = None
        self.verify_ssl = True
        self.headers = {}
        self.github_url = "https://api.github.com"
        self.client = None  # type: ignore[assignment]
        self.app_permissions = None
        # slug -> on-disk repository root. Populated by the LocalEnumerator as
        # repos are loaded so that intra-scan-set action / workflow references
        # can be resolved from the filesystem instead of being skipped.
        self._repo_roots: dict[str, Path] = {}

        # ``Api`` was split into grouped sub-APIs (``self.api.repo``,
        # ``self.api.action``, ...). Until ``LocalApiStub`` is replaced by
        # per-group stubs (planned follow-up — see PR #144), alias each
        # sub-API attribute to ``self`` so that ``stub.repo.foo(...)``
        # resolves to the existing ``stub.foo(...)`` overrides.
        self.repo = self  # type: ignore[assignment]
        self.org = self  # type: ignore[assignment]
        self.user = self  # type: ignore[assignment]
        self.commit = self  # type: ignore[assignment]
        self.action = self  # type: ignore[assignment]
        self.app = self  # type: ignore[assignment]

    # --- Skip helpers -----------------------------------------------------

    def _skip(self, kind: str, detail: str) -> None:
        """Record a skipped API-dependent check.

        Args:
            kind: Short tag identifying the check class (e.g.
                ``"external_action_resolution"``). Used for the banner counts.
            detail: Free-form extra context for the debug log line.
        """
        self.skip_counter[kind] += 1
        logger.debug("[local] skipping %s: %s", kind, detail)

    # --- Local-set registration ------------------------------------------

    def register_repo_root(self, slug: str, root: Path) -> None:
        """Record an on-disk repository root so that follow-up calls to
        :meth:`retrieve_raw_action` and :meth:`retrieve_repo_file` can resolve
        intra-scan-set references locally rather than skipping them.
        """
        self._repo_roots[slug] = Path(root)

    def _read_local_file(self, slug: str, path: str) -> str | None:
        """Best-effort read of ``<repo_root>/<path>`` for a registered repo.

        Composite actions are referenced as a directory (e.g.
        ``.github/actions/foo``); GitHub then loads ``action.yml`` /
        ``action.yaml`` inside it. We replicate that lookup here.
        Returns ``None`` if the repo is not in the scan set or the path is
        absent on disk.
        """
        root = self._repo_roots.get(slug)
        if not root:
            return None
        # The graph builder hands us a relative path; refuse anything that
        # tries to escape the repo root.
        rel = Path(path)
        if rel.is_absolute() or any(part == ".." for part in rel.parts):
            return None
        candidate = root / rel
        try:
            if candidate.is_file():
                return candidate.read_text(encoding="utf-8", errors="replace")
            if candidate.is_dir():
                for action_name in ("action.yml", "action.yaml"):
                    inner = candidate / action_name
                    if inner.is_file():
                        return inner.read_text(encoding="utf-8", errors="replace")
        except OSError as e:  # pragma: no cover - defensive
            logger.debug("[local] read error for %s/%s: %s", slug, path, e)
        return None

    # --- Authentication / identity stubs ----------------------------------

    def is_app_token(self) -> bool:
        return False

    async def check_user(self):
        # Synthetic identity for downstream code that expects a user dict.
        return {
            "user": "local-mode",
            "scopes": [],
            "name": "Gato-X Local Mode",
        }

    async def check_organizations(self):
        self._skip("organization_membership", "not available offline")
        return []

    # --- Workflow / action retrieval stubs --------------------------------

    async def retrieve_raw_action(self, repo: str, path: str, ref: str):
        # Try the local scan set first; this lets composite actions that live
        # inside one of the loaded repos (e.g. ``.github/actions/foo`` in the
        # same repository) resolve cleanly without API access.
        contents = self._read_local_file(repo, path)
        if contents is not None:
            return contents
        self._skip(
            "external_action_resolution",
            f"action {repo}/{path}@{ref} not available offline",
        )
        return None

    async def retrieve_repo_file(self, slug: str, path: str, ref: str):
        contents = self._read_local_file(slug, path)
        if contents is not None:
            return contents
        self._skip(
            "callee_workflow_resolution",
            f"workflow {slug}:{path}@{ref} not in local scan set",
        )
        return None

    async def retrieve_workflow_ymls(self, repo_name: str):
        self._skip("api_workflow_listing", repo_name)
        return []

    async def retrieve_workflow_ymls_ref(self, repo_name: str, ref: str):
        self._skip("api_workflow_listing_ref", f"{repo_name}@{ref}")
        return []

    async def retrieve_workflow_log(self, *args, **kwargs):
        self._skip("run_log_analysis", "not available offline")
        return None

    async def retrieve_run_logs(self, repo_name: str, workflows=None):
        self._skip("run_log_analysis", repo_name)
        return []

    # --- Branch / repository stubs ----------------------------------------

    async def get_repository(self, repository: str):
        self._skip("repository_metadata", repository)
        return None

    async def get_repo_branch(self, repo: str, branch: str):
        self._skip("branch_lookup", f"{repo}@{branch}")
        return None

    async def get_repo_runners(self, full_name: str):
        self._skip("runner_listing", full_name)
        return []

    async def get_secrets(self, repo_name: str):
        self._skip("repository_secrets", repo_name)
        return []

    async def get_environment_secrets(self, repo_name: str, environment_name: str):
        self._skip("environment_secrets", f"{repo_name}/{environment_name}")
        return []

    async def get_repo_org_secrets(self, repo_name: str):
        self._skip("org_secrets", repo_name)
        return []

    async def get_all_environment_protection_rules(self, repo_name: str):
        self._skip("branch_protection_rules", repo_name)
        return []

    async def get_file_last_updated(self, repo_name: str, file_path: str):
        self._skip("commit_history", f"{repo_name}:{file_path}")
        return (None, None, None)

    async def get_commit_merge_date(self, repo_name: str, sha: str):
        self._skip("commit_merge_date", f"{repo_name}@{sha}")
        return None

    async def get_user_type(self, username: str):
        self._skip("user_type_lookup", username)
        return None

    async def call_get(self, *args, **kwargs):
        self._skip("raw_api_get", str(args[:1]))
        return None

    async def call_post(self, *args, **kwargs):
        self._skip("raw_api_post", str(args[:1]))
        return None


# --- .git/config helpers ---------------------------------------------------


def parse_origin_url(config_text: str) -> tuple[str, str] | None:
    """Parse a ``.git/config`` blob and extract the GitHub ``owner/repo`` from
    the ``[remote "origin"]`` section.

    Args:
        config_text: Raw contents of the repository's ``.git/config`` file.

    Returns:
        ``(owner, name)`` tuple if a GitHub origin URL is found, else ``None``.
    """
    in_origin = False
    url: str | None = None
    for raw_line in config_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            # Section header, e.g. [remote "origin"] or [remote "origin"] etc.
            in_origin = bool(
                re.match(r'^\[remote\s+"origin"\]$', line)
                or line == '[remote "origin"]'
            )
            continue
        if in_origin and line.lower().startswith("url"):
            # Format is `url = <value>`
            parts = line.split("=", 1)
            if len(parts) == 2:
                url = parts[1].strip()
                break

    if not url:
        return None

    match = _GITHUB_ORIGIN_RE.search(url)
    if not match:
        return None
    owner, name = match.group(1), match.group(2)
    # Strip a trailing .git that may have slipped past
    if name.endswith(".git"):
        name = name[:-4]
    return owner, name


def detect_default_branch(git_dir: Path) -> str:
    """Best-effort default branch detection from ``.git/HEAD``.

    Falls back to ``"main"`` if HEAD is detached or unreadable.
    """
    head_path = git_dir / "HEAD"
    try:
        content = head_path.read_text(encoding="utf-8", errors="replace").strip()
        if content.startswith("ref:"):
            ref = content.split(maxsplit=1)[1].strip()
            if ref.startswith("refs/heads/"):
                return ref[len("refs/heads/") :]
    except OSError:
        pass
    return "main"


def repo_identity(repo_dir: Path) -> tuple[str, str, bool]:
    """Determine the ``owner/name`` slug for a local repo directory.

    Args:
        repo_dir: Path to the repository root (the directory that
            contains ``.git`` and/or ``.github/workflows``).

    Returns:
        ``(slug, default_branch, synthetic)`` where ``slug`` is the
        ``owner/name`` identifier used everywhere downstream, ``default_branch``
        is the working branch name to attach to workflows, and ``synthetic``
        is True iff the slug was not derived from a real GitHub origin URL.
    """
    git_dir = repo_dir / ".git"
    config = git_dir / "config"
    if config.is_file():
        try:
            text = config.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.debug("[local] could not read %s: %s", config, e)
            text = ""
        parsed = parse_origin_url(text)
        if parsed:
            owner, name = parsed
            return f"{owner}/{name}", detect_default_branch(git_dir), False

    # Synthetic name fallback - use the directory name with a clear local prefix.
    fallback = f"local::{repo_dir.name}"
    branch = detect_default_branch(git_dir) if git_dir.is_dir() else "main"
    return fallback, branch, True


# --- Workflow discovery ----------------------------------------------------


def _is_workflow_file(name: str) -> bool:
    lowered = name.lower()
    return lowered.endswith(".yml") or lowered.endswith(".yaml")


def _has_workflows(path: Path) -> bool:
    wf_dir = path / ".github" / "workflows"
    if not wf_dir.is_dir():
        return False
    return any(_is_workflow_file(p.name) for p in wf_dir.iterdir() if p.is_file())


def discover_repos(root: Path, recursive: bool = False) -> list[Path]:
    """Discover repository roots under ``root``.

    Detection rules (matching the locked-in UX):
      * If ``root`` itself contains ``.github/workflows/*.yml`` it is treated
        as a single repository.
      * Otherwise, immediate subdirectories of ``root`` are inspected and any
        that contain ``.github/workflows/*.yml`` are returned.
      * When ``recursive=True`` the search descends further (depth-first) and
        returns every directory below ``root`` that has a workflows folder.
    """
    if not root.exists():
        raise FileNotFoundError(f"Local scan root does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Local scan root is not a directory: {root}")

    if _has_workflows(root):
        return [root]

    discovered: list[Path] = []
    if recursive:
        for dirpath, dirnames, _ in os.walk(root):
            # Don't descend into .git or virtualenvs
            dirnames[:] = [
                d for d in dirnames if d not in {".git", ".venv", "node_modules"}
            ]
            if _has_workflows(Path(dirpath)):
                discovered.append(Path(dirpath))
    else:
        for child in sorted(root.iterdir()):
            if child.is_dir() and _has_workflows(child):
                discovered.append(child)

    return discovered


def _build_local_repo_data(slug: str, default_branch: str) -> dict:
    """Build a minimal ``Repository`` constructor dict for an offline scan.

    The downstream wrappers expect these keys; we mark permissions as
    read-only and set defaults for fields that only matter when calling the
    GitHub API (push timestamp, fork status, ...).
    """
    return {
        "full_name": slug,
        "html_url": f"local://{slug}",
        "visibility": "public",
        "default_branch": default_branch,
        "fork": False,
        "stargazers_count": 0,
        "pushed_at": None,
        "permissions": {
            "pull": True,
            "push": False,
            "maintain": False,
            "admin": False,
        },
        "archived": False,
        "isFork": False,
        "allow_forking": False,
        "environments": [],
    }


# --- Enumerator ------------------------------------------------------------


class LocalEnumerator:
    """Offline workflow enumeration driver.

    Walks one or more local repositories, loads their workflow YAMLs into the
    in-memory cache, drives the existing graph builder and visitor pipeline,
    then prints findings in the same format as the API-mode enumerator. No
    network requests are performed; every API-dependent check is logged as a
    debug-level skip via ``LocalApiStub``.
    """

    def __init__(
        self,
        local_path: str | os.PathLike,
        recursive: bool = False,
        ignore_workflow_run: bool = False,
        skip_log: bool = True,
    ):
        self.local_path = Path(local_path).expanduser().resolve()
        self.recursive = recursive
        self.ignore_workflow_run = ignore_workflow_run
        # ``skip_log`` mirrors the API-mode flag; runlog analysis is always
        # API-only so we force-default to True but expose the knob for parity.
        self.skip_log = True if skip_log is None else skip_log
        self.api = LocalApiStub()
        self.user_perms: dict | None = None
        self._loaded_repos: list[Repository] = []
        self._loaded_workflow_count = 0

    # ---- discovery + loading ------------------------------------------------

    def _load_workflow_files(self, repo_dir: Path, repo: Repository) -> list[Workflow]:
        """Read every workflow YAML for ``repo_dir`` into the cache and the graph.

        The same workflow is registered twice in the cache: once under its bare
        filename (matching the API-mode key shape used by
        :class:`DataIngestor.construct_workflow_cache`) and once under the
        ``<path>:<ref>`` key shape consulted by the graph builder when
        resolving callee references. Storing both ensures cross-repo
        ``workflow_call`` / ``workflow_run`` stitching works whenever both
        endpoints are inside the local scan set.
        """
        wf_dir = repo_dir / ".github" / "workflows"
        cache = CacheManager()
        loaded: list[Workflow] = []
        cache.set_empty(repo.name)

        if not wf_dir.is_dir():
            return loaded

        for yml in sorted(wf_dir.iterdir()):
            if not yml.is_file() or not _is_workflow_file(yml.name):
                continue
            try:
                contents = yml.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                logger.warning("[local] could not read %s: %s", yml, e)
                continue

            wf = Workflow(
                repo.name,
                contents,
                yml.name,
                default_branch=repo.repo_data["default_branch"],
            )
            if wf.isInvalid():
                logger.debug(
                    "[local] skipping invalid workflow YAML %s in %s",
                    yml.name,
                    repo.name,
                )
                continue

            cache.set_workflow(repo.name, wf.workflow_name, wf)
            # Also store under the callee key shape so cross-repo
            # workflow_call lookups inside the graph builder hit the cache
            # instead of the LocalApiStub. The graph builder uses
            # ``f"{path}:{ref}"`` as its workflow cache key.
            callee_key = f"{wf.getPath()}:{wf.branch}"
            cache.set_workflow(repo.name, callee_key, wf)
            loaded.append(wf)
        return loaded

    async def _load_repo(self, repo_dir: Path) -> Repository:
        """Build a Repository wrapper for the given directory and register it."""
        slug, branch, synthetic = repo_identity(repo_dir)
        if synthetic:
            logger.debug(
                "[local] using synthetic name %s for %s (no GitHub origin)",
                slug,
                repo_dir,
            )
        repo_data = _build_local_repo_data(slug, branch)
        repo = Repository(repo_data)
        CacheManager().set_repository(repo)
        # Register the on-disk root so the API stub can resolve intra-set
        # composite actions and reusable workflows from the filesystem.
        self.api.register_repo_root(slug, repo_dir)

        wfs = self._load_workflow_files(repo_dir, repo)
        for wf in wfs:
            await WorkflowGraphBuilder().build_graph_from_yaml(wf, repo)
        self._loaded_workflow_count += len(wfs)
        return repo

    # ---- visitor pipeline ---------------------------------------------------

    async def _process_graph(self) -> None:
        """Run the same visitor stack used by the API enumerator."""
        Output.info(
            f"Performing graph analysis on "
            f"{WorkflowGraphBuilder().graph.number_of_nodes()} nodes!"
        )

        visitors = [
            (PwnRequestVisitor, "find_pwn_requests"),
            (InjectionVisitor, "find_injections"),
            (ReviewInjectionVisitor, "find_injections"),
            (DispatchTOCTOUVisitor, "find_dispatch_misconfigurations"),
            (ArtifactPoisoningVisitor, "find_artifact_poisoning"),
        ]

        async def run_visitor(visitor_class, visitor_method):
            visitor = visitor_class()
            visitor_func = getattr(visitor, visitor_method)
            try:
                if visitor_class in (PwnRequestVisitor, InjectionVisitor):
                    return await visitor_func(
                        WorkflowGraphBuilder().graph,
                        self.api,
                        self.ignore_workflow_run,
                    )
                else:
                    return await visitor_func(WorkflowGraphBuilder().graph, self.api)
            except Exception as e:  # pragma: no cover - defensive
                logger.error(f"Error in {visitor_class.__name__}: {e}")
                return None

        results = await asyncio.gather(
            *(run_visitor(v, m) for v, m in visitors),
            return_exceptions=True,
        )

        for visitor_class, result in zip(visitors, results, strict=False):
            if result and not isinstance(result, BaseException):
                await VisitorUtils.add_repo_results(result, self.api)
            elif isinstance(result, BaseException):  # pragma: no cover
                logger.error(f"Error in {visitor_class[0].__name__}: {result}")

        # Runner detection from log files is API-only; we still run the graph
        # tag-based scanner because it works purely off parsed YAML.
        await RunnerVisitor.find_runner_workflows(WorkflowGraphBuilder().graph)
        # Note: no run-log analysis - that requires the GitHub API.
        logger.debug("[local] skipping run-log analysis: not available offline")
        self.api.skip_counter["run_log_analysis"] += 1

    # ---- public driver ------------------------------------------------------

    async def enumerate(self) -> list[Repository]:
        """Enumerate every repository discovered under ``self.local_path``.

        Returns:
            The list of :class:`Repository` wrappers populated with findings.
        """
        # Establish the local "user" once so downstream Recommender calls work
        self.user_perms = await self.api.user.check_user()

        repo_dirs = discover_repos(self.local_path, recursive=self.recursive)
        if not repo_dirs:
            Output.warn(
                f"No repositories with .github/workflows/ found under "
                f"{Output.bright(str(self.local_path))}"
            )
            return []

        Output.info(
            f"[local mode] discovered {Output.bright(str(len(repo_dirs)))} "
            f"repositor{'y' if len(repo_dirs) == 1 else 'ies'} under "
            f"{Output.bright(str(self.local_path))}"
        )

        for repo_dir in repo_dirs:
            repo = await self._load_repo(repo_dir)
            self._loaded_repos.append(repo)

        Output.info(
            f"[local mode] loaded {self._loaded_workflow_count} workflow YAML files"
        )

        await self._process_graph()

        # Emit per-repo recommendations using the same formatter as API mode.
        for repo in self._loaded_repos:
            cached = CacheManager().get_repository(repo.name)
            if not cached:
                continue
            Output.tabbed(f"Checking repository: {Output.bright(cached.name)}")
            if cached.get_risks():
                from gatox.enumerate.reports.actions import ActionsReport

                for risk in cached.get_risks():
                    ActionsReport.report_actions_risk(risk)

            # Recommendation prints honor the (empty) scope set so secrets/
            # runner sections automatically degrade to "skipped" output.
            try:
                Recommender.print_repo_attack_recommendations(
                    self.user_perms["scopes"] if self.user_perms else [],
                    cached,
                )
            except Exception as e:  # pragma: no cover - defensive
                logger.debug("[local] recommender error for %s: %s", cached.name, e)

        # Final banner summarising the offline run.
        skipped_total = sum(self.api.skip_counter.values())
        banner = (
            f"[local mode] {len(self._loaded_repos)} repos scanned offline; "
            f"{skipped_total} API-dependent checks skipped (see debug log)."
        )
        Output.result(banner)
        # Also write to the canonical info channel so it is captured even
        # when the rich Output is suppressed (e.g. JSON-only mode).
        logger.info(banner)
        return self._loaded_repos

    # ---- introspection (used by tests + caller code) -----------------------

    @property
    def loaded_repos(self) -> list[Repository]:
        return list(self._loaded_repos)

    @property
    def skip_counter(self) -> Counter:
        return self.api.skip_counter
