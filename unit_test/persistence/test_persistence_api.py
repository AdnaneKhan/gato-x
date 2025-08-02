import unittest
from unittest.mock import patch, AsyncMock
from gatox.github.api import Api


class TestPersistenceAPI(unittest.TestCase):
    """Test cases for persistence-related API methods."""

    def setUp(self):
        """Set up test fixtures."""
        self.api = Api("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

    async def test_invite_collaborator_success(self):
        """Test successful collaborator invitation API call."""
        self.api.call_post = AsyncMock()
        self.api.call_post.return_value.status_code = 201

        result = await self.api.invite_collaborator("test/repo", "username")

        self.assertTrue(result)
        self.api.call_post.assert_called_once_with(
            "/repos/test/repo/collaborators/username",
            params={"permission": "push"}
        )

    async def test_invite_collaborator_already_invited(self):
        """Test collaborator invitation when user is already invited."""
        self.api.call_post = AsyncMock()
        self.api.call_post.return_value.status_code = 204

        result = await self.api.invite_collaborator("test/repo", "username")

        self.assertTrue(result)

    async def test_invite_collaborator_failure(self):
        """Test failed collaborator invitation."""
        self.api.call_post = AsyncMock()
        self.api.call_post.return_value.status_code = 403

        result = await self.api.invite_collaborator("test/repo", "username")

        self.assertFalse(result)

    async def test_create_deploy_key_success(self):
        """Test successful deploy key creation."""
        self.api.call_post = AsyncMock()
        self.api.call_post.return_value.status_code = 201

        result = await self.api.create_deploy_key(
            "test/repo", "Test Key", "ssh-rsa AAAA...", read_only=False
        )

        self.assertTrue(result)
        self.api.call_post.assert_called_once_with(
            "/repos/test/repo/keys",
            params={
                "title": "Test Key",
                "key": "ssh-rsa AAAA...",
                "read_only": False
            }
        )

    async def test_create_deploy_key_failure(self):
        """Test failed deploy key creation."""
        self.api.call_post = AsyncMock()
        self.api.call_post.return_value.status_code = 422

        result = await self.api.create_deploy_key(
            "test/repo", "Test Key", "invalid-key"
        )

        self.assertFalse(result)

    async def test_create_workflow_on_branch_success(self):
        """Test successful workflow creation on branch."""
        # Mock the repository info call
        self.api.get_repository = AsyncMock(return_value={"default_branch": "main"})
        
        # Mock the branch info call
        branch_response = AsyncMock()
        branch_response.status_code = 200
        branch_response.json.return_value = {"object": {"sha": "abc123"}}
        
        # Mock the workflow creation call
        workflow_response = AsyncMock()
        workflow_response.status_code = 201
        
        self.api.call_get = AsyncMock(return_value=branch_response)
        self.api.call_post = AsyncMock(return_value=workflow_response)

        result = await self.api.create_workflow_on_branch(
            "test/repo", "feature-branch", "test.yml", "workflow content"
        )

        self.assertTrue(result)

    async def test_create_workflow_on_branch_repo_failure(self):
        """Test workflow creation failure due to repository access."""
        self.api.get_repository = AsyncMock(return_value=None)

        result = await self.api.create_workflow_on_branch(
            "test/repo", "feature-branch", "test.yml", "workflow content"
        )

        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()