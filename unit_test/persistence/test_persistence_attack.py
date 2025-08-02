import unittest
from unittest.mock import patch, AsyncMock, MagicMock
from gatox.attack.persistence.persistence_attack import PersistenceAttack


class TestPersistenceAttack(unittest.TestCase):
    """Test cases for persistence attack functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.persistence_attacker = PersistenceAttack(
            "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )

    @patch("gatox.attack.persistence.persistence_attack.Output")
    async def test_invite_collaborators_success(self, mock_output):
        """Test successful collaborator invitation."""
        # Mock the setup and API calls
        self.persistence_attacker.setup_user_info = AsyncMock(return_value=True)
        self.persistence_attacker.api.invite_collaborator = AsyncMock(return_value=True)

        result = await self.persistence_attacker.invite_collaborators(
            "test/repo", ["user1", "user2"]
        )

        self.assertTrue(result)
        self.assertEqual(self.persistence_attacker.api.invite_collaborator.call_count, 2)

    @patch("gatox.attack.persistence.persistence_attack.Output")
    async def test_invite_collaborators_partial_success(self, mock_output):
        """Test partial success in collaborator invitation."""
        self.persistence_attacker.setup_user_info = AsyncMock(return_value=True)
        
        # Mock first invite success, second failure
        self.persistence_attacker.api.invite_collaborator = AsyncMock(
            side_effect=[True, False]
        )

        result = await self.persistence_attacker.invite_collaborators(
            "test/repo", ["user1", "user2"]
        )

        self.assertTrue(result)  # Should still return True if at least one succeeds

    @patch("gatox.attack.persistence.persistence_attack.Output")
    async def test_invite_collaborators_setup_failure(self, mock_output):
        """Test failure due to setup issues."""
        self.persistence_attacker.setup_user_info = AsyncMock(return_value=False)

        result = await self.persistence_attacker.invite_collaborators(
            "test/repo", ["user1"]
        )

        self.assertFalse(result)

    @patch("gatox.attack.persistence.persistence_attack.Output")
    async def test_create_deploy_key_success(self, mock_output):
        """Test successful deploy key creation."""
        self.persistence_attacker.setup_user_info = AsyncMock(return_value=True)
        self.persistence_attacker.api.create_deploy_key = AsyncMock(return_value=True)

        result = await self.persistence_attacker.create_deploy_key("test/repo")

        self.assertTrue(result)
        self.persistence_attacker.api.create_deploy_key.assert_called_once()

    @patch("gatox.attack.persistence.persistence_attack.Output")
    async def test_create_deploy_key_failure(self, mock_output):
        """Test deploy key creation failure."""
        self.persistence_attacker.setup_user_info = AsyncMock(return_value=True)
        self.persistence_attacker.api.create_deploy_key = AsyncMock(return_value=False)

        result = await self.persistence_attacker.create_deploy_key("test/repo")

        self.assertFalse(result)

    @patch("gatox.attack.persistence.persistence_attack.Output")
    async def test_create_pwn_request_workflow_success(self, mock_output):
        """Test successful pwn request workflow creation."""
        self.persistence_attacker.setup_user_info = AsyncMock(return_value=True)
        self.persistence_attacker.api.create_workflow_on_branch = AsyncMock(return_value=True)

        result = await self.persistence_attacker.create_pwn_request_workflow("test/repo")

        self.assertTrue(result)
        self.persistence_attacker.api.create_workflow_on_branch.assert_called_once()

    @patch("gatox.attack.persistence.persistence_attack.Output")
    async def test_create_pwn_request_workflow_custom_branch(self, mock_output):
        """Test pwn request workflow creation with custom branch."""
        self.persistence_attacker.setup_user_info = AsyncMock(return_value=True)
        self.persistence_attacker.api.create_workflow_on_branch = AsyncMock(return_value=True)

        result = await self.persistence_attacker.create_pwn_request_workflow(
            "test/repo", "custom-branch"
        )

        self.assertTrue(result)
        # Verify the correct branch name was passed
        call_args = self.persistence_attacker.api.create_workflow_on_branch.call_args
        self.assertEqual(call_args[0][1], "custom-branch")  # Second argument is branch name


if __name__ == "__main__":
    unittest.main()