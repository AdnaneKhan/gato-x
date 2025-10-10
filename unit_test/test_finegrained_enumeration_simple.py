from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from gatox.caching.cache_manager import CacheManager
from gatox.cli.output import Output
from gatox.enumerate.finegrained_enumeration import FineGrainedEnumerator
from gatox.github.api import Api

Output(True)


@pytest.fixture(autouse=True)
def clear_cache():
    """Clear the CacheManager singleton instance before each test."""
    CacheManager._instance = None
    yield
    CacheManager._instance = None


class TestFineGrainedEnumeratorSimple:
    """Simplified test suite for FineGrainedEnumerator class."""

    @patch("gatox.enumerate.finegrained_enumeration.Api", return_value=AsyncMock(Api))
    def test_init(self, mock_api):
        """Test FineGrainedEnumerator initialization."""
        enumerator = FineGrainedEnumerator(
            pat="github_pat_11ABCDEFG123456789_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            socks_proxy=None,
            http_proxy="localhost:8080",
            skip_log=False,
        )

        assert enumerator.http_proxy == "localhost:8080"
        assert enumerator.accessible_repos == []

    async def test_probe_write_access_success(self):
        """Test successful write access probing."""
        enumerator = FineGrainedEnumerator(
            pat="github_pat_11ABCDEFG123456789_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )

        # Mock the API
        enumerator.api = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 201
        enumerator.api.call_post = AsyncMock(return_value=mock_response)

        valid_scopes = {"contents:read"}

        await enumerator.probe_write_access("octocat/Hello-World", valid_scopes, False)

        assert "contents:read" not in valid_scopes
        assert "contents:write" in valid_scopes
        enumerator.api.call_post.assert_called_once()

    async def test_probe_write_access_failure(self):
        """Test failed write access probing."""
        enumerator = FineGrainedEnumerator(
            pat="github_pat_11ABCDEFG123456789_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )

        # Mock the API
        enumerator.api = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 403
        enumerator.api.call_post = AsyncMock(return_value=mock_response)

        valid_scopes = {"contents:read"}
        original_scopes = valid_scopes.copy()

        await enumerator.probe_write_access("octocat/Hello-World", valid_scopes, False)

        # Scopes should remain unchanged on failure
        assert valid_scopes == original_scopes

    async def test_probe_write_access_public_repo(self):
        """Test write access probing for public repository without read permission."""
        enumerator = FineGrainedEnumerator(
            pat="github_pat_11ABCDEFG123456789_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )

        # Mock the API
        enumerator.api = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 201
        enumerator.api.call_post = AsyncMock(return_value=mock_response)

        valid_scopes = set()  # No read permissions

        await enumerator.probe_write_access(
            "octocat/Hello-World", valid_scopes, is_public=True
        )

        assert "contents:write" in valid_scopes
        enumerator.api.call_post.assert_called_once()

    async def test_probe_write_access_no_permission_not_public(self):
        """Test write access probing when no read permission and not public repo."""
        enumerator = FineGrainedEnumerator(
            pat="github_pat_11ABCDEFG123456789_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )

        # Mock the API
        enumerator.api = MagicMock()
        enumerator.api.call_post = AsyncMock()

        valid_scopes = set()  # No permissions

        await enumerator.probe_write_access(
            "octocat/Hello-World", valid_scopes, is_public=False
        )

        # Should not make any API calls or modify scopes
        enumerator.api.call_post.assert_not_called()
        assert len(valid_scopes) == 0

    async def test_probe_pull_requests_write_access(self):
        """Test pull requests write access probing."""
        enumerator = FineGrainedEnumerator(
            pat="github_pat_11ABCDEFG123456789_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )

        # Mock the API
        enumerator.api = MagicMock()

        # Mock PR list response
        pr_list_response = MagicMock()
        pr_list_response.status_code = 200
        pr_list_response.json.return_value = [{"number": 1}]

        # Mock successful PATCH response
        patch_response = MagicMock()
        patch_response.status_code = 200

        enumerator.api.call_get = AsyncMock(return_value=pr_list_response)
        enumerator.api.call_patch = AsyncMock(return_value=patch_response)

        valid_scopes = {"pull_requests:read"}

        await enumerator.probe_pull_requests_write_access(
            "octocat/Hello-World", valid_scopes, False
        )

        assert "pull_requests:read" not in valid_scopes
        assert "pull_requests:write" in valid_scopes

    async def test_probe_actions_write_access(self):
        """Test actions write access probing via OIDC settings."""
        enumerator = FineGrainedEnumerator(
            pat="github_pat_11ABCDEFG123456789_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )

        # Mock the API
        enumerator.api = MagicMock()

        # Mock OIDC get response
        get_response = MagicMock()
        get_response.status_code = 200
        get_response.json.return_value = {"use_default": True}

        # Mock OIDC put response
        put_response = MagicMock()
        put_response.status_code = 204

        enumerator.api.call_get = AsyncMock(return_value=get_response)
        enumerator.api.call_put = AsyncMock(return_value=put_response)

        valid_scopes = {"actions:read"}

        await enumerator.probe_actions_write_access(
            "octocat/Hello-World", valid_scopes, False
        )

        assert "actions:write" in valid_scopes
        assert "actions:read" not in valid_scopes

    async def test_probe_issue_write_access(self):
        """Test issues write access probing."""
        enumerator = FineGrainedEnumerator(
            pat="github_pat_11ABCDEFG123456789_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )

        # Mock the API
        enumerator.api = MagicMock()

        # Mock issue list response
        issue_list_response = MagicMock()
        issue_list_response.status_code = 200
        issue_list_response.json.return_value = [{"number": 1}]

        # Mock successful PATCH response
        patch_response = MagicMock()
        patch_response.status_code = 200

        enumerator.api.call_get = AsyncMock(return_value=issue_list_response)
        enumerator.api.call_patch = AsyncMock(return_value=patch_response)

        valid_scopes = {"issues:read"}

        await enumerator.probe_issue_write_access(
            "octocat/Hello-World", valid_scopes, False
        )

        assert "issues:read" not in valid_scopes
        assert "issues:write" in valid_scopes

    async def test_check_collaborator_access_success(self):
        """Test successful collaborator access check."""
        enumerator = FineGrainedEnumerator(
            pat="github_pat_11ABCDEFG123456789_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )

        # Mock the API
        enumerator.api = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        enumerator.api.call_get = AsyncMock(return_value=mock_response)

        result = await enumerator.check_collaborator_access("octocat/Hello-World")

        assert result is True
        enumerator.api.call_get.assert_called_once_with(
            "/repos/octocat/Hello-World/collaborators"
        )

    async def test_check_collaborator_access_forbidden(self):
        """Test collaborator access check with 403 response."""
        enumerator = FineGrainedEnumerator(
            pat="github_pat_11ABCDEFG123456789_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )

        # Mock the API
        enumerator.api = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 403
        enumerator.api.call_get = AsyncMock(return_value=mock_response)

        result = await enumerator.check_collaborator_access("octocat/Hello-World")

        assert result is False

    async def test_error_handling_in_probes(self):
        """Test error handling in various probe functions."""
        enumerator = FineGrainedEnumerator(
            pat="github_pat_11ABCDEFG123456789_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )

        # Mock the API to raise exceptions
        enumerator.api = MagicMock()
        enumerator.api.call_post = AsyncMock(side_effect=Exception("Network error"))
        enumerator.api.call_get = AsyncMock(side_effect=Exception("Network error"))
        enumerator.api.call_patch = AsyncMock(side_effect=Exception("Network error"))
        enumerator.api.call_put = AsyncMock(side_effect=Exception("Network error"))

        valid_scopes = {
            "contents:read",
            "issues:read",
            "pull_requests:read",
            "actions:read",
        }
        expected_scopes = valid_scopes.copy()

        # These should not raise exceptions, just handle gracefully
        await enumerator.probe_write_access("octocat/Hello-World", valid_scopes, False)
        await enumerator.probe_pull_requests_write_access(
            "octocat/Hello-World", valid_scopes, False
        )
        await enumerator.probe_actions_write_access(
            "octocat/Hello-World", valid_scopes, False
        )
        await enumerator.probe_issue_write_access(
            "octocat/Hello-World", valid_scopes, False
        )

        # Scopes should remain unchanged due to errors
        assert valid_scopes == expected_scopes

    async def test_probe_workflow_write_access_success(self):
        """Test successful workflow write access probing."""
        enumerator = FineGrainedEnumerator(
            pat="github_pat_11ABCDEFG123456789_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )

        # Mock the API
        enumerator.api = MagicMock()

        # Mock repository info response
        repo_response = MagicMock()
        repo_response.status_code = 200
        repo_response.json.return_value = {"default_branch": "main"}

        # Mock commit response from /repos/{repo}/commits/{branch}
        commit_response = MagicMock()
        commit_response.status_code = 200
        commit_response.json.return_value = {"sha": "commit123"}

        # Mock git commit response from /repos/{repo}/git/commits/{sha}
        git_commit_response = MagicMock()
        git_commit_response.status_code = 200
        git_commit_response.json.return_value = {"tree": {"sha": "tree123"}}

        # Mock tree response with existing structure
        tree_response = MagicMock()
        tree_response.status_code = 200
        tree_response.json.return_value = {
            "sha": "tree123",
            "tree": [
                {
                    "path": "README.md",
                    "mode": "100644",
                    "type": "blob",
                    "sha": "readme123",
                },
                {
                    "path": ".github",
                    "mode": "040000",
                    "type": "tree",
                    "sha": "github123",
                },
                {
                    "path": ".github/workflows",
                    "mode": "040000",
                    "type": "tree",
                    "sha": "workflows123",
                },
            ],
        }

        # Mock blob creation response
        blob_response = MagicMock()
        blob_response.status_code = 201
        blob_response.json.return_value = {"sha": "blob123"}

        # Mock successful tree creation response
        create_tree_response = MagicMock()
        create_tree_response.status_code = 201

        # Set up API call responses
        enumerator.api.call_get = AsyncMock(
            side_effect=[
                repo_response,
                commit_response,
                git_commit_response,
                tree_response,
            ]
        )
        enumerator.api.call_post = AsyncMock(
            side_effect=[blob_response, create_tree_response]
        )

        valid_scopes = {"contents:write"}

        await enumerator.probe_workflow_write_access(
            "octocat/Hello-World", valid_scopes
        )

        # Should add workflows:write scope
        assert "workflows:write" in valid_scopes
        # Should keep contents:write scope
        assert "contents:write" in valid_scopes

        # Verify API calls were made
        enumerator.api.call_post.assert_any_call(
            "/repos/octocat/Hello-World/git/blobs",
            params={"content": "TESTING", "encoding": "utf-8"},
        )

    async def test_probe_workflow_write_access_no_contents_write(self):
        """Test workflow write access probing when contents:write scope is not present."""
        enumerator = FineGrainedEnumerator(
            pat="github_pat_11ABCDEFG123456789_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )

        # Mock the API
        enumerator.api = MagicMock()
        enumerator.api.call_post = AsyncMock()
        enumerator.api.call_get = AsyncMock()

        valid_scopes = {"actions:read"}  # No contents:write

        await enumerator.probe_workflow_write_access(
            "octocat/Hello-World", valid_scopes
        )

        # Should not make any API calls since contents:write is required
        enumerator.api.call_post.assert_not_called()
        enumerator.api.call_get.assert_not_called()

        # Scopes should remain unchanged
        assert valid_scopes == {"actions:read"}

    async def test_probe_workflow_write_access_blob_creation_fails(self):
        """Test workflow write access probing when blob creation fails."""
        enumerator = FineGrainedEnumerator(
            pat="github_pat_11ABCDEFG123456789_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )

        # Mock the API
        enumerator.api = MagicMock()

        # Mock failed blob creation response
        blob_response = MagicMock()
        blob_response.status_code = 403  # Forbidden

        enumerator.api.call_post = AsyncMock(return_value=blob_response)

        valid_scopes = {"contents:write"}

        await enumerator.probe_workflow_write_access(
            "octocat/Hello-World", valid_scopes
        )

        # Should not add workflows:write scope due to blob creation failure
        assert "workflows:write" not in valid_scopes
        assert valid_scopes == {"contents:write"}

    async def test_probe_workflow_write_access_tree_creation_fails(self):
        """Test workflow write access probing when tree creation fails."""
        enumerator = FineGrainedEnumerator(
            pat="github_pat_11ABCDEFG123456789_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )

        # Mock the API
        enumerator.api = MagicMock()

        # Mock successful blob creation
        blob_response = MagicMock()
        blob_response.status_code = 201
        blob_response.json.return_value = {"sha": "blob123"}

        # Mock repository info response
        repo_response = MagicMock()
        repo_response.status_code = 200
        repo_response.json.return_value = {"default_branch": "main"}

        # Mock branch reference response
        branch_response = MagicMock()
        branch_response.status_code = 200
        branch_response.json.return_value = {"object": {"sha": "commit123"}}

        # Mock commit response
        commit_response = MagicMock()
        commit_response.status_code = 200
        commit_response.json.return_value = {"tree": {"sha": "tree123"}}

        # Mock tree response
        tree_response = MagicMock()
        tree_response.status_code = 200
        tree_response.json.return_value = {"tree": []}

        # Mock failed tree creation response
        create_tree_response = MagicMock()
        create_tree_response.status_code = 403  # Forbidden

        # Set up API call responses
        enumerator.api.call_post = AsyncMock(
            side_effect=[blob_response, create_tree_response]
        )
        enumerator.api.call_get = AsyncMock(
            side_effect=[repo_response, branch_response, commit_response, tree_response]
        )

        valid_scopes = {"contents:write"}

        await enumerator.probe_workflow_write_access(
            "octocat/Hello-World", valid_scopes
        )

        # Should not add workflows:write scope due to tree creation failure
        assert "workflows:write" not in valid_scopes
        assert valid_scopes == {"contents:write"}

    async def test_detect_scopes_integration_mocked(self):
        """Integration test for detect_scopes with mocked API responses."""
        enumerator = FineGrainedEnumerator(
            pat="github_pat_11ABCDEFG123456789_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )

        # Mock the API
        enumerator.api = MagicMock()

        # Mock repo data call for private repo
        repo_response = MagicMock()
        repo_response.json.return_value = {"private": True}
        repo_response.status_code = 200

        # Mock successful responses for all calls
        success_200 = MagicMock()
        success_200.status_code = 200
        success_200.json.return_value = [{"number": 1}]  # For PR/issue lists

        success_201 = MagicMock()
        success_201.status_code = 201  # For blob creation

        success_204 = MagicMock()
        success_204.status_code = 204  # For OIDC updates

        # Set up mocking - first call returns repo data, rest return success
        def get_side_effect(*args, **kwargs):
            if "/repos/octocat/private-repo" == args[0] and len(args) == 1:
                return repo_response
            return success_200

        enumerator.api.call_get = AsyncMock(side_effect=get_side_effect)
        enumerator.api.call_post = AsyncMock(return_value=success_201)
        enumerator.api.call_patch = AsyncMock(return_value=success_200)
        enumerator.api.call_put = AsyncMock(return_value=success_204)

        result = await enumerator.detect_scopes("octocat/private-repo")

        # Should have both read and write permissions
        expected_write_scopes = {
            "contents:write",
            "issues:write",
            "pull_requests:write",
            "actions:write",
        }

        # Check that we have write permissions (which means write probes succeeded)
        assert expected_write_scopes.issubset(
            result
        ), f"Expected {expected_write_scopes} to be subset of {result}"

    async def test_enumerate_fine_grained_token_no_repos(self):
        """Test enumerate_fine_grained_token when token has no write+ public repos and no private repos."""
        enumerator = FineGrainedEnumerator(
            pat="github_pat_11ABCDEFG123456789_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )

        # Mock the API
        enumerator.api = MagicMock()

        # Initialize user_perms to simulate successful validation
        enumerator.user_perms = {"user": "testuser"}

        # Mock validate_token_and_get_user to return True
        enumerator.validate_token_and_get_user = AsyncMock(return_value=True)

        # Mock get_own_repos to return empty lists for both public and private repos
        enumerator.api.get_own_repos = AsyncMock(return_value=[])

        repositories = await enumerator.enumerate_fine_grained_token()

        # Verify API calls were made with correct parameters
        enumerator.api.get_own_repos.assert_any_call(
            affiliation="owner,collaborator,organization_member", visibility="public"
        )
        enumerator.api.get_own_repos.assert_any_call(
            affiliation="owner,collaborator,organization_member", visibility="private"
        )

        # Should return empty list when no repos are accessible
        assert repositories == []
        # finegrained_permissions should be set to empty set
        assert enumerator.finegrained_permissions == set()
        # user_perms["scopes"] should not be set since method returns early
        assert "scopes" not in enumerator.user_perms
