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

    def test_enumerate_fine_grained_token_invalid_mode(self):
        """Test fine-grained token enumeration with invalid mode."""
        enumerator = FineGrainedEnumerator(
            pat="github_pat_11ABCDEFG123456789_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )

        with pytest.raises(
            ValueError, match="enum_mode must be either 'self' or 'single'"
        ):
            # Use a sync context manager to test the validation
            import asyncio

            asyncio.run(enumerator.enumerate_fine_grained_token("invalid", None))

    def test_enumerate_fine_grained_token_single_mode_no_repo(self):
        """Test fine-grained token enumeration in single mode without target repo."""
        enumerator = FineGrainedEnumerator(
            pat="github_pat_11ABCDEFG123456789_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )

        with pytest.raises(
            ValueError, match="target_repo is required for single repo enumeration mode"
        ):
            import asyncio

            asyncio.run(enumerator.enumerate_fine_grained_token("single", None))

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
