import unittest
from unittest.mock import MagicMock
from gatox.enumerate.ingest.ingest import DataIngestor
from gatox.caching.cache_manager import CacheManager


class TestConstructWorkflowCache(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.workflow = MagicMock()
        self.repository = MagicMock()
        CacheManager._instance = None
        self.cache_manager = CacheManager()
        MagicMock(return_value=self.workflow)
        MagicMock(return_value=self.repository)
        self.yml_results = [
            {
                "nameWithOwner": "owner/repo1",
                "object": {
                    "entries": [
                        {
                            "name": "workflow1.yml",
                            "type": "blob",
                            "object": {"text": "content1"},
                        }
                    ]
                },
                "url": "http://example.com/repo1",
                "isPrivate": False,
                "defaultBranchRef": {"name": "main"},
                "isFork": False,
                "stargazers": {"totalCount": 10},
                "pushedAt": "2023-01-01T00:00:00Z",
                "viewerPermission": "ADMIN",
                "isArchived": False,
                "forkingAllowed": True,
                "environments": {"edges": []},
            }
        ]

    async def test_construct_workflow_cache_none(self):
        # Test with None input
        assert await DataIngestor.construct_workflow_cache(None) is None

    async def test_construct_workflow_cache_empty_list(self):
        # Test with empty list input
        await DataIngestor.construct_workflow_cache([])

        assert CacheManager()._instance.repo_wf_lookup == {}
        assert CacheManager()._instance.workflow_cache == {}

    async def test_construct_workflow_cache_valid_input(self):
        # Test with valid input
        await DataIngestor.construct_workflow_cache(self.yml_results)

        assert CacheManager().is_repo_cached("owner/repo1") is True

    async def test_construct_workflow_cache_malformed_data(self):
        # Test with malformed data
        malformed_data = [{"invalid_key": "invalid_value"}]
        await DataIngestor.construct_workflow_cache(malformed_data)

        assert not CacheManager().is_repo_cached("invalid_key")


if __name__ == "__main__":
    unittest.main()
