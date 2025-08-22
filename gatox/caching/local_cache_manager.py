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

import json

from gatox.caching.cache_manager import CacheManager


class LocalCacheFactory:
    """
    A factory class for managing local cache operations in Gato-X.

    This class provides static methods to serialize and deserialize the cache
    to/from local files. The cache stores GitHub Actions metadata in a format
    of 'repo_slug:action_path:ref'.
    """

    @staticmethod
    def dump_cache(output_file: str):
        """
        Serializes and dumps the current cache state to a local file.

        The cache is written in JSON format containing key-value pairs where
        keys follow the format 'repo_slug:action_path:ref'.

        Args:
            output_file (str): Path to the file where the cache should be written.
        """
        with open(output_file, "w") as f:
            CacheManager().serialize_full_cache(f)

    @staticmethod
    def load_cache_from_file(saved_cache: str):
        """
        Loads and deserializes cache data from a local file into memory.

        The method validates the cache format and enforces naming conventions
        before loading the cache entries into the CacheManager.

        Args:
            saved_cache (str): Path to the file containing the cached data.

        Raises:
            ValueError: If the cache key format is invalid or if repository
                       slug is not lowercase.

        Example cache key format:
            'owner/repo:actions/checkout:v2'
        """
        with open(saved_cache) as f:
            data = json.load(f)
            for key, val in data.items():
                parts = key.split(":")
                if len(parts) != 3:
                    raise ValueError(
                        f"Invalid cache key format '{key}'. Expected 'repo_slug:action_path:ref'."
                    )
                if parts[0] != parts[0].lower():
                    raise ValueError(f"Repository slug '{parts[0]}' must be lowercase.")

                repo_slug, action_path, ref = parts
                CacheManager().set_action(repo_slug, action_path, ref, val)
