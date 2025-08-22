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
from typing import IO

from gatox.models.repository import Repository
from gatox.models.workflow import Workflow


class CacheManager:
    """
    Singleton class that manages an in-memory cache for workflows and reusable actions.

    """

    _instance = None

    def __new__(cls):
        """
        Create a new instance of the class. If an instance already exists, return that instance.
        """
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.repo_wf_lookup = {}
            cls._instance.repo_store = {}
            cls._instance.workflow_cache = {}
            cls._instance.action_cache = {}
        return cls._instance

    def get_repos(self) -> list:
        """
        Get all repository names from the in-memory dictionary.

        Returns:
            list: A list of repository names.
        """
        return list(self.repo_store.keys())

    def get_workflow(self, repo_slug: str, workflow_name: str) -> Workflow:
        """
        Get a workflow from the in-memory dictionary.

        Args:
            repo_slug (str): The repository slug.
            workflow_name (str): The name of the workflow.

        Returns:
            Workflow: The workflow object if found, else None.
        """
        key = f"{repo_slug.lower()}:{workflow_name}"
        return self.workflow_cache.get(key, None)

    def is_repo_cached(self, repo_slug: str):
        """
        Check if a repository is in the in-memory dictionary.

        Args:
            repo_slug (str): The repository slug.

        Returns:
            bool: True if the repository is cached, else False.
        """
        return repo_slug.lower() in self.repo_wf_lookup

    def is_action_cached(self, repo_slug: str, action_path: str, ref: str):
        """
        Check if action is cached.

        Args:
            repo_slug (str): The repository slug.
            action_path (str): The path to the action.
            ref (str): The reference (e.g., branch or tag).

        Returns:
            bool: True if the action is cached, else False.
        """
        key = f"{repo_slug.lower()}:{action_path}:{ref}"
        return key in self.action_cache

    def get_workflows(self, repo_slug: str) -> list:
        """
        Get all workflows for a repository from the in-memory dictionary.

        Args:
            repo_slug (str): The repository slug.

        Returns:
            list: A list of workflow objects.
        """
        repo_slug = repo_slug.lower()
        wf_keys = self.repo_wf_lookup.get(repo_slug, None)
        if wf_keys:
            return [
                self.workflow_cache[f"{repo_slug.lower()}:{key}"] for key in wf_keys
            ]
        else:
            return set()

    def get_action(self, repo_slug: str, action_path: str, ref: str):
        """
        Get an action from the in-memory dictionary.

        Args:
            repo_slug (str): The repository slug.
            action_path (str): The path to the action.
            ref (str): The reference (e.g., branch or tag).

        Returns:
            str: The action contents if found, else None.
        """
        key = f"{repo_slug.lower()}:{action_path}:{ref}"
        return self.action_cache.get(key, None)

    def set_repository(self, repository: Repository):
        """
        Set a repository in the in-memory dictionary.

        Args:
            repository (Repository): The repository object to cache.
        """
        key = repository.name.lower()
        self.repo_store[key] = repository

    def get_repository(self, repo_slug: str) -> Repository:
        """
        Get a repository from the in-memory dictionary.

        Args:
            repo_slug (str): The repository slug.

        Returns:
            Repository: The repository object if found, else None.
        """
        return self.repo_store.get(repo_slug.lower(), None)

    def set_workflow(self, repo_slug: str, workflow_name: str, value: Workflow):
        """
        Set a workflow in the in-memory dictionary.

        Args:
            repo_slug (str): The repository slug.
            workflow_name (str): The name of the workflow.
            value (Workflow): The workflow object to cache.
        """
        key = f"{repo_slug.lower()}:{workflow_name}"
        if repo_slug.lower() not in self.repo_wf_lookup:
            self.repo_wf_lookup[repo_slug.lower()] = set()
        self.repo_wf_lookup[repo_slug.lower()].add(workflow_name)
        self.workflow_cache[key] = value

    def set_empty(self, repo_slug: str):
        """
        Set an empty value in the in-memory dictionary for a repository.

        Args:
            repo_slug (str): The repository slug.
        """
        self.repo_wf_lookup[repo_slug.lower()] = set()

    def set_action(self, repo_slug: str, action_path: str, ref: str, value: str):
        """
        Set an action in the in-memory dictionary.

        Args:
            repo_slug (str): The repository slug.
            action_path (str): The path to the action.
            ref (str): The reference (e.g., branch or tag).
            value (str): The action contents to cache.
        """
        key = f"{repo_slug.lower()}:{action_path}:{ref}"
        self.action_cache[key] = value

    def serialize_full_cache(self, output_stream: IO[str]) -> None:
        """
        Serializes the action cache to JSON and writes it to the provided output stream.
        Raises ValueError if the stream is invalid.
        """
        if not hasattr(output_stream, "write"):
            raise ValueError("Output stream must have a 'write' method.")

        json.dump(self._instance.action_cache, output_stream, indent=2)
        output_stream.flush()
