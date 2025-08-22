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

from gatox.git.git import Git
from gatox.models.repository import Repository
from gatox.workflow_graph.graph_builder import WorkflowGraphBuilder


class IngestNonDefault:
    """Class to handle ingesting non-default branches asynchronously."""

    _tasks = []
    _api = None

    @classmethod
    async def ingest(cls, repo: Repository, api):
        """
        Enqueue a repository ingest task.
        If the API hasn't been initialized, initialize it.
        """
        if cls._api is None:
            cls._api = api

        # Create and store the task
        task = asyncio.create_task(cls._process_repo(repo))
        cls._tasks.append(task)
        return task

    @classmethod
    async def _process_repo(cls, repo: Repository):
        """Actual processing of a repository's non-default workflows."""
        git_client = Git(cls._api.pat, repo.name)
        workflows = await git_client.get_non_default()
        for workflow in workflows:
            await WorkflowGraphBuilder().build_graph_from_yaml(workflow, repo)

    @classmethod
    async def pool_empty(cls):
        """
        Returns a Future that completes once all currently-enqueued tasks finish.
        """
        if not cls._tasks:
            # No work was ever queued
            return None

        # Wait for all tasks to complete
        await asyncio.gather(*cls._tasks, return_exceptions=True)
        cls._tasks = []  # Clear the tasks list
        return None
