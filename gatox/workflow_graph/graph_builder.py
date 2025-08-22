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
import logging
import traceback

from gatox.caching.cache_manager import CacheManager
from gatox.models.composite import Composite
from gatox.models.repository import Repository
from gatox.models.workflow import Workflow
from gatox.workflow_graph.graph.tagged_graph import TaggedGraph
from gatox.workflow_graph.node_factory import NodeFactory
from gatox.workflow_graph.nodes.action import ActionNode
from gatox.workflow_graph.nodes.job import JobNode
from gatox.workflow_graph.nodes.workflow import WorkflowNode

logger = logging.getLogger(__name__)


class WorkflowGraphBuilder:
    _instance = None
    _action_locks = None
    _action_locks_lock = None

    def __new__(cls):
        """
        Create a new instance of the class. If an instance already exists, return that instance.
        """
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.graph = TaggedGraph(cls._instance)
            cls._action_locks = {}
            cls._action_locks_lock = asyncio.Lock()

        return cls._instance

    async def _get_action_lock(self, repo: str, path: str, ref: str) -> asyncio.Lock:
        """
        Get or create a lock for a specific action identified by repo, path, and ref.

        Args:
            repo (str): The repository name.
            path (str): The path to the action file.
            ref (str): The reference (e.g., branch or tag).

        Returns:
            asyncio.Lock: A lock specific to this action.
        """
        action_key = f"{repo}:{path}:{ref}"

        async with self._action_locks_lock:
            if action_key not in self._action_locks:
                self._action_locks[action_key] = asyncio.Lock()
            return self._action_locks[action_key]

    def build_lone_repo_graph(self, repo_wrapper: Repository):
        """
        Build a graph node for a repository that has no workflows.
        """
        repo, added = NodeFactory.create_repo_node(repo_wrapper)
        if added:
            self.graph.add_node(repo, **repo.get_attrs())

    def add_callee_job(
        self, workflow_wrapper: Workflow, callee: str, job_def: dict, job_node: JobNode
    ):
        """
        Adds a reference to a called workflow (reusable workflow)
        """
        if not job_def or not job_node:
            return

        callee_node = NodeFactory.create_called_workflow_node(
            callee, workflow_wrapper.branch, workflow_wrapper.repo_name
        )

        callee_node.add_caller_reference(job_node)

        if callee_node not in self.graph.nodes:
            self.graph.add_node(callee_node, **callee_node.get_attrs())
        self.graph.add_edge(job_node, callee_node, relation="uses")

    async def _initialize_action_node(self, node: ActionNode, api):
        """
        Initialize an ActionNode by retrieving and parsing its contents.

        Args:
            node (ActionNode): The action node to initialize.
            api (object): The API client used to retrieve raw action contents.
        """
        action_metadata = node.action_info
        node.initialized = True

        async def get_action_contents(repo, path, ref):
            """
            Retrieve and cache the action contents.

            Args:
                repo (str): The repository name.
                path (str): The path to the action file.
                ref (str): The reference (e.g., branch or tag).

            Returns:
                str: The contents of the action file.
            """
            action_lock = await self._get_action_lock(repo, path, ref)
            async with action_lock:
                contents = CacheManager().get_action(repo, path, ref)
                if not contents:
                    contents = await api.retrieve_raw_action(repo, path, ref)
                    if contents:
                        CacheManager().set_action(repo, path, ref, contents)
                return contents

        ref = node.caller_ref if action_metadata["local"] else action_metadata["ref"]
        contents = await get_action_contents(
            action_metadata["repo"], action_metadata["path"], ref
        )

        if not contents:
            return False

        parsed_action = Composite(contents)
        if parsed_action.composite:
            steps = parsed_action.parsed_yml["runs"].get("steps", [])
            if type(steps) is not list:
                raise ValueError("Steps must be a list")

            prev_step_node = None
            for iter, step in enumerate(steps):
                calling_name = parsed_action.parsed_yml.get("name", "EMPTY")
                step_node = NodeFactory.create_step_node(
                    step,
                    ref,
                    action_metadata["repo"],
                    action_metadata["path"],
                    calling_name,
                    iter,
                    line_number=parsed_action.source_map["steps"][iter],
                )

                self.graph.add_node(step_node, **step_node.get_attrs())

                # Steps are sequential, so for reachability checks
                # the job only "contains" the first step.
                if prev_step_node:
                    self.graph.add_edge(prev_step_node, step_node, relation="next")
                else:
                    self.graph.add_edge(node, step_node, relation="contains")
                prev_step_node = step_node

                # Handle nested actions within composite actions
                if "uses" in step:
                    action_name = step["uses"]

                    # Create usage context for nested action
                    usage_context = {
                        "workflow_name": f"composite-{node.name}",
                        "job_id": "composite",
                        "step_index": iter,
                    }

                    nested_action_node = NodeFactory.create_action_node(
                        action_name,
                        ref,
                        action_metadata["path"],
                        action_metadata["repo"],
                        usage_context=usage_context,
                    )
                    self.graph.add_node(
                        nested_action_node, **nested_action_node.get_attrs()
                    )
                    self.graph.add_edge(step_node, nested_action_node, relation="uses")

    async def _initialize_callee_node(self, workflow: WorkflowNode, api):
        """Initialize a callee workflow with the workflow yaml"""
        if "uninitialized" in workflow.get_tags():
            slug, ref, path = workflow.get_parts()
            callee_wf = CacheManager().get_workflow(slug, f"{path}:{ref}")
            if not callee_wf:
                callee_wf = await api.retrieve_repo_file(slug, path, ref)
                if callee_wf:
                    CacheManager().set_workflow(slug, f"{path}:{ref}", callee_wf)
                else:
                    # Workflow file doesn't exist - mark as non-existent to prevent re-attempts
                    logger.warning(f"Workflow file not found: {slug}:{path}:{ref}")
                    workflow.mark_as_non_existent()
                    self.graph.remove_tags_from_node(workflow, ["uninitialized"])
                    self.graph.add_tags_to_node(workflow, ["non_existent"])
                    return

            if callee_wf and not callee_wf.isInvalid():
                workflow.initialize(callee_wf)
            else:
                raise ValueError("Invalid callee workflow!")

            self.graph.remove_tags_from_node(workflow, ["uninitialized"])
            self.graph.add_tags_to_node(workflow, ["initialized"])

            await self.build_workflow_jobs(callee_wf, workflow)

    def __transform_list_job(self, jobs: list):
        """Transforms a list job into a dictionary job."""
        jobs_dict = {}
        for job in jobs:
            if type(job) is not dict:
                raise ValueError("Job must be a dictionary")
            if "name" not in job:
                raise ValueError("Job in list format must have a name field")
            name = job.pop("name")  # Remove name field and use as key
            jobs_dict[name] = job
        jobs = jobs_dict

        return jobs

    async def build_graph_from_yaml(
        self, workflow_wrapper: Workflow, repo_wrapper: Repository
    ):
        """
        Build a graph from a workflow yaml file.
        """
        if workflow_wrapper.isInvalid() or not repo_wrapper:
            return False

        repo, added = NodeFactory.create_repo_node(repo_wrapper)
        if added:
            self.graph.add_node(repo, **repo.get_attrs())
        try:
            wf_node = NodeFactory.create_workflow_node(
                workflow_wrapper,
                workflow_wrapper.branch,
                workflow_wrapper.repo_name,
                workflow_wrapper.getPath(),
            )
            if "uninitialized" not in wf_node.get_tags():
                self.graph.remove_tags_from_node(wf_node, "uninitialized")

            self.graph.add_node(wf_node, **wf_node.get_attrs())
            self.graph.add_edge(repo, wf_node, relation="contains")
            await self.build_workflow_jobs(workflow_wrapper, wf_node)

            return True
        except ValueError:
            logger.warning(
                f"Error building graph from workflow, likely syntax error: {workflow_wrapper.getPath()}, {repo_wrapper.name}"
            )
            # Likely encountered a syntax error in the workflow
            return False
        except Exception as e:
            logger.error(
                f"Exception building graph from workflow, likely Gato-X bug: {workflow_wrapper.getPath()}"
            )
            logger.error(str(e))
            logger.error(traceback.format_exc())
            # Likely gato-x bug
            return False

    async def build_workflow_jobs(
        self, workflow_wrapper: Workflow, wf_node: WorkflowNode
    ):
        """Build workflow jobs from the parsed yaml file."""
        workflow = workflow_wrapper.parsed_yml
        jobs = workflow.get("jobs", {})
        if not jobs:
            raise ValueError(
                f"No jobs found in workflow: {workflow_wrapper.workflow_name}"
            )

        if isinstance(jobs, list):
            jobs = self.__transform_list_job(jobs)

        for job_name, job_def in jobs.items():
            if not job_def:
                # This means there is a syntax error
                # in the workflow. Gato-X cannot process
                # malformed workflows.
                raise ValueError("Job definition is empty")

            job_node = NodeFactory.create_job_node(
                job_name,
                workflow_wrapper.branch,
                workflow_wrapper.repo_name,
                workflow_wrapper.getPath(),
                line_number=workflow_wrapper.source_map["jobs"][job_name]["line"],
            )
            job_node.populate(job_def, wf_node)
            self.graph.add_node(job_node, **job_node.get_attrs())

            # Handle called workflows
            callee = job_def.get("uses", None)
            if callee:
                self.add_callee_job(workflow_wrapper, callee, job_def, job_node)

            needs = job_def.get("needs", [])
            # If single entry then set as array
            if type(needs) is str:
                needs = [needs]
            prev_node = None
            for i, need in enumerate(needs):
                need_node = NodeFactory.create_job_node(
                    need,
                    workflow_wrapper.branch,
                    workflow_wrapper.repo_name,
                    workflow_wrapper.getPath(),
                    needs=needs,
                    line_number=workflow_wrapper.source_map["jobs"][need]["line"],
                )
                job_node.add_needs(need_node)
                self.graph.add_node(need_node, **need_node.get_attrs())

                # Add an extra dependency so subsequent needs depend on the previous one
                if i > 0:
                    self.graph.add_edge(prev_node, need_node, relation="extra_depends")
                self.graph.add_edge(need_node, job_node, relation="depends")
                prev_node = need_node

            if not needs:
                self.graph.add_edge(wf_node, job_node, relation="contains")

            # Handle steps
            steps = job_def.get("steps", [])
            prev_step_node = None
            for iter, step in enumerate(steps):
                step_node = NodeFactory.create_step_node(
                    step,
                    workflow_wrapper.branch,
                    workflow_wrapper.repo_name,
                    workflow_wrapper.getPath(),
                    job_name,
                    iter,
                    line_number=workflow_wrapper.source_map["jobs"][job_name]["steps"][
                        iter
                    ],
                )

                self.graph.add_node(step_node, **step_node.get_attrs())

                # Steps are sequential, so for reachability checks
                # the job only "contains" the first step.
                if prev_step_node:
                    self.graph.add_edge(prev_step_node, step_node, relation="next")
                else:
                    self.graph.add_edge(job_node, step_node, relation="contains")
                prev_step_node = step_node
                # Handle actions
                if "uses" in step:
                    action_name = step["uses"]

                    # Create usage context to ensure unique action nodes
                    usage_context = {
                        "workflow_name": workflow_wrapper.getPath(),
                        "job_id": job_name,
                        "step_index": iter,
                    }

                    action_node = NodeFactory.create_action_node(
                        action_name,
                        workflow_wrapper.branch,
                        workflow_wrapper.getPath(),
                        workflow_wrapper.repo_name,
                        params=step.get("with", {}),
                        usage_context=usage_context,
                    )
                    self.graph.add_node(action_node, **action_node.get_attrs())
                    self.graph.add_edge(step_node, action_node, relation="uses")
                    if action_node.initialized:
                        prev_step_node = action_node

    async def initialize_node(self, node, api):
        tags = node.get_tags()

        # Skip nodes that are already marked as non-existent
        if "non_existent" in tags:
            logger.info(f"Skipping initialization of non-existent node: {node.name}")
            return

        if "uninitialized" in tags:
            if "ActionNode" in tags:
                try:
                    await self._initialize_action_node(node, api)
                except ValueError as e:
                    logger.warning(f"Error initializing action node: {e}")
                    # Likely encountered a syntax error in the workflow
                    return
            elif "WorkflowNode" in tags:
                try:
                    await self._initialize_callee_node(node, api)
                except ValueError as e:
                    logger.warning(f"Error initializing callee node: {e}, {node.name}")
                    # Likely encountered a syntax error in the workflow
                    return
