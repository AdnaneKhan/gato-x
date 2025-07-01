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
import re

from gatox.configuration.configuration_manager import ConfigurationManager
from gatox.caching.cache_manager import CacheManager
from gatox.enumerate.results.confidence import Confidence
from gatox.enumerate.results.issue_type import IssueType
from gatox.enumerate.results.complexity import Complexity
from gatox.enumerate.results.result_factory import ResultFactory
from gatox.workflow_graph.graph_builder import WorkflowGraphBuilder
from gatox.github.api import Api

from gatox.workflow_parser.utility import (
    CONTEXT_REGEX,
    is_within_last_day,
    return_recent,
)
from gatox.notifications.send_webhook import send_slack_webhook
from gatox.notifications.send_webhook import send_discord_webhook

logger = logging.getLogger(__name__)


class VisitorUtils:
    """Class to track contextual information during a single visit."""

    @staticmethod
    def _add_results(
        path,
        results: dict,
        issue_type,
        confidence: Confidence = Confidence.UNKNOWN,
        complexity: Complexity = Complexity.ZERO_CLICK,
    ):
        repo_name = path[0].repo_name()
        if repo_name not in results:
            results[repo_name] = []

        if issue_type == IssueType.ACTIONS_INJECTION:
            result = ResultFactory.create_injection_result(path, confidence, complexity)
        elif issue_type == IssueType.PWN_REQUEST:
            result = ResultFactory.create_pwn_result(path, confidence, complexity)
        elif issue_type == IssueType.DISPATCH_TOCTOU:
            result = ResultFactory.create_toctou_result(path, confidence, complexity)
        elif issue_type == IssueType.PR_REVIEW_INJECTION:
            result = ResultFactory.create_review_injection_result(
                path, confidence, complexity
            )
        elif issue_type == IssueType.ARTIFACT_POISONING:
            result = ResultFactory.create_artifact_poisoning_result(
                path, confidence, complexity
            )
        else:
            raise ValueError(f"Unknown issue type: {issue_type}")

        results[repo_name].append(result)

    @staticmethod
    async def initialize_action_node(graph, api, node):
        """
        Initialize an action node by removing the 'uninitialized' tag and setting it up.

        Args:
            graph (TaggedGraph):
                The workflow graph containing all nodes.
            api (Api):
                An instance of the API wrapper to interact with external services.
            node (Node):
                The node to be initialized.

        Returns:
            None

        Raises:
            None
        """
        tags = node.get_tags()
        if "uninitialized" in tags:
            logger.info(f"Initializing action node: {node.name}")
            await WorkflowGraphBuilder()._initialize_action_node(node, api)
            graph.remove_tags_from_node(node, ["uninitialized"])

    @staticmethod
    def get_node_with_ancestors(node):
        """Get a node and all its logical ancestors based on naming convention"""
        ancestors = {node}

        # Extract parts from node name
        # Format: 'org/repo:ref:workflow:job:step'
        node_name = str(node)
        parts = node_name.split(":")

        if len(parts) >= 4:  # Has job context
            # Add the job node
            job_node_name = ":".join(parts[:4])
            ancestors.add(job_node_name)

            # Add the workflow node
            workflow_node_name = ":".join(parts[:3])
            ancestors.add(workflow_node_name)

        return ancestors

    @staticmethod
    def check_mutable_ref(ref, start_tags=set()):
        """
        Check if a reference is mutable based on allowed GitHub SHA patterns.

        Args:
            ref (str):
                The reference string to check.
            start_tags (set, optional):
                A set of starting tags for additional context. Defaults to an empty set.

        Returns:
            bool:
                False if the reference is immutable, True otherwise.
        """
        if "github.event.pull_request.head.sha" in ref:
            return False
        elif "github.event.workflow_run.head.sha" in ref:
            return False
        elif "github.sha" in ref:
            return False
        # If the trigger is pull_request_target and we have a sha in the reference, then this is very likely
        # to be from the original trigger in some form and not a mutable reference, so if it is gated we can suppress.
        elif "sha" in ref and "pull_request_target" in start_tags:
            return False
        # This points to the base branch, so it is not going to be exploitable.
        elif "github.ref" in ref and "||" not in ref:
            return False

        return True

    @staticmethod
    def process_context_var(value):
        """
        Process a context variable by extracting relevant parts.

        Args:
            value (str):
                The context variable string to process.

        Returns:
            str:
                The processed variable.
        """
        processed_var = value
        if "${{" in value:
            processed_var = CONTEXT_REGEX.findall(value)
            if processed_var:
                processed_var = processed_var[0]
                if "inputs." in processed_var:
                    processed_var = processed_var.replace("inputs.", "")
            else:
                processed_var = value
        else:
            processed_var = value
        return processed_var

    @staticmethod
    def append_path(head, tail):
        """
        Append the tail to the head if the tail starts with the last element of the head.

        Args:
            head (list):
                The initial path list.
            tail (list):
                The path to append.

        Returns:
            list:
                The combined path if conditions are met; otherwise, the original head.
        """
        if head and tail and head[-1] == tail[0]:
            head.extend(tail[1:])
        return head

    @staticmethod
    def has_dispatch_toctou_risk(workflow_inputs):
        """
        Check if workflow dispatch inputs indicate potential TOCTOU vulnerability.

        This utility function checks if there's a PR number input without a required SHA,
        which could lead to Time-Of-Check to Time-Of-Use vulnerabilities.

        Args:
            workflow_inputs (dict): The workflow dispatch inputs to analyze

        Returns:
            bool: True if there's TOCTOU risk (PR number without required SHA), False otherwise
        """
        if not workflow_inputs:
            return False

        pr_num_found = False
        sha_found = False

        # Process inputs to determine if any contain a PR number.
        # This is a heuristic to identify workflows that are taking a PR number
        # or mutable reference.
        for key, val in workflow_inputs.items():
            if "sha" in key.lower():
                if isinstance(val, dict):
                    # Suppress if sha is required
                    if "required" in val:
                        if val["required"]:
                            sha_found = True

            elif re.search(
                r"(?:^|[\b_])(pr|pull|pull_request|pr_number)(?:[\b_]|$)",
                key,
                re.IGNORECASE,
            ):
                pr_num_found = True

        return pr_num_found and not sha_found

    @staticmethod
    async def add_repo_results(data: dict, api: Api):
        """Add results to the repository data."""
        seen = set()
        for _, flows in data.items():
            for flow in flows:
                seen_before = flow.get_first_and_last_hash()
                if seen_before not in seen:
                    seen.add(seen_before)
                else:
                    continue

                repo = CacheManager().get_repository(flow.repo_name())
                repo.set_results(flow)

                if (
                    ConfigurationManager().NOTIFICATIONS["SLACK_WEBHOOKS"]
                    or ConfigurationManager().NOTIFICATIONS["DISCORD_WEBHOOKS"]
                    and repo
                    and is_within_last_day(repo.repo_data["pushed_at"])
                ):
                    value = flow.to_machine()
                    commit_date, author, sha = await api.get_file_last_updated(
                        flow.repo_name(),
                        ".github/workflows/" + value.get("initial_workflow"),
                    )

                    merge_date = await api.get_commit_merge_date(flow.repo_name(), sha)
                    if merge_date:
                        # If there is a PR merged, get the most recent.
                        commit_date = return_recent(commit_date, merge_date)

                    if is_within_last_day(commit_date):
                        asyncio.create_task(send_slack_webhook(value))
                        asyncio.create_task(send_discord_webhook(value))

    @staticmethod
    def matches_deployment_rule(deployment, rules):
        """
        Returns True if any rule string is a substring of the deployment string.
        Args:
            deployment (str): The deployment environment name.
            rules (Iterable[str]): The list of rule strings.
        Returns:
            bool: True if any rule is a substring of deployment, else False.
        """
        return any(rule in str(deployment) for rule in rules)

    @staticmethod
    async def check_deployment_approval_gate(
        node, rule_cache, api, input_lookup, env_lookup
    ):
        """
        Checks if any deployment environment for the node matches a protection rule (substring match).
        Returns True if approval gate should be set, else False.
        """
        # Assumes node.deployments is not None
        if node.repo_name() in rule_cache:
            rules = rule_cache[node.repo_name()]
        else:
            rules = await api.get_all_environment_protection_rules(node.repo_name())
            rule_cache[node.repo_name()] = rules
        for deployment in node.deployments:
            if isinstance(deployment, dict):
                deployment = deployment["name"]
            deployment = VisitorUtils.process_context_var(deployment)
            if deployment in input_lookup:
                deployment = input_lookup[deployment]
            elif deployment in env_lookup:
                deployment = env_lookup[deployment]
            if VisitorUtils.matches_deployment_rule(deployment, rules):
                return True
        return False
