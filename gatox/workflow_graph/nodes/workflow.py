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

import logging
from typing import Literal

from gatox.workflow_graph.nodes.node import Node
from gatox.workflow_graph.nodes.job import JobNode
from gatox.models.workflow import Workflow

logger = logging.getLogger(__name__)


class WorkflowNode(Node):
    """Workflow node"""

    name: str
    inputs: dict

    # Workflow permissions, if none are specified, then the default permissions are in effect identified
    # by the special string `default`.
    # An empty dict `{}` is valid and indicate the token has no permissions.
    # See https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions#defining-access-for-the-github_token-scopes
    permissions: Literal["default", "read-all", "write-all"] | dict

    def __init__(self, ref: str, repo_name: str, workflow_path: str):
        """Constructor for workflow wrapper."""

        # Create a unique ID for this workflow.
        super().__init__(f"{repo_name}:{ref}:{workflow_path}")
        # By default, a workflow node is "uninitialized" until it is processed
        # with the workflow YAML. We sometimes add unititialized nodes to the
        # graph if a workflow references another workflow that has not been
        # processed yet.
        self.uninitialized = True
        self.__workflow_path = workflow_path
        self.__triggers = []
        self.__callers = []
        self.__excluded = False
        self.__repo_name = repo_name
        self.__env_vars = {}
        self.inputs = {}
        self.permissions = "default"

    def __hash__(self):
        return hash((self.name, self.__class__.__name__))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.name == other.name

    def set_params(self, params):
        """ """
        self.params = params

    def get_parts(self):
        """ """
        repo, ref, path = self.name.split(":")

        return repo, ref, path

    def repo_name(self):
        """ """
        return self.__repo_name

    def get_workflow_name(self):
        """
        Get name of the workflow file associated with the JobNode instance.

        Returns:
            str: The path to the workflow file.
        """
        return self.__workflow_path.replace(".github/workflows/", "")

    def __process_triggers(self, workflow_data: dict):
        """Retrieve the triggers associated with the Workflow node."""
        triggers = workflow_data.get("on", [])
        extracted_triggers = []

        if isinstance(triggers, list):
            return triggers
        elif isinstance(triggers, str):
            return [triggers]
        elif isinstance(triggers, dict):
            for trigger, trigger_conditions in triggers.items():
                if trigger == "pull_request_target":
                    if trigger_conditions and "types" in trigger_conditions:
                        if (
                            "labeled" in trigger_conditions["types"]
                            and len(trigger_conditions["types"]) == 1
                        ):
                            extracted_triggers.append(
                                f"{trigger}:{trigger_conditions['types'][0]}"
                            )
                        else:
                            extracted_triggers.append(trigger)
                    else:
                        extracted_triggers.append(trigger)
                elif trigger == "workflow_run":
                    if "branches" in trigger_conditions:
                        # If the branches filter is present, then
                        # forks cannot trigger the workflow.
                        self.__excluded = True
                    else:
                        extracted_triggers.append(trigger)
                else:
                    extracted_triggers.append(trigger)

        return extracted_triggers

    def __process_inputs(self, workflow_data: dict):
        try:
            if (
                "workflow_dispatch" in self.__triggers
                and isinstance(workflow_data["on"], dict)
                and isinstance(workflow_data["on"]["workflow_dispatch"], dict)
                and "inputs" in workflow_data["on"]["workflow_dispatch"]
            ):
                return workflow_data["on"]["workflow_dispatch"]["inputs"]
            else:
                return {}
        except TypeError:
            logger.error(workflow_data["on"])

    def __process_envs(self, workflow_data: dict):
        if "env" in workflow_data:
            return workflow_data["env"]
        else:
            return {}

    def excluded(self):
        """Returns whether the workflow is excluded as it cannot be
        triggered from a fork."""
        return self.__excluded

    def get_env_vars(self):
        """Returns environment variables for the workflow."""
        return self.__env_vars

    def add_caller_reference(self, caller: JobNode):
        """Add a reference to a JobNode that calls this Workflow node,
        if it is not already marked (as we can reach it multiple times
        for nested relationships).
        """
        if caller not in self.__callers:
            self.__callers.append(caller)

    def get_caller_workflows(self):
        """Retrieve a set of the workflows that call this Workflow node."""
        if not self.__callers:
            return set()
        else:
            return set([caller.get_workflow() for caller in self.__callers])

    def initialize(self, workflow: Workflow):
        """Initialize the Workflow node with the parsed workflow data."""
        self.__triggers = self.__process_triggers(workflow.parsed_yml)
        self.__env_vars = self.__process_envs(workflow.parsed_yml)
        self.permissions = workflow.parsed_yml.get("permissions", "default")

        self.inputs = self.__process_inputs(workflow.parsed_yml)
        self.uninitialized = False

    def get_triggers(self):
        """Retrieve the triggers associated with the Workflow node."""
        return self.__triggers

    def get_tags(self):
        """ """
        tags = super().get_tags()

        if self.uninitialized:
            tags.add("uninitialized")
        else:
            tags.add("initialized")

        for trigger in self.__triggers:
            tags.add(trigger)

        return tags

    def get_attrs(self):
        """Retrieve node attributes associated with the Workflow node."""
        return {}
