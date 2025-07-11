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

from gatox.workflow_graph.nodes.node import Node

from gatox.workflow_parser.utility import (
    process_matrix,
    process_runner,
    validate_if_check,
)


class JobNode(Node):
    """
    Wrapper class for a GitHub Actions workflow job.

    Attributes:
        name (str): A unique identifier for the job node.
        params (dict): Parameters associated with the job node.
    """

    def __init__(
        self,
        job_name: str,
        ref: str,
        repo_name: str,
        workflow_path: str,
        line_number=None,
    ):
        """
        Constructor for the job wrapper.

        Args:
            job_name (str): The name of the job.
            ref (str): The reference (e.g., branch or tag).
            repo_name (str): The name of the repository.
            workflow_path (str): The path to the workflow file.
        """
        # Create a unique ID for this step.
        super().__init__(f"{repo_name}:{ref}:{workflow_path}:{job_name}", line_number)
        self.ref = ref
        self.__workflow_path = workflow_path
        self.params = {}
        self.__repo_name = repo_name
        self.if_condition = None
        self.if_evaluation = None
        self.wf_reference = None
        self.needs = []
        self.deployments = []
        self.__env_vars = {}
        self.self_hosted = False
        self.outputs = {}

    def __hash__(self):
        """
        Return the hash value of the JobNode instance.

        Returns:
            int: The hash value of the JobNode instance.
        """
        return hash((self.name, self.__class__.__name__))

    def _check_selfhosted(self, job_def: dict):
        """Returns true if the job might run on a self-hosted runner."""

        # Easy
        if "self-hosted" in job_def["runs-on"]:
            return True
        # Process a matrix job
        elif "matrix." in job_def["runs-on"]:
            return process_matrix(job_def, job_def["runs-on"])
        # Process standard label
        else:
            return process_runner(job_def["runs-on"])

    def get_workflow_name(self):
        """
        Get name of the workflow file associated with the JobNode instance.

        Returns:
            str: The path to the workflow file.
        """
        return self.__workflow_path.replace(".github/workflows/", "")

    def get_workflow(self):
        return self.wf_reference

    def get_env_vars(self):
        """Returns environemnt variables used by the job in dictionary format."""
        return self.__env_vars

    def repo_name(self):
        """Return the repository name."""
        return self.__repo_name

    def get_if_eval(self):
        """ """
        return self.if_evaluation

    def evaluate_if(self):
        """ """
        if self.if_condition:
            return validate_if_check(self.if_condition, self.__env_vars)
        return True

    def populate(self, job_def, wf_node):
        self.wf_reference = wf_node

        if not isinstance(job_def, dict):
            raise ValueError(
                "Job definition is not a dictionary, the workflow yaml is likely invalid."
            )

        self.outputs = job_def.get("outputs", {})

        params = job_def.get("with", {})
        if params:
            self.set_params(params)

        if "runs-on" in job_def:
            self.self_hosted = self._check_selfhosted(job_def)

        if "environment" in job_def:
            if type(job_def["environment"]) is list:
                self.deployments.extend(job_def["environment"])
            else:
                self.deployments.append(job_def["environment"])

        if "env" in job_def and type(job_def["env"]) is dict:
            self.__env_vars = job_def["env"]

        if job_def and "if" in job_def:
            self.if_condition = job_def["if"]
            if type(self.if_condition) is str:
                self.if_condition = self.if_condition.replace("\n", "")
                self.if_evaluation = validate_if_check(self.if_condition, {})
            else:
                self.if_condition = None
        else:
            self.if_evaluation = True

    def __eq__(self, other):
        """
        Check if two JobNode instances are equal.

        Args:
            other (JobNode): Another JobNode instance to compare with.

        Returns:
            bool: True if the instances are equal, False otherwise.
        """
        return isinstance(other, self.__class__) and self.name == other.name

    def get_if(self):
        return self.if_condition

    def get_repr(self):
        """
        Get the representation of the Node instance.

        Returns:
            value: A dict representation of the Node instance.
        """

        value = super().get_repr()
        if self.get_if():
            value["if"] = self.get_if()
            if self.if_evaluation is not None and type(self.if_evaluation) is bool:
                value["if_eval"] = self.if_evaluation

        return value

    def set_params(self, params):
        self.params = params

    def get_needs(self):
        """ """
        return self.needs

    def add_needs(self, need_node):
        """
        Add a need to the JobNode instance.
        """
        self.needs.append(need_node)

    def get_tags(self):
        """
        Get the tags associated with the JobNode instance.

        Returns:
            set: A set containing the class name of the JobNode instance.
        """
        tags = super().get_tags()

        if self.self_hosted:
            tags.add("self-hosted")

        return tags

    def get_attrs(self):
        """
        Get the attributes associated with the JobNode instance.

        Returns:
            dict: A dictionary containing attributes of the JobNode instance.
        """
        attr_dict = {
            self.__class__.__name__: True,
            "is_soft_gate": False,
            "is_hard_gate": False,
        }
        return attr_dict
