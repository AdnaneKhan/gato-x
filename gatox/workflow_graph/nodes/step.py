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
from gatox.workflow_parser.utility import filter_tokens, getTokens, parse_script


class StepNode(Node):
    """
    Wrapper class for a GitHub Actions workflow step.

    Attributes:
        name (str): A unique identifier for the step node.
        type (str): The type of the step (script, action, or unknown).
        is_checkout (bool): Indicates if the step is a checkout step.
        id (str): The ID of the step.
        is_sink (bool): Indicates if the step is a sink.
        hard_gate (bool): Indicates if the step is a hard gate.
        soft_gate (bool): Indicates if the step is a soft gate.
        params (dict): Parameters associated with the step.
        contexts (list): List of contexts associated with the step.
        metadata (bool): Metadata associated with the step.
        outputs (dict): Outputs of the step.
        uses (str): The uses of the step if it is an action.
    """

    def __init__(
        self,
        step_data: dict,
        ref: str,
        repo_name: str,
        workflow_path: str,
        job_name: str,
        step_number: int,
        line_number=None,
    ):
        """
        Constructor for the step wrapper.

        Args:
            step_data (dict): The data for the step.
            ref (str): The reference (e.g., branch or tag).
            repo_name (str): The name of the repository.
            workflow_path (str): The path to the workflow file.
            job_name (str): The name of the job.
            step_number (int): The step number within the job.
        """
        if type(step_data) is not dict:
            raise ValueError(f"Step data must be a dictionary: {str(step_data)}.")

        # Create a unique ID for this step.
        if "name" in step_data:
            name = f"{repo_name}:{ref}:{workflow_path}:{job_name}:{step_data['name']}_{step_number}"
        else:
            name = f"{repo_name}:{ref}:{workflow_path}:{job_name}:step_{step_number}"

        super().__init__(name, line_number)

        self.type = self.__get_type(step_data)
        self.is_checkout = False
        self.id = step_data.get("id", None)
        self.if_condition = step_data.get("if", "")
        if type(self.if_condition) is str:
            self.if_condition = self.if_condition.replace("\n", "")
        else:
            self.if_condition = None
        self.if_evaluation = None
        # Need to check if it's actually something because it could be none
        # if self.if_condition:
        #     self.if_condition = self.if_condition.replace("github.", "")
        self.is_sink = False
        self.hard_gate = False
        self.soft_gate = False
        self.params = {}
        self.contexts = []
        self.__repo_name = repo_name
        self.__step_data = None
        self.metadata = False
        self.outputs = step_data.get("outputs", {})

        if self.type == "script":
            self.__process_script(step_data["run"])
            self.__step_data = step_data["run"]
        elif self.type == "action":
            self.uses = step_data["uses"]
            self.__process_action(step_data)

    def __get_type(self, step_data: dict):
        """
        Retrieve the type of the step.

        Args:
            step_data (dict): The data for the step.

        Returns:
            str: The type of the step (script, action, or unknown).
        """
        if "uses" in step_data:
            return "action"
        elif "run" in step_data:
            return "script"
        else:
            return "unknown"

    def get_if(self):
        return self.if_condition

    def get_metadata(self):
        return self.metadata

    def __process_script(self, script: str):
        """
        Process a 'run' script as part of a step.

        Args:
            script (str): The script to process.
        """
        if not script:
            return

        insights = parse_script(script)

        self.is_checkout = insights["is_checkout"]
        self.is_sink = insights["is_sink"]
        self.metadata = insights["metadata"]
        self.hard_gate = insights["hard_gate"]
        self.soft_gate = insights["soft_gate"]

        self.contexts = filter_tokens(getTokens(script))

    def __process_action(self, step_data: dict):
        """
        Process an 'action' step.

        Args:
            step_data (dict): The data for the step.
        """
        self.params = step_data.get("with", {})

        if "/checkout" in self.uses and self.params and "ref" in self.params:
            ref_param = self.params["ref"]
            if isinstance(ref_param, str):
                ref_param = ref_param.lower()
                if "${{" in ref_param and (
                    "base" not in ref_param
                    and "github.event.repository.default_branch" not in ref_param
                ):
                    if (
                        "github.event.pull_request.head.ref" in ref_param
                        or "github.head_ref" in ref_param
                        or "tag" in ref_param
                        or "head_branch" in ref_param
                    ) and "repository" not in self.params:
                        self.is_checkout = False

                    elif "repository" in self.params and self.params[
                        "repository"
                    ].startswith(self.__repo_name.split("/")[0]):
                        self.is_checkout = False
                    else:
                        self.metadata = ref_param
                        self.is_checkout = True
        elif "github-script" in self.uses and "script" in self.params:
            contents = self.params["script"]
            self.contexts = filter_tokens(getTokens(contents))
            self.__step_data = contents
            insights = parse_script(contents)

            self.is_checkout = insights["is_checkout"]
            self.is_sink = insights["is_sink"]
            self.metadata = insights["metadata"]
            self.hard_gate = insights["hard_gate"]
            self.soft_gate = insights["soft_gate"]

            if "require('." in contents:
                self.is_sink = True
        elif self.uses.startswith("./"):
            self.__step_data = self.uses
            self.is_sink = True
        elif "ruby/setup-ruby" in self.uses:
            self.is_sink = self.params.get("bundler-cache", False)
        elif "actions/setup-node" in self.uses:
            self.is_sink = self.params.get("cache", False)
            if self.is_sink:
                self.__step_data = (
                    f"actions/setup-node with cache: {self.params.get('cache')}"
                )
        elif "dependabot/fetch-metadata" in self.uses:
            self.hard_gate = True

    def __hash__(self):
        """
        Return the hash value of the StepNode instance.

        Returns:
            int: The hash value of the StepNode instance.
        """
        return hash((self.name, self.__class__.__name__))

    def __eq__(self, other):
        """
        Check if two StepNode instances are equal.

        Args:
            other (StepNode): Another StepNode instance to compare with.

        Returns:
            bool: True if the instances are equal, False otherwise.
        """
        return isinstance(other, self.__class__) and self.name == other.name

    def get_step_data(self):
        """
        Get the data associated with the step if it is a script, None otherwise.

        Returns:
            str: The data associated with the step.
        """
        return self.__step_data

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

        if self.is_checkout:
            value["checkout_ref"] = self.metadata

        if self.contexts:
            value["contexts"] = self.contexts

        return value

    def get_tags(self):
        """
        Get the tags associated with the StepNode instance.

        Returns:
            set: A set containing the class name of the StepNode instance and additional tags.
        """
        tags = super().get_tags()

        if self.is_checkout:
            tags.add("checkout")

        if self.is_sink:
            tags.add("sink")

        if self.contexts:
            tags.add("injectable")

        if self.hard_gate:
            tags.add("permission_blocker")

        if self.soft_gate:
            tags.add("permission_check")

        return tags

    def get_attrs(self):
        """
        Get the attributes associated with the StepNode instance.

        Returns:
            dict: A dictionary containing attributes of the StepNode instance.
        """
        return {
            self.__class__.__name__: True,
            "type": self.type,
            "is_soft_gate": self.soft_gate,
            "is_hard_gate": self.hard_gate,
        }
