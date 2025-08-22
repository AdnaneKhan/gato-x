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

from abc import abstractmethod

from gatox.enumerate.results.complexity import Complexity
from gatox.enumerate.results.confidence import Confidence


class AnalysisResult:
    """
    Holds the results from graph traversals defined in the workflow_graph/visitors module.

    Attributes:
        repository_name (str): The name of the repository.
        issue_type (str): The type of issue identified.
        confidence_score (str): The confidence score (LOW, MEDIUM, HIGH).
        attack_complexity (str): The attack complexity score (LOW, MEDIUM, HIGH).
    """

    def __init__(
        self,
        repository_name,
        issue_type,
        confidence_score: Confidence,
        attack_complexity: Complexity,
    ):
        self.__repository_name = repository_name
        self.__confidence_score = confidence_score
        self.__issue_type = issue_type
        self.__attack_complexity = attack_complexity

    def collect_steps(self, path: list):
        for node in path:
            yield node.get_repr()

    def repo_name(self):
        """
        Gets the repository name.

        Returns:
            str: The repository name.
        """
        return self.__repository_name

    @abstractmethod
    def issue_type(self):
        """
        Gets the issue type.

        Returns:
            str: The issue type.
        """
        return self.__issue_type

    def confidence_score(self):
        """
        Gets the confidence score.

        Returns:
            str: The confidence score.
        """
        return self.__confidence_score

    def attack_complexity(self):
        """
        Gets the attack complexity score.

        Returns:
            str: The attack complexity score.
        """
        return self.__attack_complexity

    @abstractmethod
    def to_machine(self):
        pass
