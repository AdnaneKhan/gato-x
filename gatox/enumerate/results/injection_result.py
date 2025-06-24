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

from gatox.enumerate.results.confidence import Confidence
from gatox.enumerate.results.complexity import Complexity
from gatox.enumerate.results.analysis_result import AnalysisResult
from gatox.enumerate.results.issue_type import IssueType


class InjectionResult(AnalysisResult):
    """
    Represents the result of an Injection analysis.
    Inherits from AnalysisResult to include repository name, issue type,
    confidence score, and attack complexity score.
    """

    def __init__(
        self,
        path: list,
        confidence_score: Confidence,
        attack_complexity_score: Complexity,
    ):
        repository_name = path[0].repo_name()

        super().__init__(
            repository_name,
            IssueType.ACTIONS_INJECTION,
            confidence_score,
            attack_complexity_score,
        )

        self.__attack_path = path

    def get_first_and_last_hash(self):
        """Returns a hash of the first and last node. In many
        cases a path with the same start and end is effectively the same
        from a security perspective, so we may not want to keep showing it.
        """
        return hash(
            (
                str(self.__attack_path[0]),
                self.attack_complexity(),
                self.confidence_score(),
            )
        )

    def filter_triggers(self, triggers):
        """Filter triggers to remove non-relevant ones."""
        RELEVANT_TRIGGERS = {
            "issue_comment",
            "pull_request_target",
            "workflow_run",
            "issues",
            "discussion",
            "discussion_comment",
        }
        return list(set(triggers) & RELEVANT_TRIGGERS)

    def to_machine(self):
        result = {
            "repository_name": self.repo_name(),
            "issue_type": self.issue_type(),
            "triggers": self.filter_triggers(self.__attack_path[0].get_triggers()),
            "initial_workflow": self.__attack_path[0].get_workflow_name(),
            "confidence": self.confidence_score(),
            "attack_complexity": self.attack_complexity(),
            "explanation": self.attack_complexity().explain(),
            "path": [node for node in self.collect_steps(self.__attack_path)],
            "injectable_context": self.__attack_path[-1].contexts,
        }

        return result
