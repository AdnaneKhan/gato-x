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

from enum import Enum


class Complexity(str, Enum):
    """
    Represents the complexity level of a workflow vulnerability.

    Values:
        ZERO_CLICK: Exploit requires no user interaction
        TOCTOU: Time-of-check to time-of-use vulnerability
        BROKEN_ACCESS: Broken access control vulnerability
        DEFAULT_DEPENDENT: Vulnerability depends on default configuration
    """

    ZERO_CLICK = "No Interaction"
    PREVIOUS_CONTRIBUTOR = "Previous Contributor"
    FOLLOW_UP = "Persistent Approval Gated"
    TOCTOU = "Time-of-Check to Time-of-Use"
    BROKEN_ACCESS = "Broken Access Control"

    def __str__(self) -> str:
        return str(self.value)

    def __repr__(self) -> str:
        return str(self.value)

    def explain(self) -> str:
        if self.value == Complexity.ZERO_CLICK:
            return "Exploit requires no user interaction, you must still confirm there are no custom permission checks that would prevent the attack."
        elif self.value == Complexity.PREVIOUS_CONTRIBUTOR:
            return "Exploit requires a previous contributor to the repository, and the repository must use the default pull-request approval setting."
        elif self.value == Complexity.FOLLOW_UP:
            return "Exploit requires a maintainer to perform some state changing action, such as labeling a PR, at that point the attacker can follow up with their payload."
        elif self.value == Complexity.TOCTOU:
            return "Exploit requires updating pull request quickly after the maintainer performs an approval action, make sure the approval action runs on forks for this to be feasible."
        elif self.value == Complexity.BROKEN_ACCESS:
            return "Exploit requires the attacker to have some access, but the access control mechanism is not properly implemented."
        return ""
