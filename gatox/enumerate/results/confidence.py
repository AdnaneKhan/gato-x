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


class Confidence(str, Enum):
    """
    Represents the confidence level in a finding or result.

    Values:
        HIGH: Strong evidence and high certainty
        MEDIUM: Moderate evidence with some uncertainty
        LOW: Limited evidence with significant uncertainty
        UNKNOWN: Not enough information to determine confidence
    """

    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    UNKNOWN = "Unknown"

    def __str__(self) -> str:
        return str(self.value)

    def __repr__(self) -> str:
        return str(self.value)

    def to_machine(self):
        """Convert enum to machine readable format for JSON serialization."""
        return self.value

    @classmethod
    def from_string(cls, value: str):
        """Convert string to enum value, case-insensitive."""
        try:
            return cls[value.upper()]
        except KeyError:
            return cls.UNKNOWN
