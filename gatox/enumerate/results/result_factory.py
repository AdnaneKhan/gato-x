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

# THis class encapsulates the logic for a result factory.
# it takes a Graph traversal path and worlks from start to end in order
# to populate the result.
from gatox.enumerate.results.pwn_request_result import PwnRequestResult
from gatox.enumerate.results.injection_result import InjectionResult
from gatox.enumerate.results.dispatch_toctou_result import DispatchTOCTOUResult
from gatox.enumerate.results.review_injection_result import ReviewInjectionResult
from gatox.enumerate.results.artifact_poisoning_result import ArtifactPoisoningResult


class ResultFactory:
    @staticmethod
    def create_pwn_result(path: list, confidence_score, attack_complexity):
        return PwnRequestResult(path, confidence_score, attack_complexity)

    @staticmethod
    def create_injection_result(path: list, confidence_score, attack_complexity):
        return InjectionResult(path, confidence_score, attack_complexity)

    @staticmethod
    def create_toctou_result(path: list, confidence_score, attack_complexity):
        return DispatchTOCTOUResult(path, confidence_score, attack_complexity)

    @staticmethod
    def create_review_injection_result(path: list, confidence_score, attack_complexity):
        return ReviewInjectionResult(path, confidence_score, attack_complexity)

    @staticmethod
    def create_artifact_poisoning_result(
        path: list, confidence_score, attack_complexity
    ):
        return ArtifactPoisoningResult(path, confidence_score, attack_complexity)
