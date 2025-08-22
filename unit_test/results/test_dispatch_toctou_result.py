import unittest
from unittest.mock import Mock

from gatox.enumerate.results.complexity import Complexity
from gatox.enumerate.results.confidence import Confidence
from gatox.enumerate.results.dispatch_toctou_result import DispatchTOCTOUResult


class TestDispatchTOCTOUResult(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures before each test method."""
        # Mock nodes for the attack path
        self.start_node = Mock()
        self.start_node.repo_name.return_value = "test/repository"
        self.start_node.get_workflow_name.return_value = "workflow.yml"
        self.start_node.get_triggers.return_value = [
            "workflow_dispatch",
        ]

        self.end_node = Mock()
        self.end_node.get_step_data.return_value = {
            "uses": "actions/checkout@v3",
            "with": {"ref": "main"},
        }

        self.path = [self.start_node, self.end_node]

        # Create test instance
        self.result = DispatchTOCTOUResult(
            path=self.path,
            confidence_score=Confidence.HIGH,
            attack_complexity_score=Complexity.TOCTOU,
        )

    def test_initialization(self):
        """Test proper initialization of DispatchTOCTOUResult."""
        self.assertEqual(self.result.repo_name(), "test/repository")
        self.assertEqual(self.result.issue_type(), "DispatchTOCTOUResult")
        self.assertEqual(self.result.confidence_score(), Confidence.HIGH)
        self.assertEqual(self.result.attack_complexity(), Complexity.TOCTOU)

    def test_hash_consistency(self):
        """Test that hash generation is consistent for same inputs."""
        hash1 = self.result.get_first_and_last_hash()
        hash2 = self.result.get_first_and_last_hash()
        self.assertEqual(hash1, hash2)

    def test_hash_uniqueness(self):
        """Test that different inputs produce different hashes."""
        # Create result with different confidence
        different_result = DispatchTOCTOUResult(
            path=self.path,
            confidence_score=Confidence.LOW,
            attack_complexity_score=Complexity.TOCTOU,
        )

        self.assertNotEqual(
            self.result.get_first_and_last_hash(),
            different_result.get_first_and_last_hash(),
        )

    def test_to_machine_high_confidence(self):
        """Test machine output format with high confidence."""
        output = self.result.to_machine()

        self.assertEqual(output["repository_name"], "test/repository")
        self.assertEqual(output["issue_type"], "DispatchTOCTOUResult")
        self.assertEqual(output["initial_workflow"], "workflow.yml")
        self.assertEqual(output["confidence"], Confidence.HIGH)
        self.assertEqual(output["attack_complexity"], Complexity.TOCTOU)
        self.assertEqual(output["sink"], self.end_node.get_step_data())
        self.assertEqual(output["triggers"], ["workflow_dispatch"])

    def test_to_machine_low_confidence(self):
        """Test machine output format with low confidence."""
        result = DispatchTOCTOUResult(
            path=self.path,
            confidence_score=Confidence.LOW,
            attack_complexity_score=Complexity.TOCTOU,
        )

        output = result.to_machine()
        self.assertEqual(output["sink"], "Not Detected")

    def test_to_machine_required_fields(self):
        """Test that all required fields are present in machine output."""
        output = self.result.to_machine()
        required_fields = {
            "repository_name",
            "issue_type",
            "triggers",
            "initial_workflow",
            "confidence",
            "attack_complexity",
            "explanation",
            "path",
            "sink",
        }

        self.assertEqual(set(output.keys()), required_fields)


if __name__ == "__main__":
    unittest.main()
