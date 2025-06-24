import unittest
from unittest.mock import Mock

from gatox.enumerate.results.pwn_request_result import PwnRequestResult
from gatox.enumerate.results.confidence import Confidence
from gatox.enumerate.results.complexity import Complexity


class TestPwnRequestResult(unittest.TestCase):
    def setUp(self):
        # Mock the attack path nodes
        self.start_node = Mock()
        self.start_node.repo_name.return_value = "test/repo"
        self.start_node.get_workflow_name.return_value = "workflow.yml"
        self.start_node.get_triggers.return_value = [
            "pull_request_target:labeled",
            "push",
            "workflow_run",
        ]

        self.end_node = Mock()
        self.end_node.get_step_data.return_value = {
            "uses": "actions/checkout@v2",
            "with": {"ref": "${{ github.event.pull_request.head.ref }}"},
        }

        self.path = [self.start_node, self.end_node]

        # Create test instance
        self.result = PwnRequestResult(
            path=self.path,
            confidence_score=Confidence.HIGH,
            attack_complexity_score=Complexity.ZERO_CLICK,
        )

    def test_initialization(self):
        """Test proper initialization of PwnRequestResult"""
        self.assertEqual(self.result.repo_name(), "test/repo")
        self.assertEqual(self.result.issue_type(), "PwnRequestResult")
        self.assertEqual(self.result.confidence_score(), Confidence.HIGH)
        self.assertEqual(self.result.attack_complexity(), Complexity.ZERO_CLICK)

    def test_get_first_and_last_hash_consistency(self):
        """Test hash generation is deterministic"""
        hash1 = self.result.get_first_and_last_hash()
        hash2 = self.result.get_first_and_last_hash()
        self.assertEqual(hash1, hash2)

    def test_get_first_and_last_hash_uniqueness(self):
        """Test different inputs produce different hashes"""
        different_result = PwnRequestResult(
            path=self.path,
            confidence_score=Confidence.LOW,
            attack_complexity_score=Complexity.ZERO_CLICK,
        )
        self.assertNotEqual(
            self.result.get_first_and_last_hash(),
            different_result.get_first_and_last_hash(),
        )

    def test_filter_triggers(self):
        """Test trigger filtering functionality"""
        test_triggers = [
            "pull_request_target:labeled",
            "push",
            "workflow_run",
            "schedule",
            "issue_comment",
        ]

        filtered = self.result.filter_triggers(test_triggers)

        # Should include relevant triggers
        self.assertIn("pull_request_target:labeled", filtered)
        self.assertIn("workflow_run", filtered)
        self.assertIn("issue_comment", filtered)

        # Should exclude irrelevant triggers
        self.assertNotIn("push", filtered)
        self.assertNotIn("schedule", filtered)

    def test_to_machine_high_confidence(self):
        """Test machine output format with high confidence"""
        output = self.result.to_machine()

        self.assertEqual(output["repository_name"], "test/repo")
        self.assertEqual(output["issue_type"], "PwnRequestResult")
        self.assertEqual(output["initial_workflow"], "workflow.yml")
        self.assertEqual(output["confidence"], Confidence.HIGH)
        self.assertEqual(output["attack_complexity"], Complexity.ZERO_CLICK)
        self.assertEqual(output["sink"], self.end_node.get_step_data())

    def test_to_machine_low_confidence(self):
        """Test machine output format with low confidence"""
        result = PwnRequestResult(
            path=self.path,
            confidence_score=Confidence.LOW,
            attack_complexity_score=Complexity.ZERO_CLICK,
        )

        output = result.to_machine()
        self.assertEqual(output["sink"], "Not Detected")

    def test_to_machine_required_fields(self):
        """Test all required fields are present in machine output"""
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
