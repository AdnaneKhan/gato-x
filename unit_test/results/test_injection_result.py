import unittest
from unittest.mock import Mock

from gatox.enumerate.results.injection_result import InjectionResult
from gatox.enumerate.results.confidence import Confidence
from gatox.enumerate.results.complexity import Complexity


class TestInjectionResult(unittest.TestCase):
    def setUp(self):
        # Mock node objects for the attack path
        self.start_node = Mock()
        self.start_node.repo_name.return_value = "test/repo"
        self.start_node.get_workflow_name.return_value = "test.yml"
        self.start_node.get_triggers.return_value = [
            "pull_request_target",
            "push",
            "workflow_run",
        ]

        self.end_node = Mock()
        self.end_node.contexts = [
            "github.event.issue.body",
            "github.event.comment.body",
        ]

        self.path = [self.start_node, self.end_node]

        # Create InjectionResult instance
        self.result = InjectionResult(
            path=self.path,
            confidence_score=Confidence.HIGH,
            attack_complexity_score=Complexity.ZERO_CLICK,
        )

    def test_initialization(self):
        """Test proper initialization of InjectionResult"""
        self.assertEqual(self.result.repo_name(), "test/repo")
        self.assertEqual(self.result.issue_type(), "InjectionResult")
        self.assertEqual(self.result.confidence_score(), Confidence.HIGH)
        self.assertEqual(self.result.attack_complexity(), Complexity.ZERO_CLICK)

    def test_get_first_and_last_hash(self):
        """Test hash generation is consistent and includes required components"""
        first_hash = self.result.get_first_and_last_hash()
        second_hash = self.result.get_first_and_last_hash()

        # Same input should produce same hash
        self.assertEqual(first_hash, second_hash)

        # Different confidence should produce different hash
        different_result = InjectionResult(
            path=self.path,
            confidence_score=Confidence.LOW,
            attack_complexity_score=Complexity.ZERO_CLICK,
        )
        self.assertNotEqual(first_hash, different_result.get_first_and_last_hash())

    def test_get_first_and_last_hash_distinguishes_paths(self):
        """Test that paths with different first and last nodes get different hashes"""
        # Create a different start node
        different_start_node = Mock()
        different_start_node.repo_name.return_value = "test/repo"
        different_start_node.get_workflow_name.return_value = "different.yml"
        different_start_node.get_triggers.return_value = ["issue_comment"]

        # Create a different end node
        different_end_node = Mock()
        different_end_node.contexts = ["github.event.discussion.body"]

        # Create paths with different first and last nodes
        path_different_first = [different_start_node, self.end_node]
        path_different_last = [self.start_node, different_end_node]
        path_different_both = [different_start_node, different_end_node]

        # Create InjectionResult instances
        result_different_first = InjectionResult(
            path=path_different_first,
            confidence_score=Confidence.HIGH,
            attack_complexity_score=Complexity.ZERO_CLICK,
        )

        result_different_last = InjectionResult(
            path=path_different_last,
            confidence_score=Confidence.HIGH,
            attack_complexity_score=Complexity.ZERO_CLICK,
        )

        result_different_both = InjectionResult(
            path=path_different_both,
            confidence_score=Confidence.HIGH,
            attack_complexity_score=Complexity.ZERO_CLICK,
        )

        # Get hashes
        original_hash = self.result.get_first_and_last_hash()
        different_first_hash = result_different_first.get_first_and_last_hash()
        different_last_hash = result_different_last.get_first_and_last_hash()
        different_both_hash = result_different_both.get_first_and_last_hash()

        # All hashes should be different
        self.assertNotEqual(original_hash, different_first_hash)
        self.assertNotEqual(original_hash, different_last_hash)
        self.assertNotEqual(original_hash, different_both_hash)
        self.assertNotEqual(different_first_hash, different_last_hash)
        self.assertNotEqual(different_first_hash, different_both_hash)
        self.assertNotEqual(different_last_hash, different_both_hash)

    def test_filter_triggers(self):
        """Test trigger filtering logic"""
        triggers = ["push", "pull_request_target", "workflow_run", "schedule"]
        filtered = self.result.filter_triggers(triggers)

        # Should keep relevant triggers
        self.assertIn("pull_request_target", filtered)
        self.assertIn("workflow_run", filtered)

        # Should remove irrelevant triggers
        self.assertNotIn("push", filtered)
        self.assertNotIn("schedule", filtered)

    def test_to_machine(self):
        """Test machine-readable output format"""
        machine_output = self.result.to_machine()

        expected_keys = {
            "repository_name",
            "issue_type",
            "triggers",
            "initial_workflow",
            "confidence",
            "attack_complexity",
            "explanation",
            "path",
            "injectable_context",
        }

        # Verify all expected keys are present
        self.assertEqual(set(machine_output.keys()), expected_keys)

        # Verify content of machine output
        self.assertEqual(machine_output["repository_name"], "test/repo")
        self.assertEqual(machine_output["issue_type"], "InjectionResult")
        self.assertEqual(machine_output["initial_workflow"], "test.yml")
        self.assertEqual(
            machine_output["injectable_context"],
            ["github.event.issue.body", "github.event.comment.body"],
        )

        # Verify filtered triggers
        self.assertIn("pull_request_target", machine_output["triggers"])
        self.assertIn("workflow_run", machine_output["triggers"])
        self.assertNotIn("push", machine_output["triggers"])


if __name__ == "__main__":
    unittest.main()
