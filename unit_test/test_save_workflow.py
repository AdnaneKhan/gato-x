import unittest
from unittest.mock import patch, mock_open, MagicMock, call
import os
from gatox.cli import cli


class TestSaveWorkflowYmls(unittest.TestCase):
    @patch("gatox.cli.cli.CacheManager")
    @patch("pathlib.Path.mkdir")
    @patch("builtins.open", new_callable=mock_open)
    def test_save_workflow_ymls(self, mock_open_func, mock_mkdir, mock_cache_manager):
        """Test that save_workflow_ymls correctly saves workflow files."""

        # Mock CacheManager to return some repos and workflows
        mock_cache_manager_instance = MagicMock()
        mock_cache_manager.return_value = mock_cache_manager_instance

        mock_cache_manager_instance.get_repos.return_value = ["repo1", "repo2"]

        mock_workflow1 = MagicMock(
            workflow_name="wf1.yml", workflow_contents="content1"
        )
        mock_workflow2 = MagicMock(
            workflow_name="wf2.yml", workflow_contents="content2"
        )
        mock_cache_manager_instance.get_workflows.side_effect = [
            [mock_workflow1],
            [mock_workflow2],
        ]

        # Call the function
        output_directory = "/tmp/test_output"
        cli.save_workflow_ymls(output_directory)

        # Assert that mkdir was called correctly
        expected_calls = [
            call(parents=True, exist_ok=True),
            call(parents=True, exist_ok=True),
        ]
        mock_mkdir.assert_has_calls(expected_calls, any_order=True)
        self.assertEqual(mock_mkdir.call_count, 2)

        # Assert that open was called correctly and the contents were written
        mock_open_func.assert_any_call(
            os.path.join(output_directory, "repo1/wf1.yml"), "w"
        )
        mock_open_func.assert_any_call(
            os.path.join(output_directory, "repo2/wf2.yml"), "w"
        )

        handler = mock_open_func()

        handler.write.assert_any_call("content1")
        handler.write.assert_any_call("content2")


if __name__ == "__main__":
    unittest.main()
