import pytest
from unittest.mock import Mock, MagicMock, patch, AsyncMock
from gatox.workflow_graph.graph.tagged_graph import TaggedGraph
from gatox.workflow_graph.visitors.injection_visitor import InjectionVisitor
from gatox.github.api import Api


@pytest.fixture
def mock_api():
    mock_api = Mock(spec=Api)
    mock_api.get_all_environment_protection_rules = AsyncMock(return_value={})
    return mock_api


@pytest.fixture
def mock_graph():
    return Mock(spec=TaggedGraph)


class TestInjectionVisitor:
    """Test cases for InjectionVisitor"""

    async def test_find_injections_no_nodes(self, mock_graph, mock_api):
        """Test when no nodes are found with injection tags"""
        mock_graph.get_nodes_for_tags.return_value = []

        results = await InjectionVisitor.find_injections(mock_graph, mock_api)

        assert results == {}
        expected_tags = [
            "issue_comment",
            "pull_request_target",
            "fork",
            "issues",
            "discussion",
            "discussion_comment",
            "workflow_run",
        ]
        mock_graph.get_nodes_for_tags.assert_called_once_with(expected_tags)

    async def test_find_injections_ignore_workflow_run(self, mock_graph, mock_api):
        """Test that workflow_run tag is excluded when ignore_workflow_run is True"""
        mock_graph.get_nodes_for_tags.return_value = []

        await InjectionVisitor.find_injections(
            mock_graph, mock_api, ignore_workflow_run=True
        )

        expected_tags = [
            "issue_comment",
            "pull_request_target",
            "fork",
            "issues",
            "discussion",
            "discussion_comment",
        ]
        mock_graph.get_nodes_for_tags.assert_called_once_with(expected_tags)

    async def test_find_injections_include_workflow_run(self, mock_graph, mock_api):
        """Test that workflow_run tag is included when ignore_workflow_run is False"""
        mock_graph.get_nodes_for_tags.return_value = []

        await InjectionVisitor.find_injections(
            mock_graph, mock_api, ignore_workflow_run=False
        )

        expected_tags = [
            "issue_comment",
            "pull_request_target",
            "fork",
            "issues",
            "discussion",
            "discussion_comment",
            "workflow_run",
        ]
        mock_graph.get_nodes_for_tags.assert_called_once_with(expected_tags)

    async def test_find_injections_dfs_exception(self, mock_graph, mock_api):
        """Test exception handling during DFS operation"""
        mock_node = MagicMock()
        mock_graph.get_nodes_for_tags.return_value = [mock_node]
        mock_graph.dfs_to_tag = AsyncMock(side_effect=Exception("DFS error"))

        with patch(
            "gatox.workflow_graph.visitors.injection_visitor.logger"
        ) as mock_logger:
            results = await InjectionVisitor.find_injections(mock_graph, mock_api)

            assert results == {}
            mock_logger.error.assert_any_call(
                "Error finding paths for injection node: DFS error"
            )
            mock_logger.error.assert_any_call(f"Node: {mock_node}")

    async def test_find_injections_no_paths(self, mock_graph, mock_api):
        """Test when DFS returns no paths"""
        mock_node = MagicMock()
        mock_graph.get_nodes_for_tags.return_value = [mock_node]
        mock_graph.dfs_to_tag = AsyncMock(return_value=None)

        results = await InjectionVisitor.find_injections(mock_graph, mock_api)

        assert results == {}
        mock_graph.dfs_to_tag.assert_called_once_with(mock_node, "injectable", mock_api)

    async def test_find_injections_with_job_node_deployment(self, mock_graph, mock_api):
        """Test path analysis with JobNode that has deployments"""
        # Setup mock job node with deployment
        mock_job_node = MagicMock()
        mock_job_node.get_tags.return_value = ["JobNode"]
        mock_job_node.repo_name.return_value = "owner/repo"
        mock_job_node.deployments = ["production"]
        mock_job_node.get_env_vars.return_value = {"ENV_VAR": "github.event.test"}
        mock_job_node.outputs = None

        # Setup mock step node
        mock_step_node = MagicMock()
        mock_step_node.get_tags.return_value = ["StepNode", "injectable"]
        mock_step_node.contexts = ["github.event.issue.title"]

        path = [mock_job_node, mock_step_node]

        mock_graph.get_nodes_for_tags.return_value = [mock_job_node]
        mock_graph.dfs_to_tag = AsyncMock()
        mock_graph.dfs_to_tag.side_effect = [
            [path],  # First call returns the main path
            None,  # permission_check call
            None,  # permission_blocker call
        ]

        # Mock environment protection rules
        mock_api.get_all_environment_protection_rules.return_value = {
            "production": True
        }

        with (
            patch(
                "gatox.workflow_graph.visitors.injection_visitor.VisitorUtils.check_deployment_approval_gate",
                new_callable=AsyncMock,
            ) as mock_check_deploy,
            patch(
                "gatox.workflow_graph.visitors.injection_visitor.VisitorUtils.process_context_var"
            ) as mock_process_context_var,
            patch(
                "gatox.workflow_graph.visitors.injection_visitor.VisitorUtils._add_results"
            ) as mock_add_results,
        ):
            mock_check_deploy.return_value = True
            mock_process_context_var.return_value = "production"
            mock_add_results.return_value = None

            await InjectionVisitor.find_injections(mock_graph, mock_api)

            # Do not assert API call, since the method is mocked

    async def test_find_injections_with_step_node_injection(self, mock_graph, mock_api):
        """Test path analysis with StepNode injection"""
        # Setup mock job node
        mock_job_node = MagicMock()
        mock_job_node.get_tags.return_value = ["JobNode"]
        mock_job_node.repo_name.return_value = "owner/repo"
        mock_job_node.deployments = []
        mock_job_node.get_env_vars.return_value = {
            "PR_BODY": "github.event.pull_request.body"
        }
        mock_job_node.outputs = None

        # Setup mock step node with injection
        mock_step_node = MagicMock()
        mock_step_node.get_tags.return_value = ["StepNode", "injectable"]
        mock_step_node.contexts = ["github.event.issue.title"]

        path = [mock_job_node, mock_step_node]

        mock_graph.get_nodes_for_tags.return_value = [mock_job_node]
        mock_graph.dfs_to_tag = AsyncMock()
        mock_graph.dfs_to_tag.side_effect = [
            [path],  # First call returns the main path
            None,  # permission_check call
            None,  # permission_blocker call
        ]

        with patch(
            "gatox.workflow_graph.visitors.injection_visitor.VisitorUtils"
        ) as mock_visitor_utils:
            mock_visitor_utils._add_results.return_value = None

            with patch(
                "gatox.workflow_graph.visitors.injection_visitor.getToken"
            ) as mock_get_token:
                mock_get_token.return_value = "github.event.issue.title"

                with patch(
                    "gatox.workflow_graph.visitors.injection_visitor.checkUnsafe"
                ) as mock_check_unsafe:
                    mock_check_unsafe.return_value = True

                    await InjectionVisitor.find_injections(mock_graph, mock_api)

                    # Should call _add_results for the injection
                    mock_visitor_utils._add_results.assert_called()

    async def test_find_injections_with_permission_blocker(self, mock_graph, mock_api):
        """Test path analysis with permission blocker"""
        # Setup mock job node
        mock_job_node = MagicMock()
        mock_job_node.get_tags.return_value = ["JobNode"]
        mock_job_node.repo_name.return_value = "owner/repo"
        mock_job_node.deployments = []
        mock_job_node.get_env_vars.return_value = {}
        mock_job_node.outputs = None

        # Setup mock step node
        mock_step_node = MagicMock()
        mock_step_node.get_tags.return_value = ["StepNode", "injectable"]
        mock_step_node.contexts = ["github.event.issue.title"]

        path = [mock_job_node, mock_step_node]

        mock_graph.get_nodes_for_tags.return_value = [mock_job_node]
        mock_graph.dfs_to_tag = AsyncMock()
        mock_graph.dfs_to_tag.side_effect = [
            [path],  # First call returns the main path
            None,  # permission_check call
            [["blocker_path"]],  # permission_blocker call returns a path
        ]

        results = await InjectionVisitor.find_injections(mock_graph, mock_api)

        # Should break early due to permission blocker
        assert results == {}

    async def test_find_injections_with_workflow_node_fork(self, mock_graph, mock_api):
        """Test path analysis with WorkflowNode from fork repository"""
        # Setup mock workflow node
        mock_workflow_node = MagicMock()
        mock_workflow_node.get_tags.return_value = ["WorkflowNode"]
        mock_workflow_node.repo_name.return_value = "owner/repo"
        mock_workflow_node.get_env_vars.return_value = {}

        path = [mock_workflow_node]

        mock_graph.get_nodes_for_tags.return_value = [mock_workflow_node]
        mock_graph.dfs_to_tag = AsyncMock(return_value=[path])

        # Mock repository as fork
        with patch(
            "gatox.workflow_graph.visitors.injection_visitor.CacheManager"
        ) as mock_cache_manager:
            mock_repo = MagicMock()
            mock_repo.is_fork.return_value = True
            mock_cache_manager.return_value.get_repository.return_value = mock_repo

            results = await InjectionVisitor.find_injections(mock_graph, mock_api)

            # Should break early for fork repository
            assert results == {}

    async def test_find_injections_with_action_node(self, mock_graph, mock_api):
        """Test path analysis with ActionNode"""
        # Setup mock workflow node
        mock_workflow_node = MagicMock()
        mock_workflow_node.get_tags.return_value = ["WorkflowNode"]
        mock_workflow_node.repo_name.return_value = "owner/repo"
        mock_workflow_node.get_env_vars.return_value = {}

        # Setup mock action node
        mock_action_node = MagicMock()
        mock_action_node.get_tags.return_value = ["ActionNode"]

        path = [mock_workflow_node, mock_action_node]

        mock_graph.get_nodes_for_tags.return_value = [mock_workflow_node]
        mock_graph.dfs_to_tag = AsyncMock(return_value=[path])

        # Mock repository as not fork
        with patch(
            "gatox.workflow_graph.visitors.injection_visitor.CacheManager"
        ) as mock_cache_manager:
            mock_repo = MagicMock()
            mock_repo.is_fork.return_value = False
            mock_cache_manager.return_value.get_repository.return_value = mock_repo

            with patch(
                "gatox.workflow_graph.visitors.injection_visitor.VisitorUtils"
            ) as mock_visitor_utils:
                mock_visitor_utils.initialize_action_node = AsyncMock()

                await InjectionVisitor.find_injections(mock_graph, mock_api)

                # Should initialize action node
                mock_visitor_utils.initialize_action_node.assert_called_with(
                    mock_graph, mock_api, mock_action_node
                )

    async def test_find_injections_with_job_outputs(self, mock_graph, mock_api):
        """Test path analysis with JobNode that has outputs"""
        # Setup mock job node with outputs
        mock_job_node = MagicMock()
        mock_job_node.get_tags.return_value = ["JobNode"]
        mock_job_node.repo_name.return_value = "owner/repo"
        mock_job_node.deployments = []
        mock_job_node.get_env_vars.return_value = {"TEST_VAR": "github.event.test"}
        mock_job_node.outputs = {
            "output1": "env.TEST_VAR",  # String output referencing env var
            "output2": {"value": "test"},  # Non-string output
            "output3": "static_value",  # String output not referencing env
        }

        # Setup mock step node
        mock_step_node = MagicMock()
        mock_step_node.get_tags.return_value = ["StepNode", "injectable"]
        mock_step_node.contexts = ["github.event.issue.title"]

        path = [mock_job_node, mock_step_node]

        mock_graph.get_nodes_for_tags.return_value = [mock_job_node]
        mock_graph.dfs_to_tag = AsyncMock()
        mock_graph.dfs_to_tag.side_effect = [
            [path],  # First call returns the main path
            None,  # permission_check call
            None,  # permission_blocker call
        ]

        with patch(
            "gatox.workflow_graph.visitors.injection_visitor.VisitorUtils"
        ) as mock_visitor_utils:
            mock_visitor_utils._add_results.return_value = None

            with patch(
                "gatox.workflow_graph.visitors.injection_visitor.getToken"
            ) as mock_get_token:
                mock_get_token.return_value = "github.event.issue.title"

                with patch(
                    "gatox.workflow_graph.visitors.injection_visitor.checkUnsafe"
                ) as mock_check_unsafe:
                    mock_check_unsafe.return_value = True

                    await InjectionVisitor.find_injections(mock_graph, mock_api)

                    # Should process outputs and handle different types
                    mock_visitor_utils._add_results.assert_called()

    async def test_find_injections_with_context_processing(self, mock_graph, mock_api):
        """Test path analysis with various context variable processing"""
        # Setup mock job node
        mock_job_node = MagicMock()
        mock_job_node.get_tags.return_value = ["JobNode"]
        mock_job_node.repo_name.return_value = "owner/repo"
        mock_job_node.deployments = []
        mock_job_node.get_env_vars.return_value = {
            "ENV_VAR": "github.event.pull_request.body",
            "SAFE_VAR": "github.event.pull_request.number",
        }
        mock_job_node.outputs = None

        # Setup mock step node with various context types
        mock_step_node = MagicMock()
        mock_step_node.get_tags.return_value = ["StepNode", "injectable"]
        mock_step_node.contexts = [
            "inputs.user_input",  # inputs. variable
            "env.ENV_VAR",  # env. variable
            "github.event.issue.title",  # direct github variable
            "${{ github.event.test }}",  # variable with ${{ }} syntax
        ]

        path = [mock_job_node, mock_step_node]

        mock_graph.get_nodes_for_tags.return_value = [mock_job_node]
        mock_graph.dfs_to_tag = AsyncMock()
        mock_graph.dfs_to_tag.side_effect = [
            [path],  # First call returns the main path
            None,  # permission_check call
            None,  # permission_blocker call
        ]

        with patch(
            "gatox.workflow_graph.visitors.injection_visitor.VisitorUtils"
        ) as mock_visitor_utils:
            mock_visitor_utils._add_results.return_value = None

            with patch(
                "gatox.workflow_graph.visitors.injection_visitor.CONTEXT_REGEX"
            ) as mock_regex:
                mock_regex.findall.return_value = ["github.event.test"]

                with patch(
                    "gatox.workflow_graph.visitors.injection_visitor.getToken"
                ) as mock_get_token:
                    mock_get_token.side_effect = lambda x: x  # Return input as-is

                    with patch(
                        "gatox.workflow_graph.visitors.injection_visitor.getTokens"
                    ) as mock_get_tokens:
                        mock_get_tokens.return_value = ["github.event.test"]

                        with patch(
                            "gatox.workflow_graph.visitors.injection_visitor.checkUnsafe"
                        ) as mock_check_unsafe:
                            mock_check_unsafe.return_value = True

                            await InjectionVisitor.find_injections(mock_graph, mock_api)

                            # Should process all context types and find injection
                            mock_visitor_utils._add_results.assert_called()

    async def test_find_injections_workflow_run_complexity(self, mock_graph, mock_api):
        """Test that workflow_run triggers get PREVIOUS_CONTRIBUTOR complexity"""
        # Setup mock workflow node with workflow_run tag
        mock_workflow_node = MagicMock()
        mock_workflow_node.get_tags.return_value = ["WorkflowNode", "workflow_run"]
        mock_workflow_node.repo_name.return_value = "owner/repo"
        mock_workflow_node.get_env_vars.return_value = {}

        # Setup mock job and step nodes
        mock_job_node = MagicMock()
        mock_job_node.get_tags.return_value = ["JobNode"]
        mock_job_node.deployments = []
        mock_job_node.get_env_vars.return_value = {}
        mock_job_node.outputs = None

        mock_step_node = MagicMock()
        mock_step_node.get_tags.return_value = ["StepNode", "injectable"]
        mock_step_node.contexts = ["github.event.issue.title"]

        path = [mock_workflow_node, mock_job_node, mock_step_node]

        mock_graph.get_nodes_for_tags.return_value = [mock_workflow_node]
        mock_graph.dfs_to_tag = AsyncMock()
        mock_graph.dfs_to_tag.side_effect = [
            [path],  # First call returns the main path
            None,  # permission_check call
            None,  # permission_blocker call
        ]

        # Mock repository as not fork
        with patch(
            "gatox.workflow_graph.visitors.injection_visitor.CacheManager"
        ) as mock_cache_manager:
            mock_repo = MagicMock()
            mock_repo.is_fork.return_value = False
            mock_cache_manager.return_value.get_repository.return_value = mock_repo

            with patch(
                "gatox.workflow_graph.visitors.injection_visitor.VisitorUtils"
            ) as mock_visitor_utils:
                mock_visitor_utils._add_results.return_value = None

                with patch(
                    "gatox.workflow_graph.visitors.injection_visitor.getToken"
                ) as mock_get_token:
                    mock_get_token.return_value = "github.event.issue.title"

                    with patch(
                        "gatox.workflow_graph.visitors.injection_visitor.checkUnsafe"
                    ) as mock_check_unsafe:
                        mock_check_unsafe.return_value = True

                        await InjectionVisitor.find_injections(mock_graph, mock_api)

                        # Should use PREVIOUS_CONTRIBUTOR complexity for workflow_run
                        mock_visitor_utils._add_results.assert_called()
                        # Check the complexity argument in the call
                        call_args = mock_visitor_utils._add_results.call_args
                        assert call_args[1]["complexity"].name == "PREVIOUS_CONTRIBUTOR"
