import pytest
import json
import io
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from gatox.notifications.send_webhook import send_slack_webhook, send_discord_webhook, _create_result_summary


@pytest.fixture
def mock_config_manager():
    """Mock configuration manager with webhook URLs."""
    with patch("gatox.notifications.send_webhook.ConfigurationManager") as mock_cm:
        mock_instance = MagicMock()
        mock_instance.NOTIFICATIONS = {
            "SLACK_WEBHOOKS": [
                "https://hooks.slack.com/webhook1",
                "https://hooks.slack.com/webhook2",
            ],
            "DISCORD_WEBHOOKS": [
                "https://discord.com/api/webhooks/webhook1",
                "https://discord.com/api/webhooks/webhook2",
            ],
        }
        mock_cm.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def sample_message():
    """Sample message for testing."""
    return "Test notification message"


@pytest.fixture
def long_message():
    """Long message for testing attachment functionality."""
    return json.dumps({
        "repository_name": "TestUser/TestRepo",
        "issue_type": "PwnRequestResult", 
        "triggers": ["pull_request_target"],
        "initial_workflow": "test.yml",
        "confidence": "High",
        "attack_complexity": "No Interaction",
        "explanation": "This is a test vulnerability with a very long explanation that exceeds Discord's 2000 character limit" + "x" * 2000,
        "paths": [{"nodes": [f"node_{i}" for i in range(100)]} for _ in range(20)]
    })


@pytest.fixture
def sample_result_data():
    """Sample result data for summary testing."""
    return {
        "repository_name": "AmyJeanes/TARDIS",
        "issue_type": "PwnRequestResult",
        "triggers": ["pull_request_target"],
        "initial_workflow": "generate-files.yml",
        "confidence": "High",
        "attack_complexity": "No Interaction",
        "explanation": "Exploit requires no user interaction, you must still confirm there are no custom permission checks that would prevent the attack."
    }


class TestSlackWebhook:
    """Test cases for Slack webhook functionality."""

    @pytest.mark.asyncio
    async def test_send_slack_webhook_success(
        self, mock_config_manager, sample_message
    ):
        """Test successful Slack webhook sending."""
        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_context
            mock_context.post = AsyncMock(return_value=mock_response)

            await send_slack_webhook(sample_message)

            # Verify correct number of calls (2 webhooks)
            assert mock_context.post.call_count == 2

            # Verify payload format
            calls = mock_context.post.call_args_list
            for call in calls:
                args, kwargs = call
                assert "json" in kwargs
                payload = kwargs["json"]
                assert "text" in payload
                assert json.dumps(sample_message, indent=4) in payload["text"]

    @pytest.mark.asyncio
    async def test_send_slack_webhook_connection_error_retry(
        self, mock_config_manager, sample_message
    ):
        """Test Slack webhook retry logic on connection error."""
        mock_response = MagicMock()
        mock_response.status_code = 200

        with (
            patch("httpx.AsyncClient") as mock_client,
            patch("asyncio.sleep") as mock_sleep,
        ):

            mock_context = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_context

            # First webhook: first call fails, second succeeds
            # Second webhook: succeeds immediately
            mock_context.post = AsyncMock(
                side_effect=[
                    httpx.ConnectError("Connection failed"),
                    mock_response,
                    mock_response,
                ]
            )

            await send_slack_webhook(sample_message)

            # Should have made 3 calls total (retry for first webhook + success for both)
            assert mock_context.post.call_count == 3
            mock_sleep.assert_called_once_with(1)

    @pytest.mark.asyncio
    async def test_send_slack_webhook_connection_error_max_retries(
        self, mock_config_manager, sample_message
    ):
        """Test Slack webhook failure after max retries."""
        with (
            patch("httpx.AsyncClient") as mock_client,
            patch("asyncio.sleep") as mock_sleep,
        ):

            mock_context = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_context
            mock_context.post = AsyncMock(
                side_effect=httpx.ConnectError("Connection failed")
            )

            with pytest.raises(
                ValueError,
                match="Failed to send webhook due to connection errors after 3 attempts",
            ):
                await send_slack_webhook(sample_message)

            # Should have tried 3 times
            assert mock_context.post.call_count == 3
            assert mock_sleep.call_count == 3

    @pytest.mark.asyncio
    async def test_send_slack_webhook_http_error(
        self, mock_config_manager, sample_message
    ):
        """Test Slack webhook HTTP error handling."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"

        with patch("httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_context
            mock_context.post = AsyncMock(return_value=mock_response)

            with pytest.raises(
                ValueError, match="Request to slack returned an error 500"
            ):
                await send_slack_webhook(sample_message)

    @pytest.mark.asyncio
    async def test_send_slack_webhook_empty_webhooks_list(self, sample_message):
        """Test Slack webhook with empty webhooks list."""
        with patch("gatox.notifications.send_webhook.ConfigurationManager") as mock_cm:
            mock_instance = MagicMock()
            mock_instance.NOTIFICATIONS = {"SLACK_WEBHOOKS": []}
            mock_cm.return_value = mock_instance

            with patch("httpx.AsyncClient") as mock_client:
                mock_context = AsyncMock()
                mock_client.return_value.__aenter__.return_value = mock_context
                mock_context.post = AsyncMock()

                await send_slack_webhook(sample_message)

                # Should not make any HTTP calls
                mock_context.post.assert_not_called()

    @pytest.mark.asyncio
    async def test_send_slack_webhook_client_timeout(self, mock_config_manager):
        """Test Slack webhook client timeout configuration."""
        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_context
            mock_context.post = AsyncMock(return_value=mock_response)

            await send_slack_webhook("test")

            # Verify timeout is set correctly
            mock_client.assert_called_once_with(
                http2=True, follow_redirects=True, timeout=10.0
            )


class TestDiscordWebhook:
    """Test cases for Discord webhook functionality."""

    @pytest.mark.asyncio
    async def test_send_discord_webhook_success(
        self, mock_config_manager, sample_message
    ):
        """Test successful Discord webhook sending."""
        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_context
            mock_context.post = AsyncMock(return_value=mock_response)

            await send_discord_webhook(sample_message)

            # Verify correct number of calls (2 webhooks)
            assert mock_context.post.call_count == 2

            # Verify payload format
            calls = mock_context.post.call_args_list
            for call in calls:
                args, kwargs = call
                assert "json" in kwargs
                payload = kwargs["json"]
                assert "content" in payload
                assert sample_message in payload["content"]

    @pytest.mark.asyncio
    async def test_send_discord_webhook_success_204(
        self, mock_config_manager, sample_message
    ):
        """Test successful Discord webhook sending with 204 status code."""
        mock_response = MagicMock()
        mock_response.status_code = 204

        with patch("httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_context
            mock_context.post = AsyncMock(return_value=mock_response)

            await send_discord_webhook(sample_message)

            # Should succeed with 204 status
            assert mock_context.post.call_count == 2

    @pytest.mark.asyncio
    async def test_send_discord_webhook_connection_error_retry(
        self, mock_config_manager, sample_message
    ):
        """Test Discord webhook retry logic on connection error."""
        mock_response = MagicMock()
        mock_response.status_code = 200

        with (
            patch("httpx.AsyncClient") as mock_client,
            patch("asyncio.sleep") as mock_sleep,
        ):

            mock_context = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_context

            # First webhook: first call fails, second succeeds
            # Second webhook: succeeds immediately
            mock_context.post = AsyncMock(
                side_effect=[
                    httpx.ConnectError("Connection failed"),
                    mock_response,
                    mock_response,
                ]
            )

            await send_discord_webhook(sample_message)

            # Should have made 3 calls total (retry for first webhook + success for both)
            assert mock_context.post.call_count == 3
            mock_sleep.assert_called_once_with(1)

    @pytest.mark.asyncio
    async def test_send_discord_webhook_connection_error_max_retries(
        self, mock_config_manager, sample_message
    ):
        """Test Discord webhook failure after max retries."""
        with (
            patch("httpx.AsyncClient") as mock_client,
            patch("asyncio.sleep") as mock_sleep,
        ):

            mock_context = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_context
            mock_context.post = AsyncMock(
                side_effect=httpx.ConnectError("Connection failed")
            )

            with pytest.raises(
                ValueError,
                match="Failed to send Discord webhook due to connection errors after 3 attempts",
            ):
                await send_discord_webhook(sample_message)

            # Should have tried 3 times
            assert mock_context.post.call_count == 3
            assert mock_sleep.call_count == 3

    @pytest.mark.asyncio
    async def test_send_discord_webhook_http_error(
        self, mock_config_manager, sample_message
    ):
        """Test Discord webhook HTTP error handling."""
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "Bad Request"

        with patch("httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_context
            mock_context.post = AsyncMock(return_value=mock_response)

            with pytest.raises(
                ValueError, match="Request to Discord returned an error 400"
            ):
                await send_discord_webhook(sample_message)

    @pytest.mark.asyncio
    async def test_send_discord_webhook_empty_webhooks_list(self, sample_message):
        """Test Discord webhook with empty webhooks list."""
        with patch("gatox.notifications.send_webhook.ConfigurationManager") as mock_cm:
            mock_instance = MagicMock()
            mock_instance.NOTIFICATIONS = {"DISCORD_WEBHOOKS": []}
            mock_cm.return_value = mock_instance

            with patch("httpx.AsyncClient") as mock_client:
                mock_context = AsyncMock()
                mock_client.return_value.__aenter__.return_value = mock_context
                mock_context.post = AsyncMock()

                await send_discord_webhook(sample_message)

                # Should not make any HTTP calls
                mock_context.post.assert_not_called()

    @pytest.mark.asyncio
    async def test_send_discord_webhook_client_timeout(self, mock_config_manager):
        """Test Discord webhook client timeout configuration."""
        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_context
            mock_context.post = AsyncMock(return_value=mock_response)

            await send_discord_webhook("test")

            # Verify timeout is set correctly (should be 10.0 for short messages)
            mock_client.assert_called_once_with(
                http2=True, follow_redirects=True, timeout=10.0
            )

    @pytest.mark.asyncio
    async def test_send_discord_webhook_partial_failure(self, sample_message):
        """Test Discord webhook with partial failure (one webhook fails, another succeeds)."""
        with patch("gatox.notifications.send_webhook.ConfigurationManager") as mock_cm:
            mock_instance = MagicMock()
            mock_instance.NOTIFICATIONS = {
                "DISCORD_WEBHOOKS": [
                    "https://discord.com/api/webhooks/webhook1",
                    "https://discord.com/api/webhooks/webhook2",
                ]
            }
            mock_cm.return_value = mock_instance

            mock_success_response = MagicMock()
            mock_success_response.status_code = 200

            with patch("httpx.AsyncClient") as mock_client:
                mock_context = AsyncMock()
                mock_client.return_value.__aenter__.return_value = mock_context

                # First webhook fails, second succeeds - but this should still raise error
                mock_context.post = AsyncMock(
                    side_effect=[
                        httpx.ConnectError("Connection failed"),
                        httpx.ConnectError("Connection failed"),
                        httpx.ConnectError(
                            "Connection failed"
                        ),  # 3 retries for first webhook
                        mock_success_response,  # Second webhook succeeds
                    ]
                )

                with pytest.raises(
                    ValueError,
                    match="Failed to send Discord webhook due to connection errors after 3 attempts",
                ):
                    await send_discord_webhook(sample_message)


class TestWebhookIntegration:
    """Integration tests for webhook functionality."""

    @pytest.mark.asyncio
    async def test_webhook_json_serialization(self, mock_config_manager):
        """Test that complex objects are properly JSON serialized."""
        complex_message = {
            "alert": "Security Issue",
            "severity": "HIGH",
            "details": {
                "repository": "test/repo",
                "workflow": "ci.yml",
                "issues": ["injection", "pwn_request"],
            },
        }

        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_context
            mock_context.post = AsyncMock(return_value=mock_response)

            await send_slack_webhook(complex_message)
            await send_discord_webhook(complex_message)

            # Verify both webhooks were called
            assert mock_context.post.call_count == 4  # 2 slack + 2 discord webhooks

            # Verify JSON serialization worked
            calls = mock_context.post.call_args_list
            for call in calls:
                args, kwargs = call
                payload = kwargs["json"]
                # Should contain properly formatted JSON
                if "text" in payload:  # Slack
                    assert '"alert": "Security Issue"' in payload["text"]
                elif "content" in payload:  # Discord
                    assert '"alert": "Security Issue"' in payload["content"]

    @pytest.mark.asyncio
    async def test_webhook_unicode_handling(self, mock_config_manager):
        """Test that unicode characters are handled properly."""
        unicode_message = "Test message with unicode: 🚨 Alert! 中文 العربية"

        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_context
            mock_context.post = AsyncMock(return_value=mock_response)

            await send_slack_webhook(unicode_message)
            await send_discord_webhook(unicode_message)

            # Should handle unicode without errors
            assert mock_context.post.call_count == 4

    @pytest.mark.asyncio
    async def test_send_discord_webhook_long_message_with_attachment(
        self, mock_config_manager, long_message
    ):
        """Test Discord webhook with long message that gets split into summary + attachment."""
        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_context
            mock_context.post = AsyncMock(return_value=mock_response)

            await send_discord_webhook(long_message)

            # Verify correct number of calls (2 webhooks)
            assert mock_context.post.call_count == 2

            # Verify multipart payload format
            calls = mock_context.post.call_args_list
            for call in calls:
                args, kwargs = call
                assert "data" in kwargs
                assert "files" in kwargs
                
                # Check data payload
                data = kwargs["data"]
                assert "payload_json" in data
                payload = json.loads(data["payload_json"])
                assert "content" in payload
                assert "Analysis Summary:" in payload["content"]
                assert "analysis_details.json" in payload["content"]
                
                # Check file attachment
                files = kwargs["files"]
                assert "files[0]" in files
                filename, file_obj, content_type = files["files[0]"]
                assert filename == "analysis_details.json"
                assert content_type == "application/json"
                assert isinstance(file_obj, io.BytesIO)

    @pytest.mark.asyncio
    async def test_send_discord_webhook_long_message_timeout(
        self, mock_config_manager, long_message
    ):
        """Test Discord webhook with long message uses extended timeout."""
        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_context
            mock_context.post = AsyncMock(return_value=mock_response)

            await send_discord_webhook(long_message)

            # Verify timeout is set to 30.0 for long messages with attachments
            mock_client.assert_called_once_with(
                http2=True, follow_redirects=True, timeout=30.0
            )

    @pytest.mark.asyncio
    async def test_send_discord_webhook_short_message_normal_flow(
        self, mock_config_manager, sample_message
    ):
        """Test Discord webhook with short message uses normal JSON flow."""
        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_context
            mock_context.post = AsyncMock(return_value=mock_response)

            await send_discord_webhook(sample_message)

            # Verify normal JSON payload
            calls = mock_context.post.call_args_list
            for call in calls:
                args, kwargs = call
                assert "json" in kwargs
                assert "data" not in kwargs
                assert "files" not in kwargs
                
                payload = kwargs["json"]
                assert "content" in payload


class TestSummaryGeneration:
    """Test cases for result summary generation."""

    def test_create_result_summary_complete_data(self, sample_result_data):
        """Test summary generation with complete result data."""
        summary = _create_result_summary(sample_result_data)
        
        assert '"repository_name": "AmyJeanes/TARDIS"' in summary
        assert '"issue_type": "PwnRequestResult"' in summary
        assert '"triggers": ["pull_request_target"]' in summary
        assert '"initial_workflow": "generate-files.yml"' in summary
        assert '"confidence": "High"' in summary
        assert '"attack_complexity": "No Interaction"' in summary
        assert '"explanation"' in summary
        
        # Verify JSON structure
        assert summary.startswith("{")
        assert summary.endswith("}")
        assert summary.count('"repository_name"') == 1

    def test_create_result_summary_partial_data(self):
        """Test summary generation with partial result data."""
        partial_data = {
            "repository_name": "test/repo",
            "issue_type": "InjectionResult",
            "confidence": "Medium"
        }
        
        summary = _create_result_summary(partial_data)
        
        assert '"repository_name": "test/repo"' in summary
        assert '"issue_type": "InjectionResult"' in summary
        assert '"confidence": "Medium"' in summary
        assert '"triggers"' not in summary
        assert '"initial_workflow"' not in summary

    def test_create_result_summary_empty_data(self):
        """Test summary generation with empty result data."""
        summary = _create_result_summary({})
        
        assert summary == "{\n    \n}"

    def test_create_result_summary_special_characters(self):
        """Test summary generation with special characters in data."""
        special_data = {
            "repository_name": "user/repo-with-dashes_and_underscores",
            "explanation": 'This has "quotes" and \nNewlines\tTabs',
            "triggers": ["push", "pull_request"]
        }
        
        summary = _create_result_summary(special_data)
        
        # Should handle special characters properly
        assert 'repo-with-dashes_and_underscores' in summary
        assert '["push", "pull_request"]' in summary
