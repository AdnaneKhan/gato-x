import asyncio
import io
import json
import logging
from typing import Any

import httpx

from gatox.configuration.configuration_manager import ConfigurationManager

logger = logging.getLogger(__name__)


def _create_result_summary(result_data: dict[str, Any]) -> str:
    """Create a concise summary of analysis result for Discord messages.

    Args:
        result_data: Dictionary containing analysis result data

    Returns:
        Formatted summary string
    """
    summary_parts = []

    if "repository_name" in result_data:
        summary_parts.append(f'"repository_name": "{result_data["repository_name"]}"')

    if "issue_type" in result_data:
        summary_parts.append(f'"issue_type": "{result_data["issue_type"]}"')

    if "triggers" in result_data:
        triggers_str = json.dumps(result_data["triggers"])
        summary_parts.append(f'"triggers": {triggers_str}')

    if "initial_workflow" in result_data:
        summary_parts.append(f'"initial_workflow": "{result_data["initial_workflow"]}"')

    if "confidence" in result_data:
        summary_parts.append(f'"confidence": "{result_data["confidence"]}"')

    if "attack_complexity" in result_data:
        summary_parts.append(
            f'"attack_complexity": "{result_data["attack_complexity"]}"'
        )

    if "explanation" in result_data:
        summary_parts.append(f'"explanation": "{result_data["explanation"]}"')

    return "{\n    " + ",\n    ".join(summary_parts) + "\n}"


async def send_discord_webhook(message) -> None:
    """Send a message to configured Discord webhooks asynchronously.

    If the message exceeds 2000 characters, sends a summary with detailed path as attachment.

    Args:
        message: The message to send to Discord

    Raises:
        ValueError: If the request to Discord fails after retries
    """
    hooks: list[str] = ConfigurationManager().NOTIFICATIONS["DISCORD_WEBHOOKS"]

    # Convert message to JSON string if it's not already
    if isinstance(message, str):
        message_str = message
        # Parse message to determine if we need to split it
        try:
            result_data = json.loads(message)
        except json.JSONDecodeError:
            result_data = {"raw_message": message}
    else:
        # Message is a dict/object, convert to JSON string
        message_str = json.dumps(message, indent=4)
        result_data = message

    # Check if message is too long for Discord (2000 char limit)
    if len(message_str) > 2000:
        # Create summary
        summary = _create_result_summary(result_data)

        # Prepare multipart payload with attachment
        files = {
            "files[0]": (
                "analysis_details.json",
                io.BytesIO(message_str.encode()),
                "application/json",
            )
        }
        data = {
            "payload_json": json.dumps(
                {
                    "content": f"**Analysis Summary:**\n```json\n{summary}\n```\n\n*Full details attached as analysis_details.json*"
                }
            )
        }

        async with httpx.AsyncClient(
            http2=True, follow_redirects=True, timeout=30.0
        ) as client:
            for webhook in hooks:
                attempt = 0
                while attempt < 3:
                    try:
                        response = await client.post(webhook, data=data, files=files)
                        break  # Success; exit the retry loop.
                    except httpx.ConnectError:
                        attempt += 1
                        logging.warning(
                            f"Connection error sending Discord webhook, retrying! Attempt {attempt}/3"
                        )
                        await asyncio.sleep(1)
                else:
                    # All attempts failed.
                    raise ValueError(
                        "Failed to send Discord webhook due to connection errors after 3 attempts."
                    )

                if response.status_code not in [200, 204]:
                    raise ValueError(
                        f"Request to Discord returned an error {response.status_code}, the response is:\n{response.text}"
                    )
    else:
        # Message is short enough, send normally
        payload = {"content": message_str}

        async with httpx.AsyncClient(
            http2=True, follow_redirects=True, timeout=10.0
        ) as client:
            for webhook in hooks:
                attempt = 0
                while attempt < 3:
                    try:
                        response = await client.post(webhook, json=payload)
                        break  # Success; exit the retry loop.
                    except httpx.ConnectError:
                        attempt += 1
                        logging.warning(
                            f"Connection error sending Discord webhook, retrying! Attempt {attempt}/3"
                        )
                        await asyncio.sleep(1)
                else:
                    # All attempts failed.
                    raise ValueError(
                        "Failed to send Discord webhook due to connection errors after 3 attempts."
                    )

                if response.status_code not in [200, 204]:
                    raise ValueError(
                        f"Request to Discord returned an error {response.status_code}, the response is:\n{response.text}"
                    )


async def send_slack_webhook(message: str) -> None:
    """Send a message to configured Slack webhooks asynchronously.

    Args:
        message: The message to send to Slack

    Raises:
        ValueError: If the request to Slack fails after retries
    """
    payload = {"text": json.dumps(message, indent=4)}
    hooks: list[str] = ConfigurationManager().NOTIFICATIONS["SLACK_WEBHOOKS"]

    async with httpx.AsyncClient(
        http2=True, follow_redirects=True, timeout=10.0
    ) as client:
        for webhook in hooks:
            attempt = 0
            while attempt < 3:
                try:
                    response = await client.post(webhook, json=payload)
                    break  # Success; exit the retry loop.
                except httpx.ConnectError:
                    attempt += 1
                    logging.warning(
                        f"Connection error sending webhook, retrying! Attempt {attempt}/3"
                    )
                    await asyncio.sleep(1)
            else:
                # All attempts failed.
                raise ValueError(
                    "Failed to send webhook due to connection errors after 3 attempts."
                )

            if response.status_code != 200:
                raise ValueError(
                    f"Request to slack returned an error {response.status_code}, the response is:\n{response.text}"
                )
