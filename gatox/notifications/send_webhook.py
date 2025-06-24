import httpx
import logging
import json
import asyncio
from typing import List

from gatox.configuration.configuration_manager import ConfigurationManager

logger = logging.getLogger(__name__)


async def send_slack_webhook(message: str) -> None:
    """Send a message to configured Slack webhooks asynchronously.

    Args:
        message: The message to send to Slack

    Raises:
        ValueError: If the request to Slack fails after retries
    """
    payload = {"text": json.dumps(message, indent=4)}
    hooks: List[str] = ConfigurationManager().NOTIFICATIONS["SLACK_WEBHOOKS"]

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
                    "Request to slack returned an error %s, the response is:\n%s"
                    % (response.status_code, response.text)
                )
