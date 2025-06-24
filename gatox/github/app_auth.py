import jwt
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)


class GitHubAppAuth:
    """Handles GitHub App authentication and JWT generation."""

    def __init__(self, app_id: str, private_key_path: str):
        """Initialize GitHub App authentication.

        Args:
            app_id: The GitHub App ID
            private_key_path: Path to the private key PEM file
        """
        self.app_id = app_id
        self.private_key_path = Path(private_key_path)
        self._private_key = None

    def _load_private_key(self) -> str:
        """Load the private key from file."""
        if self._private_key is None:
            if not self.private_key_path.exists():
                raise FileNotFoundError(
                    f"Private key file not found: {self.private_key_path}"
                )

            with open(self.private_key_path, "r") as f:
                self._private_key = f.read()

        return self._private_key

    def generate_jwt(self, expiration_minutes: int = 10) -> str:
        """Generate a JWT for GitHub App authentication.

        Args:
            expiration_minutes: JWT expiration time in minutes (max 10)

        Returns:
            The generated JWT token
        """
        if expiration_minutes > 10:
            raise ValueError("JWT expiration cannot exceed 10 minutes")

        # Get current time
        now = datetime.now(timezone.utc)

        # JWT payload
        payload = {
            "iat": int(now.timestamp()),  # Issued at time
            "exp": int(
                (now + timedelta(minutes=expiration_minutes)).timestamp()
            ),  # Expiration time
            "iss": self.app_id,  # Issuer (App ID)
        }

        # Load private key
        private_key = self._load_private_key()

        # Generate JWT
        token = jwt.encode(payload, private_key, algorithm="RS256")

        logger.debug(f"Generated JWT for App ID {self.app_id}")
        return token
