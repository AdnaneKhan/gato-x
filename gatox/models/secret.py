class Secret:
    """Simple wrapper class to parse secret response JSON from GitHub. Used
    primarily to facilitate JSON generation and to support future
    in-depth analysis of run logs and/or workflows.
    """

    def __init__(self, secret_data: dict, parent: str, environment: str = None):
        """Initialize wrapper object for secret.

        Args:
            secret_data (dict): Data about secret returned from the GitHub API.
            parent (str): Repository or organization name that this secret
            belongs to.
        """
        self.secret_data = secret_data
        self.name = secret_data["name"]
        self.parent = parent

        if "repos" in secret_data:
            self.visibility = "selected"
            self.selected_repos = secret_data["repos"]
        else:
            self.visibility = "private"

        if environment:
            self.environment = environment
        else:
            self.environment = None

    def is_repo_level(self):
        """Returns true if the secret is a repository level secret.

        Returns:
            bool: True if this is a repository level secret.
        """
        return "/" in self.parent

    def toJSON(self):
        """Converts the repository to a Gato JSON representation."""
        representation = {
            "name": self.name,
            "updated_at": self.secret_data["updated_at"],
            "created_at": self.secret_data["created_at"],
            "visibility": self.visibility,
            "repo_level": self.is_repo_level(),
        }

        if self.environment:
            representation["environment"] = self.environment

        return representation
