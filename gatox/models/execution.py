import datetime

from gatox.models.organization import Organization, Repository


class Execution:
    """Simple wrapper class to provide accessor methods against a full Gato
    execution run.
    """

    def __init__(self):
        """Initialize wrapper class."""
        self.user_details = None
        self.organizations: list[Organization] = []
        self.repositories: list[Repository] = []
        self.timestamp = datetime.datetime.now()

    def add_organizations(self, organizations: list[Organization]):
        """Add list of organization wrapper objects.

        Args:
            organizations (List[Organization]): List of org wrappers.
        """
        if organizations:
            self.organizations = organizations

    def add_repositories(self, repositories: list[Repository]):
        """Add list of organization wrapper objects.

        Args:
            organizations (List[Organization]): List of org wrappers.
        """
        if repositories:
            self.repositories = repositories

    def set_user_details(self, user_details):
        """_summary_

        Args:
            user_details (dict): Details about the user's permissions.
        """
        self.user_details = user_details

    def toJSON(self):
        """Converts the run to Gato JSON representation"""

        if self.user_details:
            representation = {
                "username": self.user_details["user"],
                "scopes": self.user_details["scopes"],
                "enumeration": {
                    "timestamp": self.timestamp.ctime(),
                    "organizations": [
                        organization.toJSON()
                        for organization in self.organizations
                        if isinstance(organization, Organization)
                    ],
                    "repositories": [
                        repository.toJSON()
                        for repository in self.repositories
                        if isinstance(repository, Repository)
                    ],
                },
            }

            return representation
