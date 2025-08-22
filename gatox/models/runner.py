class Runner:
    """Wrapper object for a self-hosted runner. Can represent a runner obtained
    via workflow log parsing or administrative query of repo/org level
    self-hosted runners.
    """

    def __init__(
        self,
        runner_name,
        runner_type=None,
        token_permissions=None,
        runner_group=None,
        machine_name=None,
        os=None,
        status=None,
        labels=None,
        non_ephemeral=False,
    ):
        """Constructor for runner wrapper object.

        Args:
            runner_name (str): Name of self-hosted runner.
            machine_name (str, optional): Machine name of runner gathered from
            run logs. Defaults to None.
            os (str, optional): OS of runner. Defaults to None.
            status (str, optional): Status of runner. Defaults to None.
            labels (list, optional): Labels applied to runner. Defaults to [].
        """
        if labels is None:
            labels = []
        self.runner_name = runner_name
        self.machine_name = machine_name
        self.runner_group = runner_group
        self.runner_type = runner_type
        self.token_permissions = token_permissions
        self.os = os
        self.status = status
        self.labels = labels
        self.non_ephemeral = non_ephemeral

    def toJSON(self):
        """Converts the repository to a Gato JSON representation."""
        representation = {
            "name": self.runner_name,
            "machine_name": self.machine_name if self.machine_name else "Unknown",
            "runner_type": self.runner_type if self.runner_type else "Unknown",
            "runner_group_name": self.runner_group if self.runner_group else "Unknown",
            "token_permissions": self.token_permissions,
            "os": self.os if self.os else "Unknown",
            "status": self.status if self.status else "Unknown",
            "labels": list(self.labels),
            "non_ephemeral": self.non_ephemeral,
        }

        return representation
