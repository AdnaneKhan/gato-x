import yaml


class CICDAttack:
    """Class to encapsulate helper methods for attack features. Functionality
    here will focus on data processing and payload creation/management as
    opposed to API / Git interaction.
    """

    @staticmethod
    def create_push_yml(payload: str, branch_name: str):
        """Create a malicious yaml file that will trigger on push to a
        specific branch.

        Args:
            payload (str): Command to be executed as part of the 'run' payload.
            branch_name (str): Name of the branch for on: push trigger.

        Returns:
            str: Workflow yaml file containing the payload.
        """
        yaml_file = {}

        yaml_file["name"] = branch_name
        yaml_file["on"] = {"push": {"branches": branch_name}}

        test_job = {
            "runs-on": ["self-hosted"],
            "steps": [{"name": "Run Tests", "run": payload}],
        }
        yaml_file["jobs"] = {"testing": test_job}

        return yaml.dump(yaml_file, sort_keys=False)
