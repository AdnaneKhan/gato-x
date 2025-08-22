"""
Copyright 2024, Adnan Khan

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import glob
import json
import os


class ConfigurationManager:
    """
    A singleton class to manage configuration data.

    Attributes:
        _instance (ConfigurationManager): The singleton instance of the ConfigurationManager class.
        _config (dict): The loaded configuration data.
    """

    _instance = None
    _config = None

    def __new__(cls, *args, **kwargs):
        """
        Overrides the default object creation behavior to implement the singleton pattern.

        Returns:
            ConfigurationManager: The singleton instance of the ConfigurationManager class.
        """
        if cls._instance is None:
            cls._instance = super(ConfigurationManager, cls).__new__(
                cls, *args, **kwargs
            )
            script_dir = os.path.dirname(os.path.realpath(__file__))
            json_files = glob.glob(os.path.join(script_dir, "*.json"))
            for file_path in json_files:
                cls._instance.load(file_path)
        return cls._instance

    def load(self, file_path):
        """
        Loads a JSON file and merges its entries into the existing configuration data.

        Args:
            file_path (str): The path to the JSON file to load.
        """
        with open(file_path) as f:
            config = json.load(f)
            if self._config is None:
                self._config = {}
                self._config[config["name"]] = config["entries"]
            else:
                self._config[config["name"]] = config["entries"]

    def __getattr__(self, name):
        """
        Overrides the default attribute access behavior. If the attribute name matches the 'name' field in the configuration data, it returns the 'entries' field. Otherwise, it raises an AttributeError.

        Args:
            name (str): The name of the attribute to access.

        Returns:
            dict: The 'entries' field of the configuration data if the attribute name matches the 'name' field.

        Raises:
            AttributeError: If the attribute name does not match the 'name' field in the configuration data.
        """
        if self._config and name in self._config:
            return self._config[name]
        else:
            raise AttributeError(
                f"'ConfigurationManager' object has no attribute '{name}'"
            )
