import pytest
from unittest.mock import patch

from gatox import main


@patch("sys.argv", ["gatox"])
def test_cli_double_proxy(capfd):
    """Test case where no arguments are provided."""
    with pytest.raises(SystemExit):
        main.entry()

    _, err = capfd.readouterr()
    assert "the following arguments are required: command" in err
