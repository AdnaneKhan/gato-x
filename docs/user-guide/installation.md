# Installation

Gato-X supports OS X and Linux with at least **Python 3.10**.

## PyPI Installation

Gato-X is published on PyPI, so you can simply install it with:

```bash
pip install gato-x
```

## Installation from Source

### Using pip

We recommend using a virtual environment for `pip`:

```bash
git clone https://github.com/AdnaneKhan/gato-x
cd gato-x
python3 -m venv venv
source venv/bin/activate
pip install .
```

If you need to make on-the-fly modifications, install it in editable mode:

```bash
pip install -e .
```

### Using pipx

Alternatively, you can use pipx:

```bash
git clone https://github.com/AdnaneKhan/gato-x
cd gato-x
pipx install .
```

## GitHub Token Setup

The tool requires a GitHub classic Personal Access Token (PAT) to function. To create one:

1. Log in to GitHub
2. Go to [GitHub Developer Settings](https://github.com/settings/tokens)
3. Select `Generate New Token` and then `Generate new token (classic)`
4. Select the appropriate scopes based on your needs:
   - For basic scanning: `repo` scope
   - For attack features: `repo`, `workflow`, and `gist` scopes

After creating this token, set the `GH_TOKEN` environment variable within your shell:

```bash
export GH_TOKEN=<YOUR_CREATED_TOKEN>
```

Alternatively, you can enter it when the application prompts you.

## Verifying Installation

To verify that Gato-X is installed correctly, run:

```bash
gato-x --help
```

This should display the help menu with available commands and options.
