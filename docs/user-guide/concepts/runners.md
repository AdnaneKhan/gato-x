# Self-Hosted Runners

GitHub Actions supports two primary types of runners for executing workflow jobs: GitHub-hosted runners and self-hosted runners[^1]. While GitHub-hosted runners provide a convenient, managed solution, many organizations opt for self-hosted runners to gain greater control over their CI/CD environment. However, this control comes with significant security responsibilities and potential risks that organizations must carefully consider[^2].

## Overview

Self-hosted runners are machines that you manage and maintain to run GitHub Actions workflows[^3]. Unlike GitHub-hosted runners, which are ephemeral virtual machines managed by GitHub, self-hosted runners persist across workflow runs and provide organizations with:

- **Custom hardware configurations** - Access to specific CPU architectures, GPUs, or high-memory instances
- **Network access** - Ability to reach internal resources, databases, and private networks
- **Software dependencies** - Pre-installed tools, libraries, and custom software stacks
- **Performance optimization** - Faster builds through persistent caches and pre-warmed environments
- **Cost control** - Reduced costs for high-volume CI/CD workloads

However, these benefits come with significant security trade-offs that make self-hosted runners a prime target for attackers.

## Runner Types and Configurations

### GitHub-Hosted vs Self-Hosted Runners

**GitHub-Hosted Runners** are identified by standard labels such as[^4]:
```yaml
runs-on: ubuntu-latest
runs-on: windows-latest
runs-on: macos-latest
runs-on: ubuntu-22.04
```

These runners are:
- Ephemeral (destroyed after each job)
- Isolated from other workloads
- Managed and patched by GitHub
- Limited in terms of hardware specifications and network access

**Self-Hosted Runners** are identified by custom labels or explicit configuration:
```yaml
runs-on: self-hosted
runs-on: [self-hosted, linux, x64]
runs-on: [self-hosted, production-deployment]
runs-on: custom-gpu-runner
```

### Runner Scopes and Access Levels

Self-hosted runners can be configured at different organizational levels[^5]:

#### Repository-Level Runners
- Accessible only to workflows within a specific repository
- Simplest configuration but limited scalability
- Often used for repository-specific hardware requirements

#### Organization-Level Runners
- Shared across multiple repositories within an organization
- More efficient resource utilization
- Requires careful access control and runner group management

#### Enterprise-Level Runners
- Available across multiple organizations within an enterprise
- Highest level of resource sharing
- Complex security and governance requirements

### Runner Groups

Runner groups provide a mechanism for organizing and controlling access to self-hosted runners within organizations and enterprises[^6]:

```yaml
# Example workflow targeting a specific runner group
runs-on: [self-hosted, production-group]
```

**Key characteristics of runner groups:**
- **Access Control**: Restrict which repositories can use specific runners
- **Security Boundaries**: Isolate sensitive workloads from general-purpose runners
- **Resource Management**: Group runners by purpose (e.g., production, testing, deployment)
- **Audit and Compliance**: Track usage and access patterns for compliance requirements

## Ephemeral Runner Types

Modern self-hosted runner deployments increasingly favor ephemeral patterns to reduce security risks while maintaining the benefits of self-hosted infrastructure.

### Actions Runner Controller (ARC)

ARC is a Kubernetes-based solution for running ephemeral self-hosted runners[^7]:

```yaml
# Example ARC RunnerDeployment
apiVersion: actions.summerwind.dev/v1alpha1
kind: RunnerDeployment
metadata:
  name: example-runner
spec:
  template:
    spec:
      repository: myorg/myrepo
      ephemeral: true
      labels:
        - self-hosted
        - linux
        - x64
```

**ARC Benefits:**
- **Ephemeral by design**: Runners are created and destroyed for each job
- **Kubernetes integration**: Leverages existing container orchestration infrastructure
- **Scalability**: Automatic scaling based on workflow demand
- **Resource efficiency**: Optimal resource utilization through container scheduling

**ARC Security Considerations:**
- Container escape vulnerabilities
- Kubernetes RBAC misconfigurations
- Image supply chain security
- Pod-to-pod network access

### Custom Ephemeral Implementations

Organizations may implement custom ephemeral runner solutions using[^8]:

- **Virtual machine orchestration** (VMware, Proxmox, cloud providers)
- **Container platforms** (Docker, Podman, containerd)
- **Cloud auto-scaling** (AWS Auto Scaling Groups, Azure VMSS, GCP MIGs)

Example implementation pattern:
```bash
# VM-based ephemeral runner lifecycle
1. Workflow triggered → API webhook received
2. Create fresh VM from golden image
3. Register runner with GitHub
4. Execute workflow job
5. Unregister runner
6. Destroy VM and all artifacts
```

## Security Risks and Attack Vectors

Self-hosted runners present a significant attack surface that organizations must carefully secure. The persistent nature of traditional self-hosted runners, combined with their network access and elevated permissions, makes them attractive targets for attackers.

### Code Execution and Privilege Escalation

**Pull Request Poisoning**: Attackers can submit malicious pull requests that execute arbitrary code on self-hosted runners:

```yaml
# Dangerous workflow pattern
name: CI
on: pull_request
jobs:
  test:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
      - run: |
          # Attacker-controlled code from PR
          npm install
          npm test
```

**Command Injection**: Unsanitized inputs can lead to command execution:

```yaml
# Vulnerable to injection via issue title
- run: echo "Processing issue: ${{ github.event.issue.title }}"
```

### Instance and Cloud Metadata Access

Self-hosted runners often inherit cloud instance roles and metadata access, creating significant security risks:

**AWS Instance Metadata**:
```bash
# Attackers can access instance credentials
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Azure Instance Metadata**:
```bash
# Access Azure managed identity tokens
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token"
```

**GCP Instance Metadata**:
```bash
# Retrieve GCP service account tokens
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

### Network Access and Lateral Movement

Self-hosted runners typically have broad network access, enabling:

- **Internal network reconnaissance**
- **Database and service enumeration**
- **Credential harvesting from network shares**
- **Lateral movement to other systems**

### Cache and Artifact Poisoning

Persistent caches and shared storage can be exploited for:

- **Cache poisoning attacks** - Malicious dependencies injected into build caches
- **Artifact tampering** - Modification of build outputs and deployment artifacts
- **Data exfiltration** - Sensitive information stored in caches or logs

### Runner-on-Runner Attacks

In shared runner environments, compromised jobs can potentially:

- **Access other job artifacts**
- **Interfere with concurrent builds**
- **Establish persistent backdoors**
- **Pivot to runner management systems**

## Common Pitfalls and Misconfigurations

### Insufficient Trigger Restrictions

**Problem**: Using broad trigger conditions that allow untrusted code execution
```yaml
# Dangerous - allows any PR to execute code
on: pull_request

# Better - restrict to specific events
on: 
  pull_request:
    types: [labeled]
  # Only run when 'safe-to-test' label is applied
```

### Missing Input Validation

**Problem**: Direct use of user-controlled inputs in shell commands
```yaml
# Vulnerable
- run: echo "Hello ${{ github.event.issue.title }}"

# Safer
- name: Validate input
  run: |
    title="${{ github.event.issue.title }}"
    if [[ "$title" =~ ^[a-zA-Z0-9\ ]+$ ]]; then
      echo "Hello $title"
    else
      echo "Invalid title format"
      exit 1
    fi
```

### Overprivileged Runner Access

**Problem**: Runners with excessive permissions or network access
- Running with administrator/root privileges
- Access to production databases and systems
- Overly broad cloud IAM roles

**Mitigation**:
- Follow principle of least privilege
- Use dedicated runner groups for sensitive operations
- Implement network segmentation and firewall rules

### Persistent Runner State

**Problem**: Long-lived runners accumulating sensitive data
- Cached credentials and tokens
- Build artifacts and temporary files
- Network connections and session state

**Mitigation**:
- Regular runner recreation cycles
- Automated cleanup procedures
- Ephemeral runner architectures

## Security Best Practices

### Runner Isolation and Segmentation

1. **Network Segmentation**: Isolate runners in dedicated network segments
2. **Runner Groups**: Use runner groups to control access and isolate workloads
3. **Repository Restrictions**: Limit which repositories can access specific runners

### Access Control and Permissions

1. **Minimal Permissions**: Grant only necessary permissions to runner processes
2. **Token Scoping**: Use repository-scoped or organization-scoped tokens appropriately
3. **Regular Rotation**: Implement automated token and credential rotation

### Monitoring and Auditing

1. **Comprehensive Logging**: Log all runner activities and access patterns
2. **Security Monitoring**: Implement real-time monitoring for suspicious activities
3. **Regular Audits**: Conduct periodic security assessments of runner configurations

### Ephemeral Architecture

1. **Stateless Runners**: Design runners to be completely stateless
2. **Automated Provisioning**: Use infrastructure as code for runner deployment
3. **Rapid Rotation**: Implement frequent runner recreation cycles

## Detection and Response

### Indicators of Compromise

Monitor for signs of runner compromise:

- **Unexpected network connections** to external services
- **Unusual process execution** patterns or privilege escalations
- **Anomalous resource usage** (CPU, memory, disk, network)
- **Suspicious file system changes** outside expected build directories
- **Unauthorized access attempts** to cloud metadata services

### Incident Response Procedures

1. **Immediate Isolation**: Disconnect compromised runners from network
2. **Forensic Collection**: Preserve logs and artifacts for analysis
3. **Impact Assessment**: Determine scope of potential data exposure
4. **Recovery**: Rebuild runners from known-good configurations
5. **Lessons Learned**: Update security controls based on incident findings

## Security Research and References

The security community has extensively researched self-hosted runner vulnerabilities and attack techniques. Key presentations and research include:

### Conference Presentations

- **"Self-Hosted Runners: The Achilles Heel of GitHub Actions"** - BlackHat 2024
  - Comprehensive analysis of self-hosted runner attack vectors
  - Demonstration of privilege escalation and lateral movement techniques
  - Best practices for securing runner environments

- **"Grand Theft Actions: Pwning Your CI/CD Pipeline"** - DEF CON 32
  - Real-world case studies of CI/CD pipeline compromises
  - Advanced persistence techniques in runner environments
  - Detection and response strategies

### Academic Research

- **"Continuous Integration and Deployment Security"** - Various security conferences
- **"Container Escape Techniques in Kubernetes Environments"** - Cloud security research
- **"CI/CD Pipeline Security: Threats and Mitigations"** - DevSecOps publications

## Conclusion

Self-hosted runners provide powerful capabilities for organizations requiring custom CI/CD environments, but they also introduce significant security risks that must be carefully managed. The key to secure self-hosted runner deployment lies in:

1. **Understanding the attack surface** and potential impact of compromise
2. **Implementing defense-in-depth** security controls
3. **Adopting ephemeral architectures** where possible
4. **Maintaining vigilant monitoring** and incident response capabilities
5. **Staying informed** about emerging threats and best practices

Organizations should carefully weigh the benefits of self-hosted runners against the security responsibilities they entail, and ensure they have the necessary expertise and resources to operate them securely.

For detailed guidance on specific vulnerabilities and attack techniques, see the [Vulnerabilities](../advanced/vulnerabilities.md) section. For practical enumeration and assessment techniques, refer to the [Command Reference](../command-reference/enumerate.md).