# Persistence Techniques

This guide covers advanced persistence techniques for maintaining access to GitHub repositories during red team operations and security assessments. These techniques create lasting backdoors that can survive various defensive actions and provide multiple avenues for re-entry.

> **Note**: This guide is intended for authorized security testing only. Always ensure you have proper permission before using these techniques.

## Overview

Persistence in GitHub environments refers to maintaining access to repositories and their resources even after the initial compromise vector has been discovered or remediated. Unlike traditional infrastructure, GitHub persistence techniques leverage the platform's collaborative features and CI/CD capabilities to create subtle, durable backdoors.

## Why Use Persistence Techniques?

### 1. **Simulate Real-World Threats**

Modern attackers don't rely on single points of access. They establish multiple persistence mechanisms to:
- Survive credential rotation and security responses
- Maintain access during incident response activities
- Demonstrate the full impact of a compromise to stakeholders
- Test detection capabilities across different attack vectors

### 2. **Assess Detection and Response Capabilities**

Persistence techniques help evaluate:
- Whether security teams can identify unauthorized collaborators
- If deploy key creation generates appropriate alerts
- Whether malicious workflow creation is detected
- How quickly unauthorized access is discovered and remediated

### 3. **Test Privilege Escalation Paths**

Different persistence techniques require different privilege levels, allowing you to:
- Demonstrate what attackers can achieve with admin access vs. write access
- Show how lower-privilege accounts can be used for lasting compromise
- Illustrate the business impact of over-privileged service accounts

### 4. **Evaluate CI/CD Security Posture**

The malicious workflow technique specifically tests:
- Whether pull request workflows have appropriate restrictions
- If secret access is properly limited in CI/CD pipelines
- How external contributions are validated and monitored

## Persistence Techniques and Their Characteristics

### 1. Collaborator Invitation

**Privilege Required**: Admin  
**Durability**: High (survives PAT revocation)  
**Stealth**: Medium (visible in repository settings)  
**Business Impact**: High (ongoing access to all repository data)

#### Why This Works
- GitHub's collaborative model makes external contributors normal
- Collaborator access persists independently of the original compromise
- Different permission levels can be granted (read, write, admin)

#### Real-World Scenario
An attacker compromises a DevOps engineer's account with admin privileges. They invite their own account as a collaborator with admin permissions. Even after the original account is secured, the attacker maintains full repository access.

#### Detection Challenges
- Collaborator additions may be buried in audit logs
- Large organizations often have frequent collaborator changes
- Legitimate external consultants and contractors create noise

### 2. Deploy Key Creation

**Privilege Required**: Admin  
**Durability**: Medium (removed when creating PAT is revoked)  
**Stealth**: High (SSH keys are difficult to audit)  
**Business Impact**: High (Git-level access to repository)

#### Why This Works
- Deploy keys provide Git access independent of user accounts
- SSH key access is often less monitored than web-based access
- Keys can be given descriptive names that blend with legitimate keys

#### Real-World Scenario
An attacker gains admin access and creates a deploy key titled "CI/CD Integration Key". This provides persistent Git access for cloning, pulling, and pushing code changes directly, bypassing web-based authentication entirely.

#### Critical Quirk: PAT Dependency
**Important**: Deploy keys are automatically removed when the PAT used to create them is revoked or the user loses access. This makes deploy keys less durable than collaborator invitations but still valuable for short-to-medium term persistence.

#### Detection Challenges
- SSH keys are rarely audited compared to user accounts
- Legitimate deploy keys are common in development environments
- Key titles can mimic legitimate infrastructure components

### 3. Malicious Pull Request Target Workflow

**Privilege Required**: Write  
**Durability**: Very High (survives until branch deletion)  
**Stealth**: Very High (hidden on non-default branches)  
**Business Impact**: Critical (secret exfiltration + arbitrary code execution)

#### Why This Works
- `pull_request_target` workflows run with elevated permissions
- Non-default branches are rarely reviewed or monitored
- External contributors can trigger workflows without repository access
- Workflows can access all repository secrets

#### Real-World Scenario
An attacker with write access creates a branch called "feature/ci-improvements" containing a malicious workflow. Months later, any external contributor creating a PR against this branch unknowingly triggers the workflow, which exfiltrates secrets and executes attacker commands.

#### Unique Persistence Properties
**Branch Persistence**: Unlike other techniques, this persists until someone specifically deletes the branch or workflow file. It's immune to:
- User account compromises being discovered
- PAT revocation
- Permission changes
- User departures from the organization

#### Advanced Usage
The workflow can be designed to:
- Only trigger on specific conditions to avoid detection
- Exfiltrate data to external services
- Modify repository contents
- Create additional persistence mechanisms
- Establish command and control channels

## Tactical Considerations

### Combining Techniques
For maximum persistence, use multiple techniques:

1. **Immediate Access**: Deploy key for quick Git access
2. **User-Level Persistence**: Collaborator invitation for ongoing web access  
3. **Workflow Persistence**: Malicious pull_request_target for long-term backdoor

### Timing and Stealth
- Space out technique deployment over days or weeks
- Use realistic names and descriptions
- Deploy during high-activity periods when changes are less noticeable
- Consider organizational patterns (e.g., when are external collaborators typically added?)

### Cleanup Considerations
During red team exercises, plan for cleanup:
- Document all created persistence mechanisms
- Provide detailed remediation instructions
- Consider the effort required to fully remove each technique

## Defensive Recommendations

### For Collaborator Invitations
- Implement approval workflows for collaborator additions
- Regular audit of repository collaborators
- Monitor for unexpected permission escalations
- Use teams instead of direct collaborator access where possible

### For Deploy Keys
- Regular audit of all deploy keys across repositories
- Implement naming conventions and approval processes
- Monitor for SSH key authentication in logs
- Consider certificate-based authentication instead of keys

### For Malicious Workflows
- Require approval for workflow changes on all branches
- Implement branch protection rules for non-default branches
- Monitor workflow execution across all branches
- Restrict `pull_request_target` usage organization-wide
- Regular scanning of workflow files across all branches

## Related Techniques

- [Post-Compromise Enumeration](post-compromise.md) - Discovering persistence opportunities after initial access
- [Self-Hosted Runner Takeover](runner-takeover.md) - Compromising CI/CD infrastructure for persistence

## Legal and Ethical Considerations

These techniques should only be used in authorized security testing scenarios:
- Obtain written permission before deployment
- Document all persistence mechanisms for complete cleanup
- Consider the business impact of persistence during active operations
- Provide comprehensive remediation guidance to stakeholders