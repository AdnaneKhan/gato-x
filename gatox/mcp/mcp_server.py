"""
MCP server for Gato-X enumeration using FastMCP.
Exposes all enumerate functionality as LLM-friendly tools.
"""

import asyncio
import os

from fastmcp import Context, FastMCP
from pydantic import BaseModel, Field, field_validator
from typing import Optional, List

from gatox.enumerate.enumerate import Enumerator
from gatox.cli.output import Output

app = FastMCP(
    name="Gato-X MCP Server",
    instructions="MCP server exposing Gato-X GitHub enumeration tools.",
)


class MCPAuthParams(BaseModel):
    """
    Authentication and proxy options for GitHub enumeration. The GitHub Personal Access Token (PAT) is required and should be provided via the GH_TOKEN environment variable. If not set, an error will be raised. SOCKS and HTTP proxies are mutually exclusive.
    """

    socks_proxy: Optional[str] = Field(
        None, description="SOCKS proxy in HOST:PORT format (optional)"
    )
    http_proxy: Optional[str] = Field(
        None, description="HTTP proxy in HOST:PORT format (optional)"
    )
    github_url: Optional[str] = Field(
        None,
        description="Custom GitHub API URL (optional, defaults to https://api.github.com)",
    )
    skip_runners: Optional[bool] = Field(
        True,
        description="If true, skips runner enumeration via run-log analysis for speed, but may miss self-hosted runners for non-admin users.",
    )
    ignore_workflow_run: Optional[bool] = Field(
        False,
        description="If true, ignores the workflow_run trigger when enumerating repositories. Useful if the org requires approval for all fork PRs.",
    )
    deep_dive: Optional[bool] = Field(
        False,
        description="If true, performs deep-dive static analysis, including non-default branches for Pwn Request vulnerabilities. Requires git on PATH.",
    )

    @field_validator("socks_proxy")
    @classmethod
    def validate_proxies(cls, v, values):
        if v and values.get("http_proxy"):
            raise ValueError("Cannot use both SOCKS and HTTP proxy at the same time.")
        return v

    @property
    def pat(self) -> str:
        pat = os.environ.get("GH_TOKEN")
        if not pat:
            raise ValueError(
                "No 'GH_TOKEN' environment variable set! Please provide a GitHub PAT via GH_TOKEN."
            )
        return pat


class EnumerateOrganizationInput(MCPAuthParams):
    """
    Enumerate a GitHub organization for self-hosted runner abuse, workflow security, and repository security posture. Returns detailed findings, recommendations, and a summary of all non-archived repositories in the organization. The organization name is required.
    """

    target: str = Field(
        ..., description="Organization name to enumerate (e.g., 'octocat')"
    )


class EnumerateRepositoryInput(MCPAuthParams):
    """
    Enumerate a single repository in org/repo format for self-hosted runners, workflow security, and secrets exposure. Returns findings, secrets, runner info, and attack recommendations for the repository.
    """

    repository: str = Field(
        ...,
        description="Repository in 'owner/repo' format to enumerate (e.g., 'octocat/Hello-World')",
    )
    single_commit: Optional[str] = Field(
        None,
        description="Scan a single commit SHA (40 hex chars). Only compatible with single repository enumeration. Assumes commit is latest on default branch.",
    )


class EnumerateRepositoriesInput(MCPAuthParams):
    """
    Enumerate a list of repositories for self-hosted runners, workflow security, and secrets exposure. Returns findings and recommendations for each repository. Provide a list of repositories in 'owner/repo' format.
    """

    repositories: List[str] = Field(
        ...,
        description="List of repositories in 'owner/repo' format (e.g., ['octocat/Hello-World', ...])",
    )


class SelfEnumerationInput(MCPAuthParams):
    """
    Enumerate all organizations and repositories accessible to the authenticated user (the PAT owner). Returns a summary of organizations and repositories, including security findings and recommendations.
    """

    pass


class ValidatePATInput(MCPAuthParams):
    """
    Validate the provided GitHub PAT for enumeration access and print organization memberships. Returns a list of organizations if the PAT is valid, or an error message if not.
    """

    pass


# --- Tool Implementations ---


def get_enumerator(params: MCPAuthParams):
    Output(False, suppress=True)  # Suppress other stdout
    return Enumerator(
        pat=params.pat,
        socks_proxy=params.socks_proxy,
        http_proxy=params.http_proxy,
        skip_log=params.skip_runners,
        github_url=params.github_url,
        ignore_workflow_run=params.ignore_workflow_run,
        deep_dive=params.deep_dive,
    )


@app.tool()
async def enumerate_organization(ctx: Context, params: EnumerateOrganizationInput):
    """
    Enumerate a GitHub organization for self-hosted runner abuse, workflow security, and repository security posture.

    This tool performs a comprehensive security enumeration of a specified GitHub organization. It analyzes all non-archived repositories within the organization for the following:
    - Self-hosted runner abuse potential
    - Workflow security issues (including Pwn Request and injection vulnerabilities)
    - Repository security posture and misconfigurations
    - Attack surface and actionable recommendations

    **Inputs:**
    - `target` (str, required): The organization name to enumerate (e.g., 'octocat').
    - All authentication and proxy options are inherited from MCPAuthParams (see class docstring for details).

    **Authentication:**
    - The GitHub Personal Access Token (PAT) must be provided via the `GH_TOKEN` environment variable.

    **Proxy/Advanced Options:**
    - See MCPAuthParams for SOCKS/HTTP proxy, custom GitHub API URL, and advanced scan options.

    **Returns:**
    - A dictionary (from `toJSON()`) with detailed findings, recommendations, and a summary of all non-archived repositories in the organization.

    **Typical Use:**
    - Use this tool to perform a deep security review of an entire GitHub organization, including all its repositories, for CI/CD and workflow-related risks.
    """
    with open("mcp_server_debug.log", "a") as debug_log:
        debug_log.write(f"enumerate_organization called with params: {params}\n")
    ctx.info(f"Enumerating organization: {params.target}")
    try:
        enumerator = get_enumerator(params)
        org = await enumerator.enumerate_organization(params.target)
        ctx.info(f"Enumeration complete for org: {params.target}")
        return org.toJSON()
    except Exception as e:
        ctx.error(f"Failed to enumerate organization {params.target}: {e}")
        return {"error": str(e), "details": getattr(e, "args", [])}


@app.tool()
async def enumerate_repository(ctx: Context, params: EnumerateRepositoryInput):
    """
    Enumerate a single GitHub repository for self-hosted runners, workflow security, and secrets exposure.

    This tool analyzes a single repository in 'owner/repo' format. It checks for self-hosted runners, workflow security issues, and secrets exposure. It can also scan a specific commit if provided.

    **Inputs:**
    - `repository` (str, required): The repository to enumerate (e.g., 'octocat/Hello-World').
    - All authentication and proxy options are inherited from MCPAuthParams.

    **Authentication:**
    - The GitHub PAT must be provided via the `GH_TOKEN` environment variable.

    **Proxy/Advanced Options:**
    - See MCPAuthParams for details.

    **Returns:**
    - A dictionary (from `toJSON()`) with findings, secrets, runner info, and attack recommendations for the repository.

    **Typical Use:**
    - Use this tool to perform a deep security review of a single repository, or to scan a specific commit for security issues.
    """
    ctx.info(f"Enumerating repository: {params.repository}")
    try:
        enumerator = get_enumerator(params)
        repo = await enumerator.enumerate_repo(params.repository)
        ctx.info(f"Enumeration complete for repo: {params.repository}")
        return repo.toJSON()
    except Exception as e:
        ctx.error(f"Failed to enumerate repository {params.repository}: {e}")
        return {"error": str(e), "details": getattr(e, "args", [])}


@app.tool()
async def enumerate_repositories(ctx: Context, params: EnumerateRepositoriesInput):
    """
    Enumerate a list of GitHub repositories for self-hosted runners, workflow security, and secrets exposure.

    This tool takes a list of repositories in 'owner/repo' format and performs security enumeration on each. It is ideal for batch analysis or for organizations with many repositories.

    **Inputs:**
    - `repositories` (List[str], required): List of repositories to enumerate (e.g., ['octocat/Hello-World', ...]).
    - All authentication and proxy options are inherited from MCPAuthParams.

    **Authentication:**
    - The GitHub PAT must be provided via the `GH_TOKEN` environment variable.

    **Proxy/Advanced Options:**
    - See MCPAuthParams for details.

    **Returns:**
    - A list of dictionaries (from `toJSON()`) with findings and recommendations for each repository.

    **Typical Use:**
    - Use this tool to enumerate multiple repositories at once, such as all repos in a file or list.
    """
    ctx.info(f"Enumerating repositories: {params.repositories}")
    try:
        enumerator = get_enumerator(params)
        repos = await enumerator.enumerate_repos(params.repositories)
        ctx.info(f"Enumeration complete for repos: {params.repositories}")
        return [r.toJSON() for r in repos]
    except Exception as e:
        ctx.error(f"Failed to enumerate repositories {params.repositories}: {e}")
        return {"error": str(e), "details": getattr(e, "args", [])}


@app.tool()
async def self_enumeration(ctx: Context, params: SelfEnumerationInput):
    """
    Enumerate all organizations and repositories accessible to the authenticated user (the PAT owner).

    This tool enumerates all organizations and repositories that the authenticated user (PAT owner) has access to. It is useful for understanding the full scope of access and potential attack surface for a given token.

    **Inputs:**
    - All authentication and proxy options are inherited from MCPAuthParams.

    **Authentication:**
    - The GitHub PAT must be provided via the `GH_TOKEN` environment variable.

    **Proxy/Advanced Options:**
    - See MCPAuthParams for details.

    **Returns:**
    - A dictionary with two keys: 'organizations' (list of orgs) and 'repositories' (list of repos), each as dictionaries from `toJSON()`.

    **Typical Use:**
    - Use this tool to enumerate everything the current token can access, for access reviews or attack surface mapping.
    """
    ctx.info("Performing self-enumeration for authenticated user")
    try:
        enumerator = get_enumerator(params)
        orgs, repos = await enumerator.self_enumeration()
        ctx.info("Self-enumeration complete")
        return {
            "organizations": [o.toJSON() for o in orgs],
            "repositories": [r.toJSON() for r in repos],
        }
    except Exception as e:
        ctx.error(f"Failed to perform self-enumeration: {e}")
        return {"error": str(e), "details": getattr(e, "args", [])}


@app.tool()
async def validate_pat(ctx: Context, params: ValidatePATInput):
    """
    Validate the provided GitHub PAT for enumeration access and print organization memberships.

    This tool checks if the provided GitHub PAT (from `GH_TOKEN`) is valid for enumeration and lists the organizations the token has access to. It is useful for validating credentials before running more expensive enumeration operations.

    **Inputs:**
    - All authentication and proxy options are inherited from MCPAuthParams.

    **Authentication:**
    - The GitHub PAT must be provided via the `GH_TOKEN` environment variable.

    **Returns:**
    - A list of organizations (from `toJSON()`) if the PAT is valid, or an error message if not.

    **Typical Use:**
    - Use this tool to check if a PAT is valid and to see which organizations it can enumerate.
    """
    ctx.info("Validating GitHub PAT")
    try:
        enumerator = get_enumerator(params)
        orgs = await enumerator.validate_only()
        ctx.info("PAT validation complete")
        return [org.toJSON() for org in orgs]
    except Exception as e:
        ctx.error(f"Failed to validate PAT: {e}")
        return {"error": str(e), "details": getattr(e, "args", [])}


async def main():
    await app.run_async(transport="stdio")


def entry():
    return asyncio.run(main())


if __name__ == "__main__":
    asyncio.run(main())
