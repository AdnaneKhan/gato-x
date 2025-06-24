# Project Architecture

Gato-X is a modular Python toolkit for scanning, enumerating, and attacking GitHub Actions workflows. The architecture is designed for extensibility, speed, and clear separation of concerns.

## High-Level Overview

- **CLI Layer**: Entry point for all user commands (`gatox/cli/`).
- **Core Modules**: Implement scanning, enumeration, attack, and analysis logic.
- **Models**: Define data structures for repositories, workflows, runners, etc.
- **Utilities**: Shared helpers and configuration management.

## Directory Structure

```mermaid
flowchart TD
    CLI[CLI (gatox/cli)] -->|parses args| Main[main.py]
    Main -->|invokes| Search[Search (gatox/search)]
    Main -->|invokes| Enumerate[Enumerate (gatox/enumerate)]
    Main -->|invokes| Attack[Attack (gatox/attack)]
    Main -->|invokes| WorkflowGraph[Workflow Graph (gatox/workflow_graph)]
    Main -->|uses| Models[Models (gatox/models)]
    Main -->|uses| Utils[Utils (gatox/util)]
    Attack -->|uses| GitHubAPI[GitHub API (gatox/github)]
    Enumerate -->|uses| GitHubAPI
    Search -->|uses| GitHubAPI
    WorkflowGraph -->|parses| WorkflowParser[Workflow Parser]
    Models -->|used by| All
    Utils -->|used by| All
    Configuration[Configuration (gatox/configuration)] -->|provides| Utils
```

## Main Components

- **CLI (`gatox/cli/cli.py`)**: Parses user commands and dispatches to core modules.
- **Attack (`gatox/attack/`)**: Implements attack techniques (Runner-on-Runner, workflow injection, secrets exfiltration).
- **Enumerate (`gatox/enumerate/`)**: Analyzes repositories and organizations for vulnerabilities.
- **Search (`gatox/search/`)**: Finds candidate repositories and workflows.
- **Workflow Graph (`gatox/workflow_graph/`)**: Builds and analyzes workflow dependency graphs.
- **Models (`gatox/models/`)**: Data classes for repositories, workflows, runners, secrets, etc.
- **GitHub API (`gatox/github/`)**: Handles all GitHub API interactions.
- **Configuration (`gatox/configuration/`)**: Loads and manages configuration data.
- **Utils (`gatox/util/`)**: Shared utility functions.

## Data Flow

1. **User runs a CLI command** (e.g., `gato-x a --runner-on-runner ...`).
2. **CLI parses arguments** and calls the appropriate core module.
3. **Core module** (e.g., Attack) uses Models, GitHub API, and Utilities to perform its function.
4. **Results** are output to the user and/or saved to disk.

## Extensibility

- New attack/enumeration/search modules can be added under their respective directories.
- Data models are centralized in `gatox/models/` for consistency.
- Configuration is managed via JSON files in `gatox/configuration/`.
