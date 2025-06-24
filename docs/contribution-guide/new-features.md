# Adding New Features

Want to add a new feature to Gato-X? This document highlights how you should approach adding a new
feature and key considerations to keep in mind.

## Adding a new Static Analysis Detection

Gato-X's static analysis is based on graph analysis. Gato-X builds a directed graph for each execution that includes all repositories, workflows, jobs, steps, and reusable actions within its scanning scope. After building the graph, Gato-X performs graph traversal from sources to specific sinks. Gato-X will lazily load resources during the graph traversal.

To add a new detection, you will need to add a new visitor to `gatox/workflow_graph/visitors`.



## Adding New Enumeration Modules

Enumeration modules in Gato-X are responsible for discovering and collecting information about organizations, repositories, runners, secrets, and workflows. To add a new enumeration module:

1. **Create your module** in `gatox/enumerate/` (e.g., `my_enum.py`).
2. **Implement your logic** as a class or function. Follow the structure of existing modules like `organization.py` or `repository.py`.
3. **Register your module** in the CLI:
   - Update `gatox/cli/app/enumeration/` to add a new command or subcommand if needed.
   - Ensure your module is discoverable by the main enumeration logic in `gatox/enumerate/enumerate.py`.
4. **Document input and output**: Clearly define what arguments your module accepts and what data it returns.
5. **Write tests**:
   - Add unit tests in `unit_test/` (e.g., `test_enumerate.py`).
   - Add integration tests in `test/` if your module interacts with live APIs or external systems.
6. **Update documentation**: Add usage examples and descriptions to the user guide and command reference as appropriate.

## Adding Attack Features

Attack features in Gato-X are designed to test the security posture of CI/CD environments by simulating real-world attack scenarios. To add a new attack feature:

1. **Create your attack module** in `gatox/attack/` or a relevant subdirectory (e.g., `gatox/attack/runner/`).
2. **Isolate attack logic**: Ensure your code does not affect enumeration or search modules. All mutating or exploitative actions must be clearly separated.
3. **Integrate with the CLI**:
   - Add a new command or subcommand in `gatox/cli/app/attack/`.
   - Register your feature in the main attack CLI logic (`gatox/attack/attack.py`).
4. **Add configuration options**: Allow users to specify targets, roles, or other parameters. Document all options.
5. **Write tests**:
   - Add unit tests in `unit_test/test_attack.py` or a new file.
   - For features that interact with live systems, provide safe test cases and clear documentation.
6. **Document the feature**: Update the user guide and advanced documentation with usage, risks, and mitigation strategies.

### Guardrails for Attack Functionality

Gato-X's attack tools should be isolated from enumeration and search functionality. Any mutating operation by Gato-X should be under the attack module or a new module that clearly outlines its purposes.

#### Avoid Mass Exploit Scenarios

Gato-X's automated attack scenarios should only target a single resource (repository, self-hosted runner, etc.). While it is possible to implement a feature to mass exfiltrate secrets from a single organization, this is not something that Gato-X will ever support because it is too risky. If a user needs it, then they can implement it in a local copy of Gato-X or fork.

#### Good Attack Feature Example

> Gato-X feature that pushes workflow that uses id-token: write and
attempts performs OIDC authentication with cloud providers and attempts to assume a provided list of roles.

This is a good attack feature because:

* It is limited to a single repository
* It receives a configurable set of roles, which allows clear documentation of steps taken. This is important for both penetration tests and covert Red Teams.

This is a feature we would gladly accept as a contribution!

### Bad Attack Feature Example

> Add a feature to secrets dump functionality so that it supports dumping all secrets from an organization. The feature works by pushing a workflow to every single repository the user has access to using a series of GraphQL mutations.

This is not a good feature because it is very destructive. A pentester or red teamer could accidentally force an organization to rotate _ALL_ of their actions secrets instead of just one repository.

If you want to test this scenario, then you must implement it in your own version of Gato-X, because it is too risky to include in the public version.