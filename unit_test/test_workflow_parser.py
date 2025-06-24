from gatox.models.workflow import Workflow

TEST_WF = """
name: 'Test WF'

on:
  pull_request_target:
  workflow_dispatch:

jobs:
  test:
    runs-on: ['self-hosted']
    steps:

    - name: Execution
      run: |
          echo "Hello World and bad stuff!"
"""

TEST_WF2 = """
name: 'Test WF2'

on:
  pull_request_target:

jobs:
  test:
    runs-on: 'ubuntu-latest'
    steps:
    - name: Execution
      uses: actions/checkout@v4
      with:
        ref: ${{ github.event.pull_request.head.ref }}
"""

TEST_WF3 = """
name: Update Snapshots
on:
  issue_comment:
    types: [created]
jobs:
  updatesnapshots:
    if: ${{ github.event.issue.pull_request && github.event.comment.body == '/update-snapshots'}}
    timeout-minutes: 20
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0
          token: ${{ secrets.GITHUB_TOKEN }}
      - name: Get SHA and branch name
        id: get-branch-and-sha
        run: |
          sha_and_branch=$(\
            curl \
              -H 'authorization: Bearer ${{ secrets.GITHUB_TOKEN }}' \
              https://api.github.com/repos/${{ github.repository }}/pulls/${{ github.event.issue.number }} \
            | jq -r '.head.sha," ",.head.ref');
          echo "sha=$(echo $sha_and_branch | cut -d " " -f 1)" >> $GITHUB_OUTPUT
          echo "branch=$(echo $sha_and_branch | cut -d " " -f 2)" >> $GITHUB_OUTPUT
      - name: Fetch Branch
        run: git fetch
      - name: Checkout Branch
        run: git checkout ${{ steps.get-branch-and-sha.outputs.branch }}
      - uses: actions/setup-node@v3
        with:
          node-version: '19'
      - name: Install dependencies
        run: yarn
      - name: Install Playwright browsers
        run: npx playwright install --with-deps chromium
      - name: Update snapshots
        env:
          VITE_TENDERLY_ACCESS_KEY: ${{ secrets.VITE_TENDERLY_ACCESS_KEY }}
          VITE_CHAIN_RPC_URL: ${{ secrets.VITE_CHAIN_RPC_URL }}
          CI: true
        run: npx playwright test --update-snapshots --reporter=list
      - uses: stefanzweifel/git-auto-commit-action@v4
        with:
          commit_message: '[CI] Update Snapshots'
"""

TEST_WF4 = """
name: Benchmarks
on:
  issue_comment:
    types: [created]
jobs:
  check-permission:
    if: github.event.issue.pull_request && startsWith(github.event.comment.body, '/bench')
    runs-on: ubuntu-latest
    steps:
    - name: Check permission
      uses: actions/github-script@v6
      with:
        result-encoding: string
        script: |
          const response = await github.rest.repos.getCollaboratorPermissionLevel({
            owner: context.repo.owner,
            repo: context.repo.repo,
            username: context.actor
          });

          const actorPermissionLevel = response.data.permission;
          console.log(actorPermissionLevel);

          // <- lower higher ->
          // ["none", "read", "write", "admin"]
          if (!(actorPermissionLevel == "admin" || actorPermissionLevel == "write")) {
            core.setFailed("Permission denied.");
          }

  benchmarks:
    # run only when PR comments start with '/bench'.
    if: github.event.issue.pull_request && startsWith(github.event.comment.body, '/bench')
    needs: check-permission
    runs-on: [self-hosted, Linux, X64]
    steps:
    - name: Validate and set inputs
      id: bench-input
      uses: actions/github-script@v6
      with:
        result-encoding: string
        script: |
          const command = `${{ github.event.comment.body }}`.split(" ");
          console.log(command);

          // command should be '/bench chain_name pallets'
          if (command.length != 3) {
            core.setFailed("Invalid input. It should be '/bench [chain_name] [pallets]'");
          }

          core.setOutput("chain", command[1]);
          core.setOutput("pallets", command[2]);

    - name: Free disk space
      run: |
        sudo rm -rf /usr/share/dotnet
        sudo rm -rf /usr/local/lib/android
        sudo rm -rf /opt/ghc
        sudo rm -rf "/usr/local/share/boost"
        sudo rm -rf "$AGENT_TOOLSDIRECTORY"
        df -h

    - name: Get branch and sha
      id: get_branch_sha
      uses: actions/github-script@v6
      with:
        github-token: ${{secrets.GITHUB_TOKEN}}
        result-encoding: string
        script: |
          const pull_request = await github.rest.pulls.get({
            owner: context.repo.owner,
            repo: context.repo.repo,
            pull_number: context.issue.number
          })

          core.setOutput("branch", pull_request.data.head.ref)
          core.setOutput("sha", pull_request.data.head.sha)

    - name: Post starting comment
      uses: actions/github-script@v6
      env:
        MESSAGE: |
          Benchmarks job is scheduled at ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}.
          Please wait for a while.
          Branch: ${{ steps.get_branch_sha.outputs.branch }}
          SHA: ${{ steps.get_branch_sha.outputs.sha }}
      with:
        github-token: ${{secrets.GITHUB_TOKEN}}
        result-encoding: string
        script: |
          github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: process.env.MESSAGE
          })

    - name: Checkout the source code
      uses: actions/checkout@v3
      with:
        ref: ${{ steps.get_branch_sha.outputs.sha }}
        submodules: true

    - name: Install deps
      run: sudo apt -y install protobuf-compiler

    - name: Install & display rust toolchain
      run: rustup show

    - name: Check targets are installed correctly
      run: rustup target list --installed

    - name: Execute benchmarking
      run: |
        mkdir -p ./benchmark-results
        chmod +x ./scripts/run_benchmarks.sh
        ./scripts/run_benchmarks.sh -o ./benchmark-results -c ${{ steps.bench-input.outputs.chain }} -p ${{ steps.bench-input.outputs.pallets }}
"""

TEST_WF5 = """
name: 'Test WF5'

on:
  pull_request_target:

jobs:
"""


TEST_WF6 = """
name: 'Test WF6'

on:
  pull_request_target:

jobs:
  steps:
    - name: Execution
      uses: actions/checkout@v4
"""

TEST_WF7 = """
name: build

on:
  push:
    branches: [ 'master' ]
  pull_request:
    branches: [ 'master' ]

concurrency:
  group: ${{ github.ref }}-build
  cancel-in-progress: true

jobs:
  build:
    strategy:
      matrix:
        profile: [ 'jdk17', 'jdk17-aarch64' ]
        include:
          - jdk_version: '17'
          - profile: 'jdk17'
            runs_on: ubuntu-latest
          - profile: 'jdk17-aarch64'
            runs_on: [ linux, ARM64 ]
      fail-fast: false

    runs-on: ${{ matrix.runs_on }}

    steps:
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v2
        with:
          driver: docker

"""

DEPENDABOT_FALSE_WF = """
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "daily"
"""


def test_parse_workflow_db():
    workflow = Workflow("unit_test", DEPENDABOT_FALSE_WF, "main.yml")

    assert not workflow.isInvalid()


# def test_workflow_write():

#     workflow = Workflow("unit_test", TEST_WF, "main.yml")
#     parser = WorkflowParser(workflow)

#     curr_path = pathlib.Path(__file__).parent.resolve()
#     curr_path = pathlib.Path(__file__).parent.resolve()
#     test_repo_path = os.path.join(curr_path, "files/")

#     with patch("builtins.open", mock_open(read_data="")) as mock_file:
#         parser.output(test_repo_path)

#         mock_file().write.assert_called_once_with(parser.raw_yaml)


# def test_check_injection_no_vulnerable_triggers():
#     workflow = Workflow("unit_test", TEST_WF, "main.yml")
#     parser = WorkflowParser(workflow)

#     with patch.object(parser, "get_vulnerable_triggers", return_value=[]):
#         result = parser.check_injection()
#         assert result == {}


# def test_check_injection_no_job_contents():
#     workflow = Workflow("unit_test", TEST_WF5, "main.yml")
#     parser = WorkflowParser(workflow)

#     result = parser.check_injection()
#     assert result == {}


# def test_check_injection_no_step_contents():
#     workflow = Workflow("unit_test", TEST_WF6, "main.yml")
#     parser = WorkflowParser(workflow)

#     result = parser.check_injection()
#     assert result == {}


# def test_check_injection_comment():
#     workflow = Workflow("unit_test", TEST_WF3, "main.yml")
#     parser = WorkflowParser(workflow)

#     result = parser.check_injection()
#     assert "updatesnapshots" in result


# def test_check_injection_no_tokens():
#     workflow = Workflow("unit_test", TEST_WF, "main.yml")
#     parser = WorkflowParser(workflow)

#     result = parser.check_injection()
#     assert result == {}


# def test_check_pwn_request():
#     workflow = Workflow("unit_test", TEST_WF4, "benchmark.yml")
#     parser = WorkflowParser(workflow)

#     result = parser.check_pwn_request()
#     assert result["candidates"]


# def test_check_sh_runnner():
#     workflow = Workflow("unit_test", TEST_WF7, "build.yml")
#     parser = WorkflowParser(workflow)

#     result = parser.self_hosted()
#     assert len(result) > 0
