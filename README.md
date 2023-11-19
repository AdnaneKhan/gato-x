![Supported Python versions](https://img.shields.io/badge/python-3.7+-blue.svg)

# Gato (Github Attack TOolkit)

<p align="center">
  <img src="https://user-images.githubusercontent.com/2006441/212176664-2ffb61ec-1b40-49cb-8cb2-7a9127a51f3b.PNG" alt="gato"/>
</p>


Gato, or GitHub Attack Toolkit, is an enumeration and attack tool that allows both 
blue teamers and offensive security practitioners to evaluate the blast radius 
of a compromised personal access token within a GitHub organization.

The tool also allows searching for and thoroughly enumerating public
repositories that utilize self-hosted runners. GitHub recommends that
self-hosted runners only be utilized for private repositories, however, there
are thousands of organizations that utilize self-hosted runners.

## Version 1.5 Released

Gato version 1.5 was released on June 27th, 2023!

#### New Features

* Secrets Enumeration
* Secrets Exfiltration
* API-only Enumeration
* JSON Output
* Improved Code Search
* GitHub Enterprise Server Support
* PAT Validation Only Mode
* Quality of life and UX improvements

## Who is it for?

- Security engineers who want to understand the level of access a compromised
  classic PAT could provide an attacker
- Blue teams that want to build detections for self-hosted runner attacks
- Red Teamers
- Bug bounty hunters who want to try and prove RCE on organizations that are
  utilizing self-hosted runners

## Features

* GitHub Classic PAT Privilege Enumeration
* GitHub Code Search API-based enumeration
* GitHub Action Run Log Parsing to identify Self-Hosted Runners
* Bulk Repo Sparse Clone Features
* GitHub Action Workflow Parsing
* Automated Command Execution Fork PR Creation
* Automated Command Execution Workflow Creation
* Automated workflow secrets exfiltration
* SOCKS5 Proxy Support
* HTTPS Proxy Support

## Getting Started

### Installation

Gato supports OS X and Linux with at least **Python 3.7**.

In order to install the tool, simply clone the repository and use `pip install`. We 
recommend performing this within a virtual environment.

```
git clone https://github.com/praetorian-inc/gato
cd gato
python3 -m venv venv
source venv/bin/activate
pip install .
```

Gato also requires that `git` version `2.27` or above is installed and on the 
system's PATH. In order to run the fork PR attack module, `sed` must also be 
installed and present on the system's path.

#### Dev Branch

We maintain a development branch that contains newer Gato features that are not yet added to main.
There is an increased chance you will run into bugs; however, we still run our integration test
suite on the `dev` branch, so there should not be any _blatant_ bugs.

If you want to use the `dev` branch, just check it out prior to running pip install - that's it!

If you do run into any for your specific use case, by all means open an issue!


### Usage

After installing the tool, it can be launched by running `gato` or
`praetorian-gato`.

We recommend viewing the parameters for the base tool using `gato -h`, and the 
parameters for each of the tool's modules by running the following:

* `gato search -h`
* `gato enum -h`
* `gato attack -h`

The tool requires a GitHub classic PAT in order to function. To create one, log
in to GitHub and go to [GitHub Developer
Settings](https://github.com/settings/tokens) 
and select `Generate New Token` and then `Generate new token (classic)`.

After creating this token set the `GH_TOKEN` environment variable within your 
shell by running `export GH_TOKEN=<YOUR_CREATED_TOKEN>`. Alternatively, store 
the token within a secure password manager and enter it when the application 
prompts you.

For troubleshooting and additional details, such as installing in developer 
mode or running unit tests, please see the [wiki](https://github.com/praetorian-inc/gato/wiki).

## Documentation

Please see the [wiki](https://github.com/praetorian-inc/gato/wiki).
 for detailed documentation, as well as [OpSec](https://github.com/praetorian-inc/gato/wiki/opsec) considerations 
for the tool's various modules!

## Bugs

If you believe you have identified a bug within the software, please open an 
issue containing the tool's output, along with the actions you were trying to
conduct.

If you are unsure if the behavior is a bug, use the discussions section instead!


## Contributing

Contributions are welcome! Please [review](https://github.com/praetorian-inc/gato/wiki/Project-Design) our design methodology and coding 
standards before working on a new feature!

Additionally, if you are proposing significant changes to the tool, please open 
an issue [open an issue](https://github.com/praetorian-inc/gato/issues/new) to 
start a conversation about the motivation for the changes.

## License

Gato is licensed under the [Apache License, Version 2.0](LICENSE).

```
Copyright 2023 Praetorian Security, Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
