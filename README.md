# IP Fabric ChatOps

An IP Fabric ChatOps plugin for [Nautobot](https://github.com/nautobot/nautobot).

This plugin uses the [Nautobot ChatOps](https://github.com/nautobot/nautobot-plugin-chatops/) base framework. It provides the ability to query data from IP Fabric using a supported chat platform (currently Slack, Webex Teams, MS Teams, and Mattermost).

## Screenshots

![image](https://user-images.githubusercontent.com/29293048/138304572-46d2fa11-8dd2-4722-9ab0-450e20a657a5.png)

![ipfabric-2](https://user-images.githubusercontent.com/29293048/131741040-58e9d6a1-e61d-4c60-a427-9f001934915f.png)

![ipfabric-3](https://user-images.githubusercontent.com/29293048/131741046-4e01fbbb-4a82-4233-a8a1-9da4f31e2d93.png)

![ipfabric-4](https://user-images.githubusercontent.com/29293048/131741054-9ae97b71-70f7-48ff-b7b9-15b70f95b7a8.png)

![ipfabric-5](https://user-images.githubusercontent.com/29293048/131741063-a601fb0a-570c-466a-a078-15b2b6037ab8.png)

![ipfabric-6](https://user-images.githubusercontent.com/29293048/131741068-5e5f1c63-65c7-4c3a-9763-dff06f81666f.png)

![ipfabric-7](https://user-images.githubusercontent.com/29293048/131741075-6a52fef9-c9be-4686-950b-994566c6aec4.png)

## Usage

Add a slash command to your chat platform called `/ipfabric`.
See the [nautobot-chatops installation guide](https://github.com/nautobot/nautobot-plugin-chatops/blob/develop/docs/chat_setup/chat_setup.md) for instructions on adding a slash command to your chat channel.

The following commands are available:

- `/ipfabric set-snapshot [snapshot]`: Set snapshot as reference for commands.
- `/ipfabric get-snapshot`: Get snapshot as reference for commands.
- `/ipfabric device-list`: Get the device list.
- `/ipfabric interfaces [device] [metric]`: Get interface metrics for a device.
- `/ipfabric end-to-end-path [src-ip] [dst-ip] [src-port] [dst-port] [protocol]`: Execute end-to-end path simulation between source and target IP address.
- `/ipfabric routing [device] [protocol] [filter-opt]`: Get routing information for a device.
- `/ipfabric wireless [option] [ssid]`: Get wireless information by client or ssid.

IP Fabric uses a concept of snapshots which can include different devices and data. The plugin supports querying specific snapshots via the `/ipfabric set-snapshot` command. The snapshot is set per user and cached for all future commands. If a snapshot is not set, the commands will default to `$last` unless a specific snapshot id is required.

## Installation

The extension is available as a Python package in PyPI and can be installed with pip

```shell
pip install nautobot-chatops-ipfabric
```

> The plugin is compatible with Nautobot 1.0.0 and higher

To ensure the IP Fabric ChatOps plugin is automatically re-installed during future upgrades, create a file named `local_requirements.txt` (if not already existing) in the Nautobot root directory (alongside `requirements.txt`) and list the `nautobot-chatops-ipfabric` package:

```no-highlight
# echo nautobot-chatops-ipfabric >> local_requirements.txt
```

Once installed, the plugin needs to be enabled in your `nautobot_configuration.py`

```python
# In your nautobot_configuration.py
PLUGINS = ["nautobot_chatops", "nautobot_chatops_ipfabric"]

PLUGINS_CONFIG = {
  "nautobot_chatops": {
    # ADD SLACK/MS-TEAMS/WEBEX-TEAMS/MATTERMOST SETTINGS HERE
  }
  "nautobot_chatops_ipfabric": {
      "IPFABRIC_API_TOKEN": os.environ.get("IPFABRIC_API_TOKEN"),
      "IPFABRIC_HOST": os.environ.get("IPFABRIC_HOST"),
  },
}
```

The plugin behavior can be controlled with the following list of settings

- `IPFABRIC_API_TOKEN`: Token for accessing IP Fabric API
- `IPFABRIC_HOST`: URL of IP Fabric instance

## Development

The development environment supports a self-contained environment for developing nautobot chatops commands.

Build of the environment requires `python3-invoke`.  For development purposes, install `poetry` and use it to manage the required packages.

```shell
poetry install        # first time use
poetry shell
```

You can start the deveopment containers locally with an `invoke build` and `invoke start` after copying `creds.env` locally.

```shell
cp development/creds.env.example development/creds.env
invoke build
invoke start
```

You should be able to access nautobot at http://0.0.0.0:8080

## Contributing

Pull requests are welcomed and automatically built and tested against multiple version of Python and multiple version of Nautobot through TravisCI.

The project is packaged with a light development environment based on `docker-compose` to help with the local development of the project and to run the tests within TravisCI.

The project is following Network to Code software development guideline and is leveraging:

- Black, Pylint, Bandit and pydocstyle for Python linting and formatting.
- Django unit test to ensure the plugin is working properly.

### Development Environment

The development environment can be used in 2 ways. First, with a local poetry environment if you wish to develop outside of Docker. Second, inside of a docker container.

#### Invoke tasks

The [PyInvoke](http://www.pyinvoke.org/) library is used to provide some helper commands based on the environment.  There are a few configuration parameters which can be passed to PyInvoke to override the default configuration:

- `nautobot_ver`: the version of Nautobot to use as a base for any built docker containers (default: develop-latest)
- `project_name`: the default docker compose project name (default: ipfabric)
- `python_ver`: the version of Python to use as a base for any built docker containers (default: 3.6)
- `local`: a boolean flag indicating if invoke tasks should be run on the host or inside the docker containers (default: False, commands will be run in docker containers)
- `compose_dir`: the full path to a directory containing the project compose files
- `compose_files`: a list of compose files applied in order (see [Multiple Compose files](https://docs.docker.com/compose/extends/#multiple-compose-files) for more information)

Using PyInvoke these configuration options can be overridden using [several methods](http://docs.pyinvoke.org/en/stable/concepts/configuration.html).  Perhaps the simplest is simply setting an environment variable `INVOKE_IPFABRIC_VARIABLE_NAME` where `VARIABLE_NAME` is the variable you are trying to override.  The only exception is `compose_files`, because it is a list it must be overridden in a yaml file.  There is an example `invoke.yml` in this directory which can be used as a starting point.

#### Local Poetry Development Environment

1. Copy `development/creds.example.env` to `development/creds.env` (This file will be ignored by git and docker)
2. Uncomment the `POSTGRES_HOST`, `REDIS_HOST`, and `NAUTOBOT_ROOT` variables in `development/creds.env`
3. Create an invoke.yml with the following contents at the root of the repo:

```shell
---
ipfabric:
  local: true
  compose_files:
    - "docker-compose.requirements.yml"
```

4. Run the following commands:

```shell
poetry shell
poetry install
export $(cat development/dev.env | xargs)
export $(cat development/creds.env | xargs)
```

5. You can now run nautobot-server commands as you would from the [Nautobot documentation](https://nautobot.readthedocs.io/en/latest/) for example to start the development server:

```shell
nautobot-server runserver 0.0.0.0:8080 --insecure
```

Nautobot server can now be accessed at [http://localhost:8080](http://localhost:8080).

#### Docker Development Environment

This project is managed by [Python Poetry](https://python-poetry.org/) and has a few requirements to setup your development environment:

1. Install Poetry, see the [Poetry Documentation](https://python-poetry.org/docs/#installation) for your operating system.
2. Install Docker, see the [Docker documentation](https://docs.docker.com/get-docker/) for your operating system.

Once you have Poetry and Docker installed you can run the following commands to install all other development dependencies in an isolated python virtual environment:

```shell
poetry shell
poetry install
invoke start
```

Nautobot server can now be accessed at [http://localhost:8080](http://localhost:8080).

### CLI Helper Commands

The project is coming with a CLI helper based on [invoke](http://www.pyinvoke.org/) to help setup the development environment. The commands are listed below in 3 categories `dev environment`, `utility` and `testing`.

Each command can be executed with `invoke <command>`. Environment variables `INVOKE_IPFABRIC_PYTHON_VER` and `INVOKE_IPFABRIC_NAUTOBOT_VER` may be specified to override the default versions. Each command also has its own help `invoke <command> --help`

#### Docker dev environment

```no-highlight
  build            Build all docker images.
  debug            Start Nautobot and its dependencies in debug mode.
  destroy          Destroy all containers and volumes.
  restart          Restart Nautobot and its dependencies.
  start            Start Nautobot and its dependencies in detached mode.
  stop             Stop Nautobot and its dependencies.
```

#### Utility

```no-highlight
  cli              Launch a bash shell inside the running Nautobot container.
  create-user      Create a new user in django (default: admin), will prompt for password.
  makemigrations   Run Make Migration in Django.
  nbshell          Launch a nbshell session.
```

#### Testing

```no-highlight
  bandit           Run bandit to validate basic static code security analysis.
  black            Run black to check that Python files adhere to its style standards.
  flake8           This will run flake8 for the specified name and Python version.
  pydocstyle       Run pydocstyle to validate docstring formatting adheres to NTC defined standards.
  pylint           Run pylint code analysis.
  tests            Run all tests for this plugin.
  unittest         Run Django unit tests for the plugin.
```

## Questions

For any questions or comments, please check the [FAQ](FAQ.md) first and feel free to swing by the [Network to Code slack channel](https://networktocode.slack.com/) (channel #networktocode).
Sign up [here](http://slack.networktocode.com/)
