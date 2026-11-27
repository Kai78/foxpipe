# foxpipe

[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-backend-009688.svg)](https://fastapi.tiangolo.com/)
[![systemd](https://img.shields.io/badge/systemd-supported-4EAA25.svg)](https://systemd.io/)
[![GitHub last commit](https://img.shields.io/github/last-commit/Kai78/foxpipe)](https://github.com/Kai78/foxpipe/commits/main)
[![GitHub issues](https://img.shields.io/github/issues/Kai78/foxpipe)](https://github.com/Kai78/foxpipe/issues)
[![GitHub stars](https://img.shields.io/github/stars/Kai78/foxpipe?style=social)](https://github.com/Kai78/foxpipe/stargazers)

Triggering local pipelines from webhook. **[1](https://github.com/Kai78/foxpipe/)**

`foxpipe` is a self-hosted GitLab webhook receiver and local pipeline runner. It accepts GitLab events, clones repositories over SSH, resolves pipeline steps from YAML files inside the target repository, executes them asynchronously, and keeps a full audit trail in a built-in dashboard. **[1](https://github.com/Kai78/foxpipe/)** **[2](https://raw.githubusercontent.com/Kai78/foxpipe/main/pyproject.toml)** **[3](https://raw.githubusercontent.com/Kai78/foxpipe/main/app/routers/webhook.py)** **[4](https://raw.githubusercontent.com/Kai78/foxpipe/main/app/routers/dashboard.py)**

## Features

The project combines webhook ingestion, SSH-based repository access, asynchronous execution, audit persistence, and a web dashboard with optional LDAP integration and multiple database backends. **[3](https://raw.githubusercontent.com/Kai78/foxpipe/main/app/routers/webhook.py)** **[4](https://raw.githubusercontent.com/Kai78/foxpipe/main/app/routers/dashboard.py)** **[5](https://raw.githubusercontent.com/Kai78/foxpipe/main/app/database.py)** **[6](https://raw.githubusercontent.com/Kai78/foxpipe/main/app/worker.py)** **[7](https://raw.githubusercontent.com/Kai78/foxpipe/main/app/git_service.py)**

- GitLab webhook receiver with shared-secret validation
- SSH-based repository cloning
- Background pipeline execution with a bounded worker pool
- Pipeline step discovery from repository YAML files
- Dashboard for audit, reruns, logs, and configuration
- Optional LDAP / Active Directory authentication with local fallback
- SQLite, PostgreSQL, and MariaDB support for audit storage
- Health endpoint for monitoring
- Local webhook simulator for testing
- Linux `systemd` deployment included

## Quick Start

The repository contains a Python 3.11 backend, a Node.js entry/proxy layer, example configuration files, and deployment assets. For local development, Python 3.11, Node.js, Git, OpenSSH, and a Unix-like shell are the relevant prerequisites. **[1](https://github.com/Kai78/foxpipe/)** **[2](https://raw.githubusercontent.com/Kai78/foxpipe/main/pyproject.toml)** **[8](https://raw.githubusercontent.com/Kai78/foxpipe/main/package.json)** **[9](https://raw.githubusercontent.com/Kai78/foxpipe/main/config.example.yaml)**

### Requirements

- Python 3.11
- Node.js + npm
- Git
- OpenSSH client
- Linux or another Unix-like environment with `/bin/bash`

### Local development

```bash
git clone https://github.com/Kai78/foxpipe.git
cd foxpipe

python3.11 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

npm install

cp config.example.yaml config.yaml
cp .env.example .env

mkdir -p data logs keys
chmod 700 keys

npm run dev
```

This starts the Node.js entrypoint, launches the Python backend, waits for the health endpoint, and proxies incoming requests to FastAPI. **[8](https://raw.githubusercontent.com/Kai78/foxpipe/main/package.json)** **[10](https://raw.githubusercontent.com/Kai78/foxpipe/main/run.py)** **[3](https://raw.githubusercontent.com/Kai78/foxpipe/main/app/routers/webhook.py)**

## Architecture

`foxpipe` uses a two-layer runtime model: Python 3.11 / FastAPI for the application logic and a Node.js / Express bootstrap layer that starts the Python process, waits for health, and proxies requests. For Linux service deployments, the application runs directly from Python once the static assets are built. **[8](https://raw.githubusercontent.com/Kai78/foxpipe/main/package.json)** **[10](https://raw.githubusercontent.com/Kai78/foxpipe/main/run.py)** **[11](https://raw.githubusercontent.com/Kai78/foxpipe/main/deploy/README.md)**

```text
GitLab Webhook
      |
      v
+-------------+
|   foxpipe   |
|  webhook    |
+-------------+
      |
      v
+----------------------+
| SSH clone repository |
+----------------------+
      |
      v
+----------------------+
| Resolve pipeline YAML|
+----------------------+
      |
      v
+----------------------+
| Run steps in worker  |
+----------------------+
      |
      v
+----------------------+
| Store audit results  |
| + dashboard / API    |
+----------------------+
```

## Configuration

The main runtime settings live in `config.yaml` and are grouped into `server`, `webhook`, `ssh`, `pipeline`, `database`, `logging`, `auth`, and `branding`. The example configuration shows webhook filtering, SSH key paths, pipeline defaults, database settings, logging, LDAP options, and UI branding values. **[9](https://raw.githubusercontent.com/Kai78/foxpipe/main/config.example.yaml)**

### Example configuration areas

- `server`: host, port, app title, worker count
- `webhook`: secret token, allowed events, allowed repository hosts, simulator toggle
- `ssh`: key paths, host key checking, clone timeout, clone depth
- `pipeline`: workspace directory, YAML filenames, fallback scripts, timeout, worker count
- `database`: SQLite / PostgreSQL / MariaDB backend settings
- `logging`: file, level, rotation
- `auth`: local auth and optional LDAP
- `branding`: dashboard title, logo, subtitle

## Environment Variables

`foxpipe` supports environment-based overrides for secrets, bind settings, reverse proxy handling, and external database credentials. For a production service setup, the canonical environment file is `/etc/foxpipe/runner.env`. **[10](https://raw.githubusercontent.com/Kai78/foxpipe/main/run.py)** **[12](https://raw.githubusercontent.com/Kai78/foxpipe/main/deploy/runner.env.example)**

- `SESSION_SECRET_KEY`
- `GITLAB_WEBHOOK_SECRET`
- `LDAP_BIND_PASSWORD`
- `RUNNER_DB_PASSWORD`
- `PYTHON_HOST`
- `PYTHON_PORT`
- `FORWARDED_ALLOW_IPS`
- `RUNNER_CONFIG_PATH`

## Webhook Endpoint

GitLab can send events to `POST /webhook/gitlab` or `POST /api/webhook/gitlab`. The application also exposes `GET /api/health` for health checks. **[3](https://raw.githubusercontent.com/Kai78/foxpipe/main/app/routers/webhook.py)**

## Pipeline Configuration in Target Repositories

The runner searches cloned repositories for pipeline definitions such as `.pipeline.yml`, `.gitlab-pipeline.yml`, and `pipeline.yml`. The parser supports repository-defined YAML steps and falls back to default scripts from the central configuration if no repository-specific file is found. **[13](https://raw.githubusercontent.com/Kai78/foxpipe/main/app/pipeline_runner.py)** **[9](https://raw.githubusercontent.com/Kai78/foxpipe/main/config.example.yaml)**

### Minimal example

```yaml
steps:
  - name: "Inspect workspace"
    command: "pwd && ls -la"

  - name: "Run tests"
    command: "pytest -q"
```

## Dashboard

The dashboard covers login, first-run admin setup, execution history, execution detail views, reruns, configuration management, LDAP testing, database switching, SSH key generation, local user management, and log inspection. **[4](https://raw.githubusercontent.com/Kai78/foxpipe/main/app/routers/dashboard.py)**

## Run as a Linux `systemd` Service

The repository already includes a Linux `systemd` deployment path with an installation script, example environment file, service unit, and optional Nginx reverse proxy configuration. **[11](https://raw.githubusercontent.com/Kai78/foxpipe/main/deploy/README.md)** **[14](https://raw.githubusercontent.com/Kai78/foxpipe/main/deploy/install-systemd.sh)** **[12](https://raw.githubusercontent.com/Kai78/foxpipe/main/deploy/runner.env.example)** **[15](https://raw.githubusercontent.com/Kai78/foxpipe/main/deploy/foxpipe.service)**

### Option 1: Automated installation

```bash
sudo bash deploy/install-systemd.sh
```

The installation script runs idempotently and creates the `pipeline-runner` system user, installs the application under `/opt/foxpipe`, preserves runtime data on upgrades, creates a Python virtual environment, installs dependencies, generates `/etc/foxpipe/runner.env` if needed, installs the `foxpipe.service`, reloads `systemd`, enables the service, and starts or restarts it. **[11](https://raw.githubusercontent.com/Kai78/foxpipe/main/deploy/README.md)** **[14](https://raw.githubusercontent.com/Kai78/foxpipe/main/deploy/install-systemd.sh)**

### Option 2: Manual `systemd` setup

```bash
npm ci && npm run build

sudo useradd --system --home-dir /opt/foxpipe --shell /usr/sbin/nologin pipeline-runner
sudo mkdir -p /opt/foxpipe /etc/foxpipe
sudo cp -a . /opt/foxpipe/

sudo python3.11 -m venv /opt/foxpipe/.venv
sudo /opt/foxpipe/.venv/bin/pip install -r /opt/foxpipe/requirements.txt

sudo cp deploy/runner.env.example /etc/foxpipe/runner.env
sudo cp deploy/foxpipe.service /etc/systemd/system/foxpipe.service

sudo chown root:pipeline-runner /etc/foxpipe/runner.env
sudo chmod 0640 /etc/foxpipe/runner.env
sudo chown -R pipeline-runner:pipeline-runner /opt/foxpipe

sudo systemctl daemon-reload
sudo systemctl enable --now foxpipe.service
```

### Service management

```bash
sudo systemctl status foxpipe
sudo journalctl -u foxpipe -f
sudo systemctl restart foxpipe
curl -s http://127.0.0.1:8090/api/health
```

### Runtime paths

- Install dir: `/opt/foxpipe`
- Env file: `/etc/foxpipe/runner.env`
- Service name: `foxpipe`
- System user: `pipeline-runner`

### Reverse proxy

If you want HTTPS in front of the service, use the provided Nginx example at `deploy/nginx.foxpipe.conf.example` and keep the Python service bound to `127.0.0.1`. **[11](https://raw.githubusercontent.com/Kai78/foxpipe/main/deploy/README.md)**

## Storage Backends

The audit repository supports SQLite, PostgreSQL, and MariaDB / MySQL backends. SQLite is suitable for smaller standalone setups, while PostgreSQL is typically the safer default for multi-user or longer-lived installations. **[5](https://raw.githubusercontent.com/Kai78/foxpipe/main/app/database.py)**

## API Overview

The main API surface includes webhook ingestion, local simulation, execution listing, execution detail lookup, reruns, and health reporting. **[3](https://raw.githubusercontent.com/Kai78/foxpipe/main/app/routers/webhook.py)**

- `POST /webhook/gitlab`
- `POST /api/webhook/gitlab`
- `POST /api/webhook/simulate`
- `GET /api/executions`
- `GET /api/executions/{execution_id}`
- `POST /api/executions/{execution_id}/rerun`
- `GET /api/health`

## Project Structure

The repository currently contains application code, deployment assets, tests, and both Python and Node project metadata. **[1](https://github.com/Kai78/foxpipe/)** **[2](https://raw.githubusercontent.com/Kai78/foxpipe/main/pyproject.toml)** **[8](https://raw.githubusercontent.com/Kai78/foxpipe/main/package.json)**

```text
.
├── app/
├── deploy/
├── src/
├── tests/
├── .env.example
├── config.example.yaml
├── config.yaml
├── package.json
├── pyproject.toml
├── requirements.txt
├── run.py
├── server.ts
└── vite.config.ts
```

## Security Notes

Before using `foxpipe` in production, review the webhook secret, SSH private key permissions, allowed GitLab hosts, host key verification mode, LDAP configuration, reverse proxy / TLS setup, database credential handling, and file permissions for `config.yaml`, `runner.env`, and `keys/`. **[7](https://raw.githubusercontent.com/Kai78/foxpipe/main/app/git_service.py)** **[9](https://raw.githubusercontent.com/Kai78/foxpipe/main/config.example.yaml)** **[12](https://raw.githubusercontent.com/Kai78/foxpipe/main/deploy/runner.env.example)** **[15](https://raw.githubusercontent.com/Kai78/foxpipe/main/deploy/foxpipe.service)**

## Typical Use Cases

`foxpipe` fits lightweight internal automation after GitLab pushes, local execution of repository-defined validation jobs, webhook-driven operations tooling, and auditable replacement of ad-hoc shell automation. **[3](https://raw.githubusercontent.com/Kai78/foxpipe/main/app/routers/webhook.py)** **[6](https://raw.githubusercontent.com/Kai78/foxpipe/main/app/worker.py)**

## Contributing

Contributions are welcome. If you plan larger changes, open an issue first to discuss architecture, security, and operational impact.

## License

Add the correct license information for this repository here.
