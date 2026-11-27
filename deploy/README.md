# Running as a Linux `systemd` Service

On Linux, the entire application (webhook ingestion, SSH GitLab cloner, background pipeline worker, SQLite audit store, and Jinja2 + Tailwind CSS dashboard) runs directly from Python 3.11 (`run.py` -> `app.main:app`) without needing Node.js at runtime once `app/static/css/styles.css` is built.

## Option 1: Automated Installation (Recommended)

From the project root on your Linux server (requires Python >= 3.11, `git`, `openssh-client`, and `systemd`):

```bash
sudo bash deploy/install-systemd.sh
```

This script idempotently performs the following steps:
1. Creates a dedicated unprivileged system account (`pipeline-runner`).
2. Copies the application to `/opt/gitlab-pipeline-runner` (preserving existing `config.yaml`, `data/`, `logs/`, `keys/`, and uploaded branding logos on upgrades).
3. Sets up `/opt/gitlab-pipeline-runner/.venv` and installs `requirements.txt`.
4. Generates a persistent `SESSION_SECRET_KEY` in `/etc/gitlab-pipeline-runner/runner.env` (`0640`).
5. Installs `/etc/systemd/system/gitlab-pipeline-runner.service`, runs `systemctl daemon-reload`, enables the service at boot, and starts it.

## Option 2: Manual `systemd` Setup

1. Build the Tailwind CSS bundle once (if `app/static/css/styles.css` is not already present):
   ```bash
   npm ci && npm run build
   ```
2. Create the system user and install directory:
   ```bash
   sudo useradd --system --home-dir /opt/gitlab-pipeline-runner --shell /usr/sbin/nologin pipeline-runner
   sudo mkdir -p /opt/gitlab-pipeline-runner /etc/gitlab-pipeline-runner
   sudo cp -a . /opt/gitlab-pipeline-runner/
   sudo python3.11 -m venv /opt/gitlab-pipeline-runner/.venv
   sudo /opt/gitlab-pipeline-runner/.venv/bin/pip install -r /opt/gitlab-pipeline-runner/requirements.txt
   ```
3. Configure secrets & environment overrides:
   ```bash
   sudo cp deploy/runner.env.example /etc/gitlab-pipeline-runner/runner.env
   # Edit SESSION_SECRET_KEY (e.g. openssl rand -hex 32), PYTHON_HOST, PYTHON_PORT, and optional LDAP/webhook secrets
   sudo chown root:pipeline-runner /etc/gitlab-pipeline-runner/runner.env
   sudo chmod 0640 /etc/gitlab-pipeline-runner/runner.env
   sudo chown -R pipeline-runner:pipeline-runner /opt/gitlab-pipeline-runner
   ```
4. Install and start the unit:
   ```bash
   sudo cp deploy/gitlab-pipeline-runner.service /etc/systemd/system/gitlab-pipeline-runner.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now gitlab-pipeline-runner.service
   ```

## Managing & Verifying the Service

```bash
# Check service status
sudo systemctl status gitlab-pipeline-runner

# Stream live systemd journal logs
sudo journalctl -u gitlab-pipeline-runner -f

# Restart after editing /etc/gitlab-pipeline-runner/runner.env or config.yaml manually
sudo systemctl restart gitlab-pipeline-runner

# Health check
curl -s http://127.0.0.1:8090/api/health
```

## Optional HTTPS Reverse Proxy (Nginx)

If you want to expose the dashboard and GitLab webhook endpoint over HTTPS (`443`), set `PYTHON_HOST="127.0.0.1"` in `/etc/gitlab-pipeline-runner/runner.env` and adapt `deploy/nginx.gitlab-pipeline-runner.conf.example`.
