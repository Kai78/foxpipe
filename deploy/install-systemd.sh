#!/usr/bin/env bash
set -euo pipefail

# Idempotent installer for running GitLab SSH Pipeline Runner as a Linux systemd service.
# Usage: sudo bash deploy/install-systemd.sh

SERVICE_NAME="gitlab-pipeline-runner"
SERVICE_USER="pipeline-runner"
SERVICE_GROUP="pipeline-runner"
INSTALL_DIR="/opt/gitlab-pipeline-runner"
ENV_DIR="/etc/gitlab-pipeline-runner"
ENV_FILE="${ENV_DIR}/runner.env"
UNIT_DEST="/etc/systemd/system/${SERVICE_NAME}.service"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Error: Please run this installer as root (e.g. sudo bash deploy/install-systemd.sh)." >&2
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "Error: systemctl not found. This script requires a systemd-based Linux distribution." >&2
  exit 1
fi

if ! command -v git >/dev/null 2>&1 || ! command -v ssh >/dev/null 2>&1; then
  echo "Error: Both 'git' and 'ssh' (openssh-client) must be installed." >&2
  exit 1
fi

PYTHON_BIN=""
for candidate in python3.11 python3.12 python3; do
  if command -v "${candidate}" >/dev/null 2>&1; then
    if "${candidate}" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
      PYTHON_BIN="$(command -v "${candidate}")"
      break
    fi
  fi
done

if [[ -z "${PYTHON_BIN}" ]]; then
  echo "Error: Python 3.11 or newer is required." >&2
  exit 1
fi

echo "==> Using Python interpreter: ${PYTHON_BIN}"

# Build Tailwind CSS bundle if npm is available and styles.css is missing or stale
if [[ ! -f "${SOURCE_DIR}/app/static/css/styles.css" ]]; then
  if command -v npm >/dev/null 2>&1 && [[ -f "${SOURCE_DIR}/package.json" ]]; then
    echo "==> Building Tailwind CSS bundle..."
    (cd "${SOURCE_DIR}" && npm ci --no-audit --no-fund && npm run build)
  else
    echo "Warning: app/static/css/styles.css not found and npm is unavailable. Ensure static CSS is built before starting." >&2
  fi
fi

# Create dedicated unprivileged system user and group
if ! getent group "${SERVICE_GROUP}" >/dev/null 2>&1; then
  echo "==> Creating system group '${SERVICE_GROUP}'..."
  groupadd --system "${SERVICE_GROUP}"
fi

if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
  echo "==> Creating system user '${SERVICE_USER}'..."
  useradd --system \
    --gid "${SERVICE_GROUP}" \
    --home-dir "${INSTALL_DIR}" \
    --shell /usr/sbin/nologin \
    --comment "GitLab SSH Pipeline Runner service account" \
    "${SERVICE_USER}"
fi

echo "==> Syncing application files to ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}"

if command -v rsync >/dev/null 2>&1; then
  rsync -a --delete \
    --exclude '.git' \
    --exclude '.venv' \
    --exclude 'node_modules' \
    --exclude 'dist' \
    --exclude 'data' \
    --exclude 'logs' \
    --exclude 'keys' \
    --exclude 'config.yaml' \
    --exclude 'app/static/branding' \
    --exclude '__pycache__' \
    --exclude '.pytest_cache' \
    "${SOURCE_DIR}/" "${INSTALL_DIR}/"
else
  cp -a "${SOURCE_DIR}/app" "${INSTALL_DIR}/"
  cp -a "${SOURCE_DIR}/run.py" "${SOURCE_DIR}/requirements.txt" "${SOURCE_DIR}/pyproject.toml" "${SOURCE_DIR}/config.example.yaml" "${INSTALL_DIR}/"
fi

# Ensure runtime directories exist without overwriting existing user data
mkdir -p \
  "${INSTALL_DIR}/data" \
  "${INSTALL_DIR}/logs" \
  "${INSTALL_DIR}/keys" \
  "${INSTALL_DIR}/app/static/branding" \
  "${INSTALL_DIR}/app/static/css"

if [[ ! -f "${INSTALL_DIR}/config.yaml" ]]; then
  if [[ -f "${SOURCE_DIR}/config.yaml" ]]; then
    cp "${SOURCE_DIR}/config.yaml" "${INSTALL_DIR}/config.yaml"
  else
    cp "${INSTALL_DIR}/config.example.yaml" "${INSTALL_DIR}/config.yaml"
  fi
fi

# Create or update Python 3.11 virtual environment
if [[ ! -x "${INSTALL_DIR}/.venv/bin/python" ]]; then
  echo "==> Creating Python virtual environment at ${INSTALL_DIR}/.venv..."
  "${PYTHON_BIN}" -m venv "${INSTALL_DIR}/.venv"
fi

echo "==> Installing Python dependencies..."
"${INSTALL_DIR}/.venv/bin/pip" install --upgrade pip >/dev/null
"${INSTALL_DIR}/.venv/bin/pip" install --no-cache-dir -r "${INSTALL_DIR}/requirements.txt"

# Provision persistent environment file with generated session secret if absent
mkdir -p "${ENV_DIR}"
if [[ ! -f "${ENV_FILE}" ]]; then
  echo "==> Creating ${ENV_FILE} with generated SESSION_SECRET_KEY..."
  GENERATED_SECRET="$("${INSTALL_DIR}/.venv/bin/python" -c 'import secrets; print(secrets.token_hex(32))')"
  cat > "${ENV_FILE}" <<EOF
SESSION_SECRET_KEY="${GENERATED_SECRET}"
PYTHON_HOST="0.0.0.0"
PYTHON_PORT="8090"
FORWARDED_ALLOW_IPS="127.0.0.1"
# GITLAB_WEBHOOK_SECRET=""
# LDAP_BIND_PASSWORD=""
EOF
fi
chown root:"${SERVICE_GROUP}" "${ENV_FILE}"
chmod 0640 "${ENV_FILE}"

# Apply strict ownership and permissions
chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${INSTALL_DIR}"
chmod 0750 "${INSTALL_DIR}/data" "${INSTALL_DIR}/logs" "${INSTALL_DIR}/app/static/branding"
chmod 0700 "${INSTALL_DIR}/keys"
chmod 0640 "${INSTALL_DIR}/config.yaml"

echo "==> Installing systemd unit ${UNIT_DEST}..."
install -m 0644 "${INSTALL_DIR}/deploy/gitlab-pipeline-runner.service" "${UNIT_DEST}"

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}.service"
systemctl restart "${SERVICE_NAME}.service"

echo ""
echo "==> ${SERVICE_NAME} installed and started."
echo "    Check status : systemctl status ${SERVICE_NAME}"
echo "    Follow logs  : journalctl -u ${SERVICE_NAME} -f"
echo "    Config YAML  : ${INSTALL_DIR}/config.yaml"
echo "    Secrets Env  : ${ENV_FILE}"
