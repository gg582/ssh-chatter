#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: sudo scripts/install_modbot_service.sh [options]

Options:
  --install-dir DIR     Directory to install the moderator bot (default: /opt/chatter-modbot)
  --service-user USER   System user to run the service (default: chatter-modbot)
  --service-name NAME   Name of the systemd service (default: chatter-modbot)
  --skip-start          Install without enabling/starting the service automatically
  -h, --help            Show this help message
USAGE
}

INSTALL_DIR="/opt/chatter-modbot"
SERVICE_USER="chatter-modbot"
SERVICE_NAME="chatter-modbot"
SKIP_START=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --service-user)
            SERVICE_USER="$2"
            shift 2
            ;;
        --service-name)
            SERVICE_NAME="$2"
            shift 2
            ;;
        --skip-start)
            SKIP_START=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "This installer must be run as root." >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required to create the virtual environment." >&2
    exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SERVICE_TEMPLATE="$SCRIPT_DIR/systemd/chatter-modbot.service.in"
if [[ ! -f "$SERVICE_TEMPLATE" ]]; then
    echo "Missing service template: $SERVICE_TEMPLATE" >&2
    exit 1
fi

ENV_FILE="/etc/default/${SERVICE_NAME}"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
RUNNER_PATH="${INSTALL_DIR}/run.sh"
VENV_PATH="${INSTALL_DIR}/venv"
PY_SCRIPT_DEST="${INSTALL_DIR}/gpt_moderator.py"

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --create-home --home-dir "$INSTALL_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
fi

SERVICE_GROUP=$(id -gn "$SERVICE_USER")

mkdir -p "$INSTALL_DIR"
chown "$SERVICE_USER":"$SERVICE_GROUP" "$INSTALL_DIR"

python3 -m venv --clear "$VENV_PATH"
"$VENV_PATH/bin/pip" install --upgrade pip >/dev/null
"$VENV_PATH/bin/pip" install --upgrade asyncssh >/dev/null
chown -R "$SERVICE_USER":"$SERVICE_GROUP" "$VENV_PATH"

install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 644 "$SCRIPT_DIR/gpt_moderator.py" "$PY_SCRIPT_DEST"

cat > "$RUNNER_PATH" <<RUNNER
#!/usr/bin/env bash
set -euo pipefail

if [[ -z "\${CHATTER_HOST:-}" ]]; then
    echo "CHATTER_HOST must be set (see $ENV_FILE)." >&2
    exit 1
fi

ARGS=("\${CHATTER_HOST}")

if [[ -n "\${CHATTER_PORT:-}" ]]; then
    ARGS+=("--port" "\${CHATTER_PORT}")
fi
if [[ -n "\${CHATTER_USERNAME:-}" ]]; then
    ARGS+=("--username" "\${CHATTER_USERNAME}")
fi
if [[ -n "\${CHATTER_PASSWORD:-}" ]]; then
    ARGS+=("--password" "\${CHATTER_PASSWORD}")
fi
if [[ -n "\${CHATTER_IDENTITY:-}" ]]; then
    ARGS+=("--identity" "\${CHATTER_IDENTITY}")
fi
if [[ -n "\${CHATTER_WARNING_LIMIT:-}" ]]; then
    ARGS+=("--warning-limit" "\${CHATTER_WARNING_LIMIT}")
fi
if [[ -n "\${CHATTER_LOG_LEVEL:-}" ]]; then
    ARGS+=("--log-level" "\${CHATTER_LOG_LEVEL}")
fi

if [[ -n "\${OPENAI_API_KEY:-}" ]]; then
    export OPENAI_API_KEY="\${OPENAI_API_KEY}"
fi

exec "$VENV_PATH/bin/python" "$PY_SCRIPT_DEST" "\${ARGS[@]}"
RUNNER

chown "$SERVICE_USER":"$SERVICE_GROUP" "$RUNNER_PATH"
chmod 750 "$RUNNER_PATH"

if [[ ! -f "$ENV_FILE" ]]; then
    cat > "$ENV_FILE" <<'ENV'
# ssh-chatter GPT moderator configuration
# Mandatory settings
CHATTER_HOST=ssh-chatter.example.com

# Optional overrides
#CHATTER_PORT=2022
#CHATTER_USERNAME=gpt-5
#CHATTER_PASSWORD=
#CHATTER_IDENTITY=/path/to/private_key
#CHATTER_WARNING_LIMIT=5
#CHATTER_LOG_LEVEL=INFO
#OPENAI_API_KEY=
#GPT_PROMPT="You are ChatGPT 5, a helpful chatter."
#OPENAI_MODEL=gpt-4o-mini
#GPT_HISTORY_LIMIT=12
#GPT_RESPONSE_COOLDOWN=2.0
#GPT_RESPOND_TO_QUESTIONS=0
#OPENAI_BASE_URL=https://api.openai.com
ENV
fi

chmod 640 "$ENV_FILE"

sed \
    -e "s|@INSTALL_ROOT@|$INSTALL_DIR|g" \
    -e "s|@SERVICE_USER@|$SERVICE_USER|g" \
    -e "s|@SERVICE_GROUP@|$SERVICE_GROUP|g" \
    -e "s|@ENV_FILE@|$ENV_FILE|g" \
    "$SERVICE_TEMPLATE" > "$SERVICE_PATH"

chmod 644 "$SERVICE_PATH"

systemctl daemon-reload

if [[ $SKIP_START -eq 0 ]]; then
    systemctl enable --now "$SERVICE_NAME"
else
    echo "Service installed but not started. Enable it with: systemctl enable --now $SERVICE_NAME"
fi

echo "Installation complete. Update $ENV_FILE with real connection details."
