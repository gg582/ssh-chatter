#!/usr/bin/env bash
# Memory leak detection script using valgrind
# This script runs ssh-chatter under valgrind to detect memory leaks and other memory issues

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VALGRIND_SUPP="${REPO_ROOT}/valgrind-libgc.supp"
BINARY="${REPO_ROOT}/ssh-chatter"

# Check if valgrind is installed
if ! command -v valgrind &> /dev/null; then
    echo "ERROR: valgrind is not installed. Install it with:"
    echo "  sudo apt-get install valgrind  # Debian/Ubuntu"
    echo "  sudo yum install valgrind      # RHEL/CentOS"
    echo "  sudo dnf install valgrind      # Fedora"
    exit 1
fi

# Check if the binary exists
if [[ ! -f "${BINARY}" ]]; then
    echo "ERROR: ${BINARY} not found. Build it first with 'make'"
    exit 1
fi

# Check if suppression file exists
if [[ ! -f "${VALGRIND_SUPP}" ]]; then
    echo "WARNING: Valgrind suppression file not found at ${VALGRIND_SUPP}"
    echo "Running without suppressions..."
    SUPP_ARG=""
else
    SUPP_ARG="--suppressions=${VALGRIND_SUPP}"
fi

# Parse command-line arguments
DURATION=30
LEAK_CHECK="full"
TRACK_ORIGINS="yes"
SHOW_REACHABLE="no"
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --duration)
            DURATION="$2"
            shift 2
            ;;
        --quick)
            LEAK_CHECK="summary"
            TRACK_ORIGINS="no"
            shift
            ;;
        --show-reachable)
            SHOW_REACHABLE="yes"
            shift
            ;;
        *)
            EXTRA_ARGS+=("$1")
            shift
            ;;
    esac
done

echo "=========================================="
echo "SSH-Chatter Memory Leak Check with Valgrind"
echo "=========================================="
echo "Binary: ${BINARY}"
echo "Duration: ${DURATION} seconds"
echo "Leak check: ${LEAK_CHECK}"
echo "Track origins: ${TRACK_ORIGINS}"
echo "Show reachable: ${SHOW_REACHABLE}"
echo ""
echo "The server will run for ${DURATION} seconds, then be terminated."
echo "Check the output below for any memory leaks or errors."
echo ""
echo "To connect to the test server, use:"
echo "  ssh -p 2222 testuser@localhost"
echo "=========================================="
echo ""

# Create temporary directory for runtime files
TEMP_DIR=$(mktemp -d)
trap "rm -rf ${TEMP_DIR}" EXIT

# Create minimal MOTD
echo "Valgrind memory leak test server" > "${TEMP_DIR}/motd"

# Generate temporary SSH host key if needed
if [[ ! -f "${TEMP_DIR}/ssh_host_rsa_key" ]]; then
    ssh-keygen -t rsa -b 2048 -f "${TEMP_DIR}/ssh_host_rsa_key" -N "" -q
fi

# Run valgrind with appropriate options
timeout "${DURATION}s" valgrind \
    --leak-check="${LEAK_CHECK}" \
    --show-leak-kinds=definite,possible \
    --track-origins="${TRACK_ORIGINS}" \
    --show-reachable="${SHOW_REACHABLE}" \
    --num-callers=20 \
    --verbose \
    --log-file="${TEMP_DIR}/valgrind.log" \
    ${SUPP_ARG} \
    "${BINARY}" \
    -a 127.0.0.1 \
    -p 2222 \
    -m "${TEMP_DIR}/motd" \
    -k "${TEMP_DIR}" \
    -T off \
    "${EXTRA_ARGS[@]}" \
    2>&1 || true

echo ""
echo "=========================================="
echo "Valgrind analysis complete"
echo "=========================================="
echo ""

# Display the valgrind log
if [[ -f "${TEMP_DIR}/valgrind.log" ]]; then
    echo "Valgrind output:"
    echo "----------------------------------------"
    cat "${TEMP_DIR}/valgrind.log"
    echo "----------------------------------------"
    echo ""
    
    # Analyze results
    DEFINITE_LEAKS=$(grep -c "definitely lost:" "${TEMP_DIR}/valgrind.log" || echo "0")
    POSSIBLE_LEAKS=$(grep -c "possibly lost:" "${TEMP_DIR}/valgrind.log" || echo "0")
    ERRORS=$(grep -c "ERROR SUMMARY:" "${TEMP_DIR}/valgrind.log" || echo "0")
    
    echo "Summary:"
    echo "  - Definite leaks found: ${DEFINITE_LEAKS}"
    echo "  - Possible leaks found: ${POSSIBLE_LEAKS}"
    echo "  - Error summaries: ${ERRORS}"
    echo ""
    
    # Check for critical issues
    if grep -q "definitely lost: [1-9]" "${TEMP_DIR}/valgrind.log"; then
        echo "❌ FAILED: Definite memory leaks detected!"
        exit 1
    elif grep -q "ERROR SUMMARY: [1-9]" "${TEMP_DIR}/valgrind.log"; then
        echo "⚠️  WARNING: Memory errors detected!"
        exit 1
    else
        echo "✅ PASSED: No critical memory issues detected"
        exit 0
    fi
else
    echo "ERROR: Valgrind log file not found"
    exit 1
fi
