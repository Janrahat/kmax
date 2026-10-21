#!/usr/bin/env bash
# =============================================================================
#  KMAX installer - Kali Linux / Debian / any POSIX system with Python 3.9+
#
#  Usage:
#     ./install.sh                 install for the current user (recommended)
#     sudo ./install.sh --system   install system-wide into /usr/local
#     ./install.sh --venv          install into a local .venv
#     ./install.sh --deps          also apt-install the optional helper tools
#     ./install.sh --test          install, then run the test suite
#     ./install.sh --uninstall     remove a previous user/system install
#
#  KMAX itself needs no third-party Python packages: only the standard library.
#  The helpers below merely make some checks richer.
# =============================================================================
set -Eeuo pipefail

PROJECT_NAME="kmax"
VERSION="2.0.0"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
MODE="user"
DO_DEPS=0
DO_TEST=0
DO_UNINSTALL=0

# --- colours (degrade to plain text when not a terminal) ---------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[91m'; GREEN=$'\033[92m'
    YELLOW=$'\033[93m'; BLUE=$'\033[94m'; CYAN=$'\033[96m'; RESET=$'\033[0m'
else
    BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; BLUE=""; CYAN=""; RESET=""
fi

say()  { printf '%s\n' "${CYAN}[*]${RESET} $*"; }
ok()   { printf '%s\n' "${GREEN}[+]${RESET} $*"; }
warn() { printf '%s\n' "${YELLOW}[!]${RESET} $*"; }
die()  { printf '%s\n' "${RED}[-]${RESET} $*" >&2; exit 1; }
hr()   { printf '%s\n' "${DIM}────────────────────────────────────────────────────────────${RESET}"; }

# --- argument parsing -------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --system)    MODE="system" ;;
        --venv)      MODE="venv" ;;
        --user)      MODE="user" ;;
        --deps)      DO_DEPS=1 ;;
        --test)      DO_TEST=1 ;;
        --uninstall) DO_UNINSTALL=1 ;;
        -h|--help)
            sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
    shift
done

hr
printf '%s\n' "${BOLD}${CYAN}  KMAX installer ${VERSION}${RESET}"
printf '%s\n' "${DIM}  Kali Multi-tool eXplorer - reconnaissance toolkit${RESET}"
hr

# --- locate a Python interpreter -------------------------------------------
find_python() {
    local candidate
    for candidate in python3 python; do
        if command -v "$candidate" >/dev/null 2>&1; then
            if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
                command -v "$candidate"
                return 0
            fi
        fi
    done
    return 1
}

PYTHON_BIN="$(find_python || true)"
[ -n "${PYTHON_BIN}" ] || die "Python 3.9 or newer is required but was not found.
     On Kali/Debian:  sudo apt update && sudo apt install python3 python3-pip"
PY_VERSION="$("${PYTHON_BIN}" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')"
ok "Python ${PY_VERSION}  (${PYTHON_BIN})"

# --- uninstall --------------------------------------------------------------
if [ "$DO_UNINSTALL" -eq 1 ]; then
    say "uninstalling KMAX…"
    if [ "$MODE" = "system" ] || [ "$(id -u)" -eq 0 ]; then
        "${PYTHON_BIN}" -m pip uninstall -y "${PROJECT_NAME}" 2>/dev/null || true
    else
        "${PYTHON_BIN}" -m pip uninstall -y --user "${PROJECT_NAME}" 2>/dev/null || true
    fi
    rm -rf "${SCRIPT_DIR}/.venv" 2>/dev/null || true
    ok "KMAX removed. (Reports and wordlists you created were left untouched.)"
    exit 0
fi

# --- optional system helpers ------------------------------------------------
install_deps() {
    local missing=()
    for tool in nmap dig openssl ping ip; do
        command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
    done
    if [ "${#missing[@]}" -eq 0 ]; then
        ok "all optional helper tools are already present"
        return 0
    fi
    warn "missing optional helpers: ${missing[*]}"
    if ! command -v apt-get >/dev/null 2>&1; then
        warn "apt-get not available - install these manually: nmap dnsutils openssl iproute2 iputils-ping"
        return 0
    fi
    if [ "$(id -u)" -ne 0 ]; then
        say "sudo is required to install the helper packages"
        sudo apt-get update -qq || warn "apt-get update failed; continuing"
        sudo apt-get install -y nmap dnsutils openssl iproute2 iputils-ping || warn "helper install failed"
    else
        apt-get update -qq || true
        apt-get install -y nmap dnsutils openssl iproute2 iputils-ping || warn "helper install failed"
    fi
    ok "helper tools processed"
}

[ "$DO_DEPS" -eq 1 ] && install_deps

# --- sanity-check the payload ----------------------------------------------
[ -f "${SCRIPT_DIR}/pyproject.toml" ] || die "pyproject.toml not found in ${SCRIPT_DIR} - run install.sh from the project root"
[ -f "${SCRIPT_DIR}/kmax/cli.py" ]    || die "kmax/cli.py not found - the archive looks incomplete"

say "compiling every module to catch syntax errors early…"
"${PYTHON_BIN}" -m compileall -q "${SCRIPT_DIR}/kmax" >/dev/null || die "byte-compilation failed; the source tree may be corrupt"
ok "source tree compiles cleanly"

# --- install ---------------------------------------------------------------
case "${MODE}" in
    venv)
        say "creating a virtual environment in ${SCRIPT_DIR}/.venv"
        "${PYTHON_BIN}" -m venv "${SCRIPT_DIR}/.venv" || die "could not create a virtual environment (install python3-venv)"
        # shellcheck disable=SC1091
        . "${SCRIPT_DIR}/.venv/bin/activate"
        python -m pip install --quiet --upgrade pip wheel >/dev/null 2>&1 || true
        python -m pip install --quiet -e "${SCRIPT_DIR}[dev]" || die "pip install failed"
        ok "installed into ${SCRIPT_DIR}/.venv"
        ACTIVATE_HINT="source \"${SCRIPT_DIR}/.venv/bin/activate\""
        ;;
    system)
        [ "$(id -u)" -eq 0 ] || die "--system requires root (use: sudo ./install.sh --system)"
        say "installing system-wide into /usr/local"
        "${PYTHON_BIN}" -m pip install --break-system-packages --quiet . \
            || "${PYTHON_BIN}" -m pip install --quiet .
        ok "installed system-wide (kmax is on PATH for every user)"
        ACTIVATE_HINT=""
        ;;
    *)
        say "installing for the current user (pip --user)"
        if ! "${PYTHON_BIN}" -m pip install --quiet --user . 2>/dev/null; then
            warn "pip --user failed; retrying inside a virtual environment"
            "${PYTHON_BIN}" -m venv "${SCRIPT_DIR}/.venv" || die "venv creation failed"
            "${SCRIPT_DIR}/.venv/bin/python" -m pip install --quiet -e "${SCRIPT_DIR}" || die "pip install failed"
            ACTIVATE_HINT="source \"${SCRIPT_DIR}/.venv/bin/activate\""
        else
            ACTIVATE_HINT=""
        fi
        ok "installed for the current user"
        ;;
esac

# --- verify the entry point ------------------------------------------------
hr
say "verifying the installation…"
if command -v kmax >/dev/null 2>&1; then
    kmax version >/dev/null 2>&1 && ok "entry point works: $(command -v kmax)"
elif "${PYTHON_BIN}" -c 'import kmax' >/dev/null 2>&1; then
    ok "importable as a module (use: python3 -m kmax)"
else
    warn "the kmax command is not on PATH yet"
    [ -n "${ACTIVATE_HINT}" ] && warn "run: ${ACTIVATE_HINT}"
    warn "or fall back to: PYTHONPATH=\"${SCRIPT_DIR}\" ${PYTHON_BIN} -m kmax"
fi

# --- optional test run -----------------------------------------------------
if [ "$DO_TEST" -eq 1 ]; then
    hr
    say "running the test suite…"
    if "${PYTHON_BIN}" -c 'import pytest' >/dev/null 2>&1; then
        (cd "${SCRIPT_DIR}" && "${PYTHON_BIN}" -m pytest -q) || warn "some tests failed"
    else
        warn "pytest is not installed (pip install pytest) - running the built-in smoke test instead"
        "${PYTHON_BIN}" "${SCRIPT_DIR}/tools/smoke_test.py" || warn "smoke test reported problems"
    fi
fi

# --- closing banner --------------------------------------------------------
hr
printf '%s\n' "${BOLD}${GREEN}  KMAX ${VERSION} is ready.${RESET}"
hr
cat <<'EOF'
  Get started:

    kmax --help                        # every command and flag
    kmax scan 192.168.1.0/24          # who is on my LAN?
    kmax ports 10.0.0.5 --top 1000     # open ports + banners
    kmax dns example.com -s            # DNS records + subdomains
    kmax web https://example.com       # headers, redirects, TLS cert
    kmax sysinfo --tools               # local system + tool inventory
    kmax shell                         # interactive prompt

  Add a report to any command:

    kmax ports 10.0.0.5 --top 100 -o scan.html     # or: --report scan.html
    kmax scan 10.0.0.0/24 --json > scan.json
    kmax report scan.json partial.json --out combined.html

  Reminder: scan only systems you own or have written permission to test.
EOF
hr
