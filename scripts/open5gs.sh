#!/usr/bin/env bash
# open5gs.sh — Clone, build (ASAN), and manage open5GS network functions
#
# Usage:
#   ./open5gs.sh setup   [version]             clone + checkout + ASAN build
#   ./open5gs.sh start   [version]             start all NFs  (requires root)
#   ./open5gs.sh stop    [version]             stop all NFs
#   ./open5gs.sh restart [version]             stop then start
#   ./open5gs.sh status  [version]             show running/down status
#   ./open5gs.sh watch   [version] [--errors]  tail all NF logs
#
# version defaults to the latest release on GitHub.  open5GS is cloned to ~/open5gs.

set -euo pipefail

# Use the invoking user's home even when run via sudo
if [[ -n "${SUDO_USER:-}" ]]; then
    REAL_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
else
    REAL_HOME="$HOME"
fi

OPEN5GS_DIR="${REAL_HOME}/open5gs"
OPEN5GS_REPO="https://github.com/open5gs/open5gs.git"

_latest_version() {
    curl -fsSL "https://api.github.com/repos/open5gs/open5gs/releases/latest" \
        2>/dev/null | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/'
}

COMMAND="${1:-}"
VERSION="${2:-}"

if [[ -z "$VERSION" ]]; then
    echo "  Fetching latest open5GS version from GitHub ..."
    VERSION="$(_latest_version)"
    if [[ -z "$VERSION" ]]; then
        echo "ERROR: could not determine latest version. Pass a version explicitly (e.g. v2.7.7)." >&2
        exit 1
    fi
    echo "  Latest version: ${VERSION}"
fi

BUILD_DIR="${OPEN5GS_DIR}/build_${VERSION}"
BIN_DIR="${BUILD_DIR}/src"
CFG_DIR="${BUILD_DIR}/configs/open5gs"
LOG_DIR="/tmp/open5gs-${VERSION}-logs"
PID_DIR="/tmp/open5gs-${VERSION}-pids"

# ---------------------------------------------------------------------------
# NF startup order (NRF first, UPF last)
# ---------------------------------------------------------------------------
NFS=(nrf udr udm ausf bsf pcf nssf amf smf upf)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Guard against running apt-get update more than once per script invocation.
_APT_UPDATED=0
_apt_update() {
    (( _APT_UPDATED )) && return 0
    apt-get update -qq
    _APT_UPDATED=1
}

_binary()  { echo "${BIN_DIR}/$1/open5gs-${1}d"; }
_config()  { echo "${CFG_DIR}/$1.yaml"; }
_logfile() { echo "${LOG_DIR}/$1.log"; }
_pidfile() { echo "${PID_DIR}/$1.pid"; }

_running_pid() {
    local nf="$1"
    local pf; pf="$(_pidfile "$nf")"
    [[ -f "$pf" ]] || return 1
    local pid; pid="$(cat "$pf")"
    kill -0 "$pid" 2>/dev/null && echo "$pid" || return 1
}

# Kill any lingering process by binary name (fallback when PID file is absent/stale)
_kill_by_name() {
    local nf="$1"
    local bin="open5gs-${nf}d"
    pgrep -f "$bin" >/dev/null 2>&1 || return 0
    pkill -TERM -f "$bin" 2>/dev/null || true
    local w=0
    while pgrep -f "$bin" >/dev/null 2>&1 && (( w < 30 )); do sleep 0.1; (( w += 1 )); done
    pkill -KILL -f "$bin" 2>/dev/null || true
}

_print_status() {
    echo ""
    echo "=== open5GS ${VERSION} NF Status ==="
    for nf in "${NFS[@]}"; do
        local pid; pid="$(_running_pid "$nf" 2>/dev/null)" || true
        if [[ -n "$pid" ]]; then
            printf "  %-6s  UP    pid=%-8s  log=%s\n" "$nf" "$pid" "$(_logfile "$nf")"
        else
            printf "  %-6s  DOWN\n" "$nf"
        fi
    done
}

_install_mongodb() {
    if command -v mongod >/dev/null 2>&1; then
        echo "  [mongodb] mongod already installed ($(mongod --version 2>&1 | head -1))"
        return 0
    fi

    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: root privileges required to install MongoDB. Re-run with sudo." >&2
        exit 1
    fi

    # Detect distro and codename to select the right MongoDB repo.
    local distro codename
    distro="$(. /etc/os-release && echo "${ID}")"
    codename="$(. /etc/os-release && echo "${VERSION_CODENAME:-}")"
    if [[ -z "$codename" ]]; then
        codename="$(lsb_release -cs 2>/dev/null || true)"
    fi

    # MongoDB 7.0 supports: ubuntu focal/jammy/noble, debian bullseye/bookworm.
    # Fall back to the nearest supported release for unknown codenames.
    local mongo_ver="7.0"
    local repo_distro repo_codename
    case "$distro" in
        ubuntu)
            repo_distro="ubuntu"
            case "$codename" in
                focal|jammy|noble) repo_codename="$codename" ;;
                *)
                    echo "  [mongodb] WARNING: unknown Ubuntu codename '${codename}', using jammy"
                    repo_codename="jammy" ;;
            esac
            ;;
        debian)
            repo_distro="debian"
            case "$codename" in
                bullseye|bookworm) repo_codename="$codename" ;;
                *)
                    echo "  [mongodb] WARNING: unknown Debian codename '${codename}', using bookworm"
                    repo_codename="bookworm" ;;
            esac
            ;;
        *)
            echo "  [mongodb] ERROR: unsupported distro '${distro}' — install MongoDB manually." >&2
            return 1
            ;;
    esac

    echo "  [mongodb] Installing MongoDB ${mongo_ver} for ${repo_distro}/${repo_codename} ..."

    apt-get install -y -qq gnupg curl ca-certificates

    local keyring="/usr/share/keyrings/mongodb-server-${mongo_ver}.gpg"
    curl -fsSL "https://www.mongodb.org/static/pgp/server-${mongo_ver}.asc" \
        | gpg --dearmor -o "$keyring"

    local sources_file="/etc/apt/sources.list.d/mongodb-org-${mongo_ver}.list"
    echo "deb [ arch=amd64,arm64 signed-by=${keyring} ] \
https://repo.mongodb.org/apt/${repo_distro} ${repo_codename}/mongodb-org/${mongo_ver} multiverse" \
        > "$sources_file"

    _apt_update
    apt-get install -y mongodb-org

    # Enable the service so it survives reboots and starts on first use.
    systemctl enable mongod
    systemctl start  mongod
    sleep 1

    if ! command -v mongosh >/dev/null 2>&1; then
        echo "  [mongodb] WARNING: mongosh not found after install — ping check skipped"
        return 0
    fi
    if mongosh --quiet --eval 'db.runCommand({ping:1})' \
               mongodb://localhost/open5gs >/dev/null 2>&1; then
        echo "  [mongodb] installed and running"
    else
        echo "  [mongodb] WARNING: installed but not yet reachable — UDR/PCF may need a moment"
    fi
}

_ensure_mongodb() {
    # If mongod is not installed at all, install it now (setup should have done
    # this, but handle the case where start is called on a fresh machine too).
    if ! command -v mongod >/dev/null 2>&1; then
        echo "  [mongodb] not installed — running installer ..."
        _install_mongodb
    fi

    if mongosh --quiet --eval 'db.runCommand({ping:1})' \
               mongodb://localhost/open5gs >/dev/null 2>&1; then
        return 0
    fi
    echo "  [mongodb] not reachable — attempting to start ..."
    if systemctl start mongod 2>/dev/null || systemctl start mongodb 2>/dev/null; then
        sleep 1
        if mongosh --quiet --eval 'db.runCommand({ping:1})' \
                   mongodb://localhost/open5gs >/dev/null 2>&1; then
            echo "  [mongodb] started via systemctl"
            return 0
        fi
    fi
    echo "  [mongodb] ERROR: cannot reach MongoDB — udr and pcf will fail" >&2
    return 1
}

# ---------------------------------------------------------------------------
# _install_deps — install missing build dependencies via apt
# ---------------------------------------------------------------------------
_DEPS=(
    python3-pip python3-setuptools python3-wheel
    ninja-build build-essential flex bison git cmake
    libsctp-dev libgnutls28-dev libgcrypt-dev libssl-dev libidn11-dev
    libmongoc-dev libbson-dev libyaml-dev libnghttp2-dev libmicrohttpd-dev
    libcurl4-gnutls-dev libtins-dev libtalloc-dev meson
)

_install_deps() {
    local missing=()
    for pkg in "${_DEPS[@]}"; do
        dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed" \
            || missing+=("$pkg")
    done

    if [[ ${#missing[@]} -eq 0 ]]; then
        echo "  All build dependencies already installed."
        return 0
    fi

    echo "  Missing packages: ${missing[*]}"
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: root privileges required to install packages. Re-run with sudo." >&2
        exit 1
    fi
    _apt_update
    apt-get install -y "${missing[@]}"
}

# ---------------------------------------------------------------------------
# setup — clone, checkout version, build with ASAN
# ---------------------------------------------------------------------------
cmd_setup() {
    echo "=== Setting up open5GS ${VERSION} ==="

    echo "--- Checking / installing MongoDB ---"
    _install_mongodb

    echo "--- Checking build dependencies ---"
    _install_deps

    # Clone if not present
    if [[ ! -d "${OPEN5GS_DIR}/.git" ]]; then
        echo "  Cloning ${OPEN5GS_REPO} → ${OPEN5GS_DIR} ..."
        git clone "${OPEN5GS_REPO}" "${OPEN5GS_DIR}"
    else
        echo "  Repo already exists at ${OPEN5GS_DIR} — skipping clone"
        git -C "${OPEN5GS_DIR}" fetch --tags --quiet
    fi

    # Checkout requested version
    echo "  Checking out ${VERSION} ..."
    git -C "${OPEN5GS_DIR}" checkout "${VERSION}"

    # Configure with meson (reconfigure if build dir already exists)
    echo "  Configuring ${BUILD_DIR} ..."
    (
        cd "${OPEN5GS_DIR}"
        if [[ -f "${BUILD_DIR}/build.ninja" ]]; then
            meson setup "build_${VERSION}" \
                --buildtype=debug \
                -Db_sanitize=address,undefined \
                -Db_lundef=false \
                --prefix="$(pwd)/install" \
                --reconfigure
        else
            mkdir -p "build_${VERSION}"
            meson setup "build_${VERSION}" \
                --buildtype=debug \
                -Db_sanitize=address,undefined \
                -Db_lundef=false \
                --prefix="$(pwd)/install"
        fi
    )

    # Build
    echo "  Building with ninja ..."
    ninja -C "${BUILD_DIR}"

    # Install to prefix so NFs find their configs (freeDiameter, TLS certs, etc.)
    echo "  Installing to $(pwd)/install ..."
    ninja -C "${BUILD_DIR}" install

    echo ""
    echo "=== Build complete: ${BUILD_DIR} ==="
    echo "    Run: sudo $0 start ${VERSION}"
}

# ---------------------------------------------------------------------------
# start
# ---------------------------------------------------------------------------
cmd_start() {
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: must be run as root (UPF needs /dev/net/tun). Use: sudo $0 start ${VERSION}" >&2
        exit 1
    fi

    if [[ ! -d "${BUILD_DIR}" ]]; then
        echo "ERROR: build directory not found: ${BUILD_DIR}" >&2
        echo "       Run: $0 setup ${VERSION}" >&2
        exit 1
    fi

    echo "=== Starting open5GS ${VERSION} NFs ==="
    mkdir -p "${LOG_DIR}" "${PID_DIR}"
    _ensure_mongodb || true

    # ASAN: log crashes to file, don't halt so all NFs keep running
    export ASAN_OPTIONS="${ASAN_OPTIONS:-halt_on_error=0:abort_on_error=0:detect_leaks=0:log_path=${LOG_DIR}/asan}"
    export UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=0:print_stacktrace=1:log_path=${LOG_DIR}/ubsan}"

    for nf in "${NFS[@]}"; do
        local bin; bin="$(_binary "$nf")"
        local cfg; cfg="$(_config "$nf")"
        local log; log="$(_logfile "$nf")"
        local pf;  pf="$(_pidfile "$nf")"

        if ! [[ -x "$bin" ]]; then
            echo "  [${nf}] ERROR: binary not found at ${bin}" >&2; continue
        fi
        if ! [[ -f "$cfg" ]]; then
            echo "  [${nf}] ERROR: config not found at ${cfg}" >&2; continue
        fi

        # Stop any existing instance before starting fresh (PID file or stale process)
        local existing_pid; existing_pid="$(_running_pid "$nf" 2>/dev/null)" || true
        if [[ -n "$existing_pid" ]]; then
            printf "  [%s] stopping existing (pid %s) ...\n" "$nf" "$existing_pid"
            kill -TERM "$existing_pid" 2>/dev/null || true
            local w=0
            while kill -0 "$existing_pid" 2>/dev/null && (( w < 30 )); do
                sleep 0.1; (( w += 1 ))
            done
            kill -KILL "$existing_pid" 2>/dev/null || true
            rm -f "$pf"
        fi
        _kill_by_name "$nf"  # catch any stale process not tracked by a PID file

        "$bin" -c "$cfg" -l "$log" >> "$log" 2>&1 &
        local pid=$!
        disown "$pid" 2>/dev/null || true  # suppress bash's "Aborted (core dumped)" noise
        echo "$pid" > "$pf"

        sleep 0.15
        if kill -0 "$pid" 2>/dev/null; then
            printf "  [%s] started (pid %s)  log: %s\n" "$nf" "$pid" "$log"
        else
            printf "  [%s] ERROR: exited immediately — %s\n" "$nf" "$log" >&2
            tail -15 "$log" 2>/dev/null | sed "s/^/    /" >&2
            rm -f "$pf"
        fi
    done

    # Give slow-to-crash NFs a grace period, then report any that died
    sleep 1
    local crashed=0
    for nf in "${NFS[@]}"; do
        local pf; pf="$(_pidfile "$nf")"
        [[ -f "$pf" ]] || continue
        local pid; pid="$(cat "$pf" 2>/dev/null)" || continue
        kill -0 "$pid" 2>/dev/null && continue
        (( crashed++ ))
        printf "\n  [%s] CRASHED after start — last log lines:\n" "$nf" >&2
        tail -20 "$(_logfile "$nf")" 2>/dev/null | sed "s/^/    /" >&2
        rm -f "$pf"
    done

    _print_status
}

# ---------------------------------------------------------------------------
# stop
# ---------------------------------------------------------------------------
cmd_stop() {
    echo "=== Stopping open5GS ${VERSION} NFs ==="

    local reversed=()
    for (( i=${#NFS[@]}-1; i>=0; i-- )); do reversed+=("${NFS[$i]}"); done

    for nf in "${reversed[@]}"; do
        local pid; pid="$(_running_pid "$nf" 2>/dev/null)" || true
        if [[ -z "$pid" ]]; then
            # No PID file — kill by name in case a stale process is still holding the port
            if pgrep -f "open5gs-${nf}d" >/dev/null 2>&1; then
                printf "  [%s] no PID file but process found — killing by name\n" "$nf"
                _kill_by_name "$nf"
            else
                printf "  [%s] not running\n" "$nf"
            fi
            continue
        fi

        kill -TERM "$pid" 2>/dev/null || true
        local waited=0
        while kill -0 "$pid" 2>/dev/null && (( waited < 50 )); do
            sleep 0.1; (( waited += 1 ))
        done

        if kill -0 "$pid" 2>/dev/null; then
            kill -KILL "$pid" 2>/dev/null || true
            printf "  [%s] killed (pid %s)\n" "$nf" "$pid"
        else
            printf "  [%s] stopped (pid %s)\n" "$nf" "$pid"
        fi
        rm -f "$(_pidfile "$nf")"
    done
}

# ---------------------------------------------------------------------------
# watch — tail all NF logs with per-NF colors and severity highlighting
# ---------------------------------------------------------------------------
declare -A _NF_COLOR=(
    [nrf]="36"  [udr]="33"  [udm]="35"  [ausf]="34"  [bsf]="32"
    [pcf]="91"  [nssf]="37" [amf]="92"  [smf]="93"   [upf]="94"
)

cmd_watch() {
    local errors_only=0
    [[ "${3:-}" == "--errors" ]] && errors_only=1

    local found=0
    for nf in "${NFS[@]}"; do [[ -f "$(_logfile "$nf")" ]] && { found=1; break; }; done
    if (( found == 0 )); then
        echo "No log files found in ${LOG_DIR} — run 'start ${VERSION}' first." >&2; exit 1
    fi

    if (( errors_only )); then
        echo "=== open5GS ${VERSION} logs  [FATAL/ERROR/WARNING only — Ctrl+C to stop] ==="
    else
        echo "=== open5GS ${VERSION} logs  [all lines — Ctrl+C to stop] ==="
    fi
    echo

    local watch_pids=()
    for nf in "${NFS[@]}"; do
        local log; log="$(_logfile "$nf")"
        [[ -f "$log" ]] || continue
        local color="${_NF_COLOR[$nf]:-37}"
        (
            tail -n 5 -f "$log" 2>/dev/null | while IFS= read -r line; do
                local plain; plain="$(printf '%s' "$line" | sed 's/\x1b\[[0-9;]*m//g')"

                local sev_color=""
                if   [[ "$plain" =~ FATAL|Segmentation.fault|core.dumped|SIGABRT|SIGSEGV|Aborted ]]; then
                    sev_color="\e[1;31m"
                elif [[ "$plain" =~ [[:space:]]ERROR[[:space:]] || "$plain" =~ \]\ ERROR ]]; then
                    sev_color="\e[31m"
                elif [[ "$plain" =~ [[:space:]]WARNING[[:space:]] || "$plain" =~ \]\ WARNING ]]; then
                    sev_color="\e[33m"
                fi

                (( errors_only )) && [[ -z "$sev_color" ]] && continue
                [[ "$plain" =~ ^[0-9]{2}/[0-9]{2}\ [0-9]{2}: && ! "$line" =~ $'\x1b' ]] && continue

                local msg; msg="$(printf '%s' "$plain" | sed 's/^[0-9/]* [0-9:\.]*: //')"
                printf "\e[${color}m[%-4s]\e[0m ${sev_color}%s\e[0m\n" "$nf" "$msg"
            done
        ) &
        watch_pids+=($!)
    done

    trap 'kill "${watch_pids[@]}" 2>/dev/null; echo; exit 0' INT TERM
    wait
}

# ---------------------------------------------------------------------------
# restart / status
# ---------------------------------------------------------------------------
cmd_restart() { cmd_stop; sleep 1; cmd_start; }
cmd_status()  { _print_status; }

# ---------------------------------------------------------------------------
# start-nf — restart a single NF (used by the fuzzer's --amf-restart-cmd)
# ---------------------------------------------------------------------------
cmd_start_nf() {
    local nf="${3:-}"
    if [[ -z "$nf" ]]; then
        echo "Usage: $0 start-nf <version> <nf-name>" >&2
        echo "  nf-name: one of ${NFS[*]}" >&2
        exit 1
    fi
    nf="${nf,,}"  # lowercase

    local bin; bin="$(_binary "$nf")"
    local cfg; cfg="$(_config "$nf")"
    local log; log="$(_logfile "$nf")"
    local pf;  pf="$(_pidfile "$nf")"

    if ! [[ -x "$bin" ]]; then
        echo "ERROR: binary not found: ${bin}" >&2; exit 1
    fi
    if ! [[ -f "$cfg" ]]; then
        echo "ERROR: config not found: ${cfg}" >&2; exit 1
    fi

    # Kill any existing instance
    local existing_pid; existing_pid="$(_running_pid "$nf" 2>/dev/null)" || true
    if [[ -n "$existing_pid" ]]; then
        kill -TERM "$existing_pid" 2>/dev/null || true
        local w=0
        while kill -0 "$existing_pid" 2>/dev/null && (( w < 30 )); do
            sleep 0.1; (( w += 1 ))
        done
        kill -KILL "$existing_pid" 2>/dev/null || true
        rm -f "$pf"
    fi

    mkdir -p "${LOG_DIR}" "${PID_DIR}"
    export ASAN_OPTIONS="${ASAN_OPTIONS:-halt_on_error=0:abort_on_error=0:detect_leaks=0:log_path=${LOG_DIR}/asan}"
    export UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=0:print_stacktrace=1:log_path=${LOG_DIR}/ubsan}"

    "$bin" -c "$cfg" -l "$log" >> "$log" 2>&1 &
    local pid=$!
    disown "$pid" 2>/dev/null || true
    echo "$pid" > "$pf"

    sleep 0.3
    if kill -0 "$pid" 2>/dev/null; then
        echo "[${nf}] started (pid ${pid})"
    else
        echo "ERROR: [${nf}] exited immediately — check ${log}" >&2
        tail -15 "$log" 2>/dev/null | sed "s/^/  /" >&2
        rm -f "$pf"
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
case "${COMMAND}" in
    setup)    cmd_setup              ;;
    start)    cmd_start              ;;
    stop)     cmd_stop               ;;
    restart)  cmd_restart            ;;
    status)   cmd_status             ;;
    watch)    cmd_watch "$@"         ;;
    start-nf) cmd_start_nf "$@"     ;;
    *)
        cat <<EOF
Usage: $0 <command> [version]

Commands:
  setup      [version]             clone open5GS, checkout version, build with ASAN
  start      [version]             start all NFs (requires root)
  stop       [version]             stop all NFs
  restart    [version]             stop then start
  status     [version]             show running/down status
  watch      [version] [--errors]  tail all NF logs (Ctrl+C to stop)
  start-nf   <version> <nf>        restart a single NF (for fuzzer --amf-restart-cmd)

version defaults to the latest release on GitHub.  open5GS is cloned to ${OPEN5GS_DIR}.

Examples:
  sudo $0 setup
  sudo $0 setup v2.7.7
  sudo $0 start
  $0 watch --errors
  $0 status
  sudo $0 start-nf v2.7.5 nrf
EOF
        exit 1
        ;;
esac
