#!/usr/bin/env bash
# free5gc.sh — Clone, build (ASAN), and manage free5GC network functions
#
# Usage:
#   ./free5gc.sh setup   [version]             clone + checkout + ASAN build
#   ./free5gc.sh start   [version]             start all NFs  (requires root)
#   ./free5gc.sh stop    [version]             stop all NFs
#   ./free5gc.sh restart [version]             stop then start
#   ./free5gc.sh status  [version]             show running/down status
#   ./free5gc.sh watch   [version] [--errors]  tail all NF logs
#   ./free5gc.sh start-nf <version> <nf>       restart a single NF
#
# ASAN is always enabled.  ASAN_OPTIONS/UBSAN_OPTIONS are set automatically
# at start time — no manual export needed.
# version defaults to the latest release on GitHub.  free5GC is cloned to ~/free5gc.

set -euo pipefail

# Use the invoking user's home even when run via sudo
if [[ -n "${SUDO_USER:-}" ]]; then
    REAL_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
else
    REAL_HOME="$HOME"
fi

FREE5GC_DIR="${REAL_HOME}/free5gc"
FREE5GC_REPO="https://github.com/free5gc/free5gc.git"
GTP5G_REPO="https://github.com/free5gc/gtp5g.git"
GTP5G_DIR="${REAL_HOME}/gtp5g"

_latest_version() {
    curl -fsSL "https://api.github.com/repos/free5gc/free5gc/releases/latest" \
        2>/dev/null | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/'
}

COMMAND="${1:-}"
VERSION="${2:-}"

if [[ -z "$VERSION" ]]; then
    echo "  Fetching latest free5GC version from GitHub ..."
    VERSION="$(_latest_version)"
    if [[ -z "$VERSION" ]]; then
        echo "ERROR: could not determine latest version. Pass a version explicitly (e.g. v3.4.3)." >&2
        exit 1
    fi
    echo "  Latest version: ${VERSION}"
fi

# free5GC builds in-place; binaries land in bin/, configs live in config/
BIN_DIR="${FREE5GC_DIR}/bin"
CFG_DIR="${FREE5GC_DIR}/config"
LOG_DIR="/tmp/free5gc-${VERSION}-logs"
PID_DIR="/tmp/free5gc-${VERSION}-pids"
# Go-coverage output dir (one subdir per NF).  Used by build-cover/start-cover/coverage.
COV_DIR="/tmp/free5gc-${VERSION}-cov"

# ---------------------------------------------------------------------------
# NF startup order (NRF first, UPF last among core NFs)
# CHF was added in v3.4; it is probed at runtime and skipped if absent.
# ---------------------------------------------------------------------------
NFS=(nrf udr udm ausf bsf nssf pcf amf smf upf)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_APT_UPDATED=0
_apt_update() {
    (( _APT_UPDATED )) && return 0
    apt-get update -qq
    _APT_UPDATED=1
}

_binary()    { echo "${BIN_DIR}/$1"; }
_cover_binary() { echo "${BIN_DIR}/${1}_cover"; }   # Go-coverage-instrumented build

# COVER_NFS: space/comma-separated NF list to launch from their -cover binary
# (with GOCOVERDIR set) when running `start`.  Lets one `start` bring the whole
# stack up with just the target NF(s) instrumented, e.g.:
#   COVER_NFS=udm sudo ./free5gc.sh start main
_is_cover_nf() {
    local nf="$1"; local list=" ${COVER_NFS:-} "; list="${list//,/ }"
    [[ "$list" == *" ${nf} "* ]]
}
_config()    { echo "${CFG_DIR}/${1}cfg.yaml"; }
_logfile()   { echo "${LOG_DIR}/$1.log"; }
_pidfile()   { echo "${PID_DIR}/$1.pid"; }
# SMF also requires a UE-routing config; default path mirrors free5GC repo layout
_uerouting() { echo "${CFG_DIR}/uerouting.yaml"; }

_running_pid() {
    local nf="$1"
    local pf; pf="$(_pidfile "$nf")"
    [[ -f "$pf" ]] || return 1
    local pid; pid="$(cat "$pf")"
    kill -0 "$pid" 2>/dev/null && echo "$pid" || return 1
}

# Kill any lingering process by binary path (fallback when PID file is absent/stale)
_kill_by_name() {
    local nf="$1"
    local bin="${BIN_DIR}/${nf}"
    pgrep -f "$bin" >/dev/null 2>&1 || return 0
    pkill -TERM -f "$bin" 2>/dev/null || true
    local w=0
    while pgrep -f "$bin" >/dev/null 2>&1 && (( w < 30 )); do sleep 0.1; (( w += 1 )); done
    pkill -KILL -f "$bin" 2>/dev/null || true
}

_print_status() {
    echo ""
    echo "=== free5GC ${VERSION} NF Status ==="
    local nfs_list=("${NFS[@]}")
    [[ -x "$(_binary chf)" ]] && nfs_list+=(chf)
    for nf in "${nfs_list[@]}"; do
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

    local distro codename
    distro="$(. /etc/os-release && echo "${ID}")"
    codename="$(. /etc/os-release && echo "${VERSION_CODENAME:-}")"
    if [[ -z "$codename" ]]; then
        codename="$(lsb_release -cs 2>/dev/null || true)"
    fi

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

    systemctl enable mongod
    systemctl start  mongod
    sleep 1

    if ! command -v mongosh >/dev/null 2>&1; then
        echo "  [mongodb] WARNING: mongosh not found after install — ping check skipped"
        return 0
    fi
    if mongosh --quiet --eval 'db.runCommand({ping:1})' \
               mongodb://localhost/free5gc >/dev/null 2>&1; then
        echo "  [mongodb] installed and running"
    else
        echo "  [mongodb] WARNING: installed but not yet reachable — UDR may need a moment"
    fi
}

_ensure_mongodb() {
    if ! command -v mongod >/dev/null 2>&1; then
        echo "  [mongodb] not installed — running installer ..."
        _install_mongodb
    fi

    if mongosh --quiet --eval 'db.runCommand({ping:1})' \
               mongodb://localhost/free5gc >/dev/null 2>&1; then
        return 0
    fi
    echo "  [mongodb] not reachable — attempting to start ..."
    if systemctl start mongod 2>/dev/null || systemctl start mongodb 2>/dev/null; then
        sleep 1
        if mongosh --quiet --eval 'db.runCommand({ping:1})' \
                   mongodb://localhost/free5gc >/dev/null 2>&1; then
            echo "  [mongodb] started via systemctl"
            return 0
        fi
    fi
    echo "  [mongodb] ERROR: cannot reach MongoDB — udr will fail" >&2
    return 1
}

# ---------------------------------------------------------------------------
# _install_go — ensure Go >= 1.21 is available
# ---------------------------------------------------------------------------
_MIN_GO_MAJOR=1
_MIN_GO_MINOR=21

_go_version_ok() {
    command -v go >/dev/null 2>&1 || return 1
    local ver; ver="$(go version | awk '{print $3}' | sed 's/go//')"
    local major minor
    IFS='.' read -r major minor _ <<< "$ver"
    (( major > _MIN_GO_MAJOR || ( major == _MIN_GO_MAJOR && minor >= _MIN_GO_MINOR ) ))
}

_install_go() {
    if _go_version_ok; then
        echo "  [go] already installed: $(go version)"
        return 0
    fi

    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: Go >= ${_MIN_GO_MAJOR}.${_MIN_GO_MINOR} required. Re-run with sudo to auto-install." >&2
        exit 1
    fi

    local go_ver="1.22.3"
    local arch; arch="$(uname -m)"
    case "$arch" in
        x86_64)  arch="amd64" ;;
        aarch64) arch="arm64" ;;
        *)
            echo "ERROR: unsupported architecture '${arch}' for Go auto-install." >&2
            exit 1 ;;
    esac

    echo "  [go] Installing Go ${go_ver} (${arch}) ..."
    local tarball="go${go_ver}.linux-${arch}.tar.gz"
    curl -fsSL "https://go.dev/dl/${tarball}" -o "/tmp/${tarball}"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "/tmp/${tarball}"
    rm -f "/tmp/${tarball}"
    ln -sf /usr/local/go/bin/go    /usr/local/bin/go
    ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
    export PATH="/usr/local/go/bin:${PATH}"
    echo "  [go] installed: $(go version)"
}

# ---------------------------------------------------------------------------
# _install_gtp5g — build and load the gtp5g kernel module (required by UPF)
# ---------------------------------------------------------------------------
_install_gtp5g() {
    if lsmod | grep -q '^gtp5g'; then
        echo "  [gtp5g] module already loaded"
        return 0
    fi

    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: root privileges required to install gtp5g. Re-run with sudo." >&2
        exit 1
    fi

    _apt_update
    apt-get install -y -qq "linux-headers-$(uname -r)" gcc make

    if [[ ! -d "${GTP5G_DIR}/.git" ]]; then
        echo "  [gtp5g] Cloning ${GTP5G_REPO} → ${GTP5G_DIR} ..."
        git clone --depth=1 "${GTP5G_REPO}" "${GTP5G_DIR}"
    else
        echo "  [gtp5g] Repo exists — pulling latest ..."
        git -C "${GTP5G_DIR}" pull --ff-only --quiet
    fi

    echo "  [gtp5g] Building kernel module ..."
    make -C "${GTP5G_DIR}"

    echo "  [gtp5g] Loading kernel module ..."
    # Load udp_tunnel dependency first (gtp5g depends on it)
    modprobe udp_tunnel 2>/dev/null || true

    local load_err
    load_err="$(insmod "${GTP5G_DIR}/gtp5g.ko" 2>&1)" \
        || modprobe gtp5g 2>/dev/null \
        || true

    if lsmod | grep -q '^gtp5g'; then
        echo "  [gtp5g] module loaded"
    else
        echo "  [gtp5g] WARNING: module not loaded — UPF will likely fail" >&2
        [[ -n "$load_err" ]] && echo "  [gtp5g] insmod error: ${load_err}" >&2
        echo "  [gtp5g] hint: check 'dmesg | tail -10' and 'mokutil --sb-state' (Secure Boot)" >&2
    fi
}

# ---------------------------------------------------------------------------
# _install_deps — install missing build dependencies via apt
# ---------------------------------------------------------------------------
_DEPS=(
    git wget curl make gcc g++ clang cmake autoconf libtool pkg-config
    build-essential libmnl-dev libyaml-dev
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
# setup — clone, checkout version, build
# ---------------------------------------------------------------------------
cmd_setup() {
    echo "=== Setting up free5GC ${VERSION} ==="

    echo "--- Checking / installing MongoDB ---"
    _install_mongodb

    echo "--- Checking / installing Go toolchain ---"
    _install_go
    export PATH="/usr/local/go/bin:${PATH}"

    echo "--- Checking build dependencies ---"
    _install_deps

    echo "--- Installing gtp5g kernel module (for UPF) ---"
    _install_gtp5g

    # Clone if not present; otherwise fetch all refs (tags + branches)
    if [[ ! -d "${FREE5GC_DIR}/.git" ]]; then
        echo "  Cloning ${FREE5GC_REPO} → ${FREE5GC_DIR} ..."
        git clone --recurse-submodules "${FREE5GC_REPO}" "${FREE5GC_DIR}"
    else
        echo "  Repo already exists at ${FREE5GC_DIR} — fetching all refs ..."
        git -C "${FREE5GC_DIR}" fetch --all --tags --quiet
        git -C "${FREE5GC_DIR}" submodule update --init --recursive --quiet
    fi

    # Checkout requested version (tag, branch, or commit SHA)
    echo "  Checking out ${VERSION} ..."
    git -C "${FREE5GC_DIR}" checkout "${VERSION}"
    # If VERSION is a remote branch, fast-forward to its latest commit
    if git -C "${FREE5GC_DIR}" show-ref --verify --quiet "refs/remotes/origin/${VERSION}"; then
        echo "  Fast-forwarding branch ${VERSION} to origin/${VERSION} ..."
        git -C "${FREE5GC_DIR}" reset --hard "origin/${VERSION}"
    fi
    git -C "${FREE5GC_DIR}" submodule update --init --recursive

    # The Makefile hardcodes CGO_ENABLED=0 inline in each recipe, which cannot be
    # overridden by environment variables — patch it to 1 before building with ASAN.
    echo "  Patching Makefile: CGO_ENABLED=0 → CGO_ENABLED=1 ..."
    sed -i 's/CGO_ENABLED=0/CGO_ENABLED=1/g' "${FREE5GC_DIR}/Makefile"

    # Build all NFs with ASAN
    echo "  Building with ASAN (GOFLAGS=-asan  CGO_CFLAGS/LDFLAGS=-fsanitize=address) ..."
    (
        cd "${FREE5GC_DIR}"
        export PATH="/usr/local/go/bin:${PATH}"
        CGO_CFLAGS="-fsanitize=address -g" \
        CGO_LDFLAGS="-fsanitize=address" \
        GOFLAGS="-asan" \
        make
    )

    echo ""
    echo "=== ASAN build complete: ${BIN_DIR} ==="
    echo "    Run: sudo $0 start ${VERSION}"
}

# ---------------------------------------------------------------------------
# start
# ---------------------------------------------------------------------------
cmd_start() {
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: must be run as root (UPF needs TUN/GTP). Use: sudo $0 start ${VERSION}" >&2
        exit 1
    fi

    if [[ ! -d "${BIN_DIR}" ]]; then
        echo "ERROR: bin directory not found: ${BIN_DIR}" >&2
        echo "       Run: $0 setup ${VERSION}" >&2
        exit 1
    fi

    echo "=== Starting free5GC ${VERSION} NFs ==="
    mkdir -p "${LOG_DIR}" "${PID_DIR}"
    _ensure_mongodb || true

    # ASAN: log crashes to file; don't halt so all NFs keep running during fuzzing.
    # detect_leaks=0: Go's GC confuses ASAN's leak detector — disable to avoid false positives.
    export ASAN_OPTIONS="${ASAN_OPTIONS:-halt_on_error=0:abort_on_error=0:detect_leaks=0:log_path=${LOG_DIR}/asan}"
    export UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=0:print_stacktrace=1:log_path=${LOG_DIR}/ubsan}"

    # Ensure gtp5g is loaded (UPF will crash without it)
    if ! lsmod | grep -q '^gtp5g'; then
        echo "  [gtp5g] module not loaded — attempting to load ..."
        _install_gtp5g || true
    fi

    local nfs_list=("${NFS[@]}")
    [[ -x "$(_binary chf)" ]] && nfs_list+=(chf)

    for nf in "${nfs_list[@]}"; do
        # COVERAGE: launch this NF from its -cover binary with a per-NF GOCOVERDIR.
        local bin gcd=""
        if _is_cover_nf "$nf"; then
            bin="$(_cover_binary "$nf")"
            gcd="${COV_DIR}/${nf}"
            mkdir -p "$gcd"
            printf "  [%s] COVERAGE binary + GOCOVERDIR=%s\n" "$nf" "$gcd"
        else
            bin="$(_binary "$nf")"
        fi
        local cfg; cfg="$(_config "$nf")"
        local log; log="$(_logfile "$nf")"
        local pf;  pf="$(_pidfile "$nf")"

        if ! [[ -x "$bin" ]]; then
            echo "  [${nf}] ERROR: binary not found at ${bin}" >&2
            _is_cover_nf "$nf" && echo "       run: sudo $0 build-cover ${VERSION} ${nf}" >&2
            continue
        fi
        if ! [[ -f "$cfg" ]]; then
            echo "  [${nf}] ERROR: config not found at ${cfg}" >&2; continue
        fi

        # Stop any existing instance before starting fresh
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
        _kill_by_name "$nf"

        # Run from FREE5GC_DIR so NFs can resolve relative paths in configs;
        # exec replaces the subshell so $! is the actual NF pid.
        # SMF also needs --uerouting; all NFs accept --config and -l.
        local extra_args=()
        [[ "$nf" == "smf" && -f "$(_uerouting)" ]] && extra_args+=(--uerouting "$(_uerouting)")
        # For a cover NF, export its GOCOVERDIR only in that NF's exec environment.
        (cd "${FREE5GC_DIR}" && { [[ -n "$gcd" ]] && export GOCOVERDIR="$gcd"; }; \
            exec "$bin" --config "$cfg" -l "$log" "${extra_args[@]}") >> "$log" 2>&1 &
        local pid=$!
        disown "$pid" 2>/dev/null || true
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

    # Make ASAN log files world-readable so the fuzzer can read stack traces.
    # ASAN writes logs as root:root 640; a background loop chmod-fixes new files.
    (while sleep 2; do chmod 644 "${LOG_DIR}"/asan.* "${LOG_DIR}"/ubsan.* 2>/dev/null || true; done) &
    disown $! 2>/dev/null || true

    # Give slow-starting NFs a grace period, then report any that died
    sleep 1
    for nf in "${nfs_list[@]}"; do
        local pf; pf="$(_pidfile "$nf")"
        [[ -f "$pf" ]] || continue
        local pid; pid="$(cat "$pf" 2>/dev/null)" || continue
        kill -0 "$pid" 2>/dev/null && continue
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
    echo "=== Stopping free5GC ${VERSION} NFs ==="

    local nfs_list=("${NFS[@]}")
    [[ -x "$(_binary chf)" ]] && nfs_list+=(chf)

    local reversed=()
    for (( i=${#nfs_list[@]}-1; i>=0; i-- )); do reversed+=("${nfs_list[$i]}"); done

    for nf in "${reversed[@]}"; do
        local pid; pid="$(_running_pid "$nf" 2>/dev/null)" || true
        if [[ -z "$pid" ]]; then
            if pgrep -f "${BIN_DIR}/${nf}" >/dev/null 2>&1; then
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
    [chf]="96"
)

cmd_watch() {
    local errors_only=0
    [[ "${3:-}" == "--errors" ]] && errors_only=1

    local all_nfs=("${NFS[@]}" chf)
    local found=0
    for nf in "${all_nfs[@]}"; do [[ -f "$(_logfile "$nf")" ]] && { found=1; break; }; done
    if (( found == 0 )); then
        echo "No log files found in ${LOG_DIR} — run 'start ${VERSION}' first." >&2; exit 1
    fi

    if (( errors_only )); then
        echo "=== free5GC ${VERSION} logs  [FATAL/ERROR/WARN only — Ctrl+C to stop] ==="
    else
        echo "=== free5GC ${VERSION} logs  [all lines — Ctrl+C to stop] ==="
    fi
    echo

    local watch_pids=()
    for nf in "${all_nfs[@]}"; do
        local log; log="$(_logfile "$nf")"
        [[ -f "$log" ]] || continue
        local color="${_NF_COLOR[$nf]:-37}"
        (
            tail -n 5 -f "$log" 2>/dev/null | while IFS= read -r line; do
                local plain; plain="$(printf '%s' "$line" | sed 's/\x1b\[[0-9;]*m//g')"

                # Skip structured-format duplicate lines (free5GC logs each event
                # twice: time="..." then [WARN][NF][Cat]).  Only show bracket format.
                [[ "$plain" =~ ^time= ]] && continue

                local sev_color=""
                # FATAL — open5GS: FATAL/assert/crash  free5GC: [FATA]/panic:/crash
                if [[ "$plain" =~ FATAL|\[FATA\]|panic:|Segmentation.fault|core.dumped|SIGABRT|SIGSEGV ]]; then
                    sev_color="\e[1;31m"
                # ERROR — open5GS: ] ERROR  free5GC: [ERRO]
                elif [[ "$plain" =~ \]\ ERROR|[[:space:]]ERROR[[:space:]]|\[ERRO\]|level=\"error\" ]]; then
                    sev_color="\e[31m"
                # WARN — open5GS: ] WARN   free5GC: [WARN]
                elif [[ "$plain" =~ \]\ WARN|[[:space:]]WARN[[:space:]]|\[WARN\]|level=\"warning\" ]]; then
                    sev_color="\e[33m"
                fi

                (( errors_only )) && [[ -z "$sev_color" ]] && continue

                local msg; msg="$(printf '%s' "$plain" | sed 's/^[0-9T:/\.\-]*Z* *//')"
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
        echo "  nf-name: one of ${NFS[*]} chf" >&2
        exit 1
    fi
    nf="${nf,,}"  # lowercase

    # Coverage mode (F5GC_COVER=1): launch the -cover binary and point GOCOVERDIR
    # at this NF's coverage dir.  Go writes the profile on graceful exit (SIGTERM →
    # the NF returns from main), so 'stop'/restart flush automatically.
    local bin
    if [[ "${F5GC_COVER:-0}" == "1" ]]; then
        bin="$(_cover_binary "$nf")"
        export GOCOVERDIR="${COV_DIR}/${nf}"
        mkdir -p "${GOCOVERDIR}"
        echo "[${nf}] COVERAGE mode — GOCOVERDIR=${GOCOVERDIR}"
        if ! [[ -x "$bin" ]]; then
            echo "ERROR: cover binary not found: ${bin} — run: sudo $0 build-cover ${VERSION} ${nf}" >&2
            exit 1
        fi
    else
        bin="$(_binary "$nf")"
    fi
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

    local extra_args=()
    [[ "$nf" == "smf" && -f "$(_uerouting)" ]] && extra_args+=(--uerouting "$(_uerouting)")
    (cd "${FREE5GC_DIR}" && exec "$bin" --config "$cfg" -l "$log" "${extra_args[@]}") >> "$log" 2>&1 &
    local pid=$!
    disown "$pid" 2>/dev/null || true
    echo "$pid" > "$pf"

    (while sleep 2; do chmod 644 "${LOG_DIR}"/asan.* "${LOG_DIR}"/ubsan.* 2>/dev/null || true; done) &
    disown $! 2>/dev/null || true

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
# Go coverage:  build-cover → start-cover → (run fuzzer) → stop → coverage
#
# free5GC is Go, so ASAN/crash-count is a poor success metric — a robust NF can
# absorb a whole campaign with 0 crashes.  Coverage answers "how much of the NF
# did we actually exercise?".  A -cover binary writes its profile to GOCOVERDIR
# on graceful exit (SIGTERM), which 'stop' sends — no source changes needed.
# NOTE: plain `-cover` (no -coverpkg) is required so the main package is
# instrumented too; otherwise Go never registers the exit hook and nothing flushes.
# ---------------------------------------------------------------------------
cmd_build_cover() {
    local nf="${3:-}"
    if [[ -z "$nf" ]]; then
        echo "Usage: $0 build-cover <version> <nf-name>" >&2
        echo "  nf-name: one of ${NFS[*]} chf" >&2
        exit 1
    fi
    nf="${nf,,}"
    local src="${FREE5GC_DIR}/NFs/${nf}/cmd"
    if ! [[ -f "${src}/main.go" ]]; then
        echo "ERROR: ${src}/main.go not found — is free5GC set up?" >&2; exit 1
    fi
    export PATH="/usr/local/go/bin:${PATH}"

    # Inject the on-demand coverage dumper.  Build-tagged 'coverage', so it is
    # compiled in ONLY for cover builds (normal `make` builds exclude it and stay
    # clean).  On SIGUSR2 it snapshots Go coverage counters to GOCOVERDIR while the
    # NF keeps running — the Go analog of open5GS's SIGUSR2 __gcov_dump.  This is
    # what lets the fuzzer read coverage *during* a campaign (online mode).
    cat > "${src}/zz_cover_dump.go" <<'GOEOF'
//go:build coverage

package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime/coverage"
	"syscall"
	"time"
)

// init registers a SIGUSR2 handler that flushes current coverage counters to
// $GOCOVERDIR without exiting.  Meta-data is written once up front.  Each dump
// appends a line to $GOCOVERDIR/_dump.log so the fuzzer (and humans) can confirm
// the online dump is firing.
func init() {
	dir := os.Getenv("GOCOVERDIR")
	if dir == "" {
		return
	}
	logln := func(s string) {
		if f, e := os.OpenFile(dir+"/_dump.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); e == nil {
			fmt.Fprintf(f, "%s %s\n", time.Now().Format(time.RFC3339Nano), s)
			f.Close()
		}
	}
	if e := coverage.WriteMetaDir(dir); e != nil {
		logln("meta ERR: " + e.Error())
	} else {
		logln("meta ok")
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR2)
	go func() {
		for range ch {
			if e := coverage.WriteCountersDir(dir); e != nil {
				logln("counters ERR: " + e.Error())
			} else {
				logln("counters ok")
			}
		}
	}()
}
GOEOF

    # -covermode=atomic is REQUIRED for on-demand WriteCountersDir mid-run (the
    # default -covermode=set rejects it) and is the correct mode for a concurrent
    # server.  -tags coverage pulls in the SIGUSR2 dumper above.
    # Build the cmd PACKAGE ('.'), not 'main.go' alone — `go build main.go`
    # compiles only that one file and ignores sibling files, so the build-tagged
    # zz_cover_dump.go (SIGUSR2 dumper) would never be included.  Building the
    # directory pulls in all package-main files.
    echo "  [cover] building ${nf} with -cover -covermode=atomic -tags coverage → $(_cover_binary "$nf") ..."
    ( cd "$src" && CGO_ENABLED=1 GOFLAGS=-mod=mod \
        go build -cover -covermode=atomic -tags coverage -o "$(_cover_binary "$nf")" . )
    if [[ -x "$(_cover_binary "$nf")" ]]; then
        echo "  [cover] built $(_cover_binary "$nf")"
        echo "  Next: sudo $0 start-cover ${VERSION} ${nf}"
    else
        echo "  [cover] BUILD FAILED" >&2; exit 1
    fi
}

cmd_start_cover() {
    # Reuse all of start-nf's start/stop/pidfile logic via the F5GC_COVER flag.
    F5GC_COVER=1 cmd_start_nf "$@"
}

cmd_coverage() {
    local nf="${3:-}"
    if [[ -z "$nf" ]]; then
        echo "Usage: $0 coverage <version> <nf-name> [--func]" >&2
        exit 1
    fi
    nf="${nf,,}"
    export PATH="/usr/local/go/bin:${PATH}"
    local dir="${COV_DIR}/${nf}"
    if ! ls "${dir}"/covmeta.* >/dev/null 2>&1; then
        echo "ERROR: no coverage data in ${dir}." >&2
        echo "  Did you 'start-cover' then 'stop' (graceful flush) this NF?" >&2
        exit 1
    fi
    echo "=== ${nf} coverage  (GOCOVERDIR=${dir}) ==="
    go tool covdata percent -i="${dir}"
    if [[ "${4:-}" == "--func" ]]; then
        echo "=== per-function (uncovered first) ==="
        go tool covdata func -i="${dir}" | sort -t$'\t' -k3 -n | head -60
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
    start-nf) cmd_start_nf "$@"      ;;
    build-cover) cmd_build_cover "$@" ;;
    start-cover) cmd_start_cover "$@" ;;
    coverage)    cmd_coverage "$@"    ;;
    *)
        cat <<EOF
Usage: $0 <command> [version]

Commands:
  setup      [version]             clone free5GC, checkout version, ASAN build
  start      [version]             start all NFs (requires root)
  stop       [version]             stop all NFs
  restart    [version]             stop then start
  status     [version]             show running/down status
  watch      [version] [--errors]  tail all NF logs (Ctrl+C to stop)
  start-nf   <version> <nf>        restart a single NF (for fuzzer --amf-restart-cmd)
  build-cover <version> <nf>       build a Go-coverage-instrumented <nf>_cover binary
  start-cover <version> <nf>       run <nf>_cover with GOCOVERDIR set (for coverage runs)
  coverage    <version> <nf> [--func]  report Go coverage % for <nf> (after stop)

version defaults to the latest release on GitHub.  free5GC is cloned to ${FREE5GC_DIR}.

Coverage workflow (free5GC is Go — measure code reached, not just crashes).
UDM depends on NRF (registration) and UDR (auth lookup), so the WHOLE stack must
run; only the target NF needs instrumenting.  Use COVER_NFS to bring the full
stack up with just the target NF built from its -cover binary:
  sudo $0 build-cover main udm                       # one-time instrumented build
  sudo COVER_NFS=udm $0 start main                   # full stack, udm instrumented
                                                     # (COVER_NFS goes AFTER sudo, else
                                                     #  sudo strips it from the env)
  CORE=free5gc RESTART_CMD='sudo scripts/free5gc.sh start-cover main udm' \\
      ./scripts/fuzz_udm.sh                           # run the campaign (cover-aware restart)
  sudo $0 stop main                                  # graceful exit flushes coverage
  $0 coverage main udm --func                        # report % + per-function gaps

  (start-cover/start-nf only (re)start ONE NF — handy to swap the target into an
   already-running stack, but they do NOT start NRF/UDR/etc.)

ASAN is always enabled.  ASAN_OPTIONS and UBSAN_OPTIONS are exported automatically
at start time; crash reports land in ${LOG_DIR}/asan.<pid>.

NFs managed: ${NFS[*]} [chf — auto-detected, v3.4+]

Examples:
  sudo $0 setup
  sudo $0 setup v3.4.3
  sudo $0 start
  $0 watch --errors
  $0 status
  sudo $0 start-nf v3.4.3 amf
EOF
        exit 1
        ;;
esac
