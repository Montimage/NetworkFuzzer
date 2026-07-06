#!/usr/bin/env bash
# open5gs.sh — Clone, build (ASAN or gcov), and manage open5GS network functions
#
# Usage:
#   ./open5gs.sh setup   [version] [--gcov]    clone + checkout + ASAN build
#                                               --gcov: build with gcov coverage instead of ASAN
#   ./open5gs.sh start   [version] [--gcov]    start all NFs  (requires root)
#                                               --gcov: preload gcov_ctrl.so for signal-driven reset/dump
#   ./open5gs.sh stop    [version]             stop all NFs
#   ./open5gs.sh restart [version] [--gcov]    stop then start
#   ./open5gs.sh status  [version]             show running/down status
#   ./open5gs.sh watch   [version] [--errors]  tail all NF logs
#   ./open5gs.sh gcov-report [version]         generate lcov HTML coverage report
#
# version defaults to the latest release on GitHub.  open5GS is cloned to ~/open5gs.
#
# gcov notes:
#   --gcov is mutually exclusive with ASAN (instrumentation conflict).
#   .gcda files are written to BUILD_DIR/src/<nf>/ as each NF runs.
#   Use NfMonitor.gcov_reset() / gcov_dump() to snapshot coverage per request.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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

# --gcov flag: scan all arguments (can appear in any position after command)
GCOV_BUILD=0
for _arg in "$@"; do [[ "$_arg" == "--gcov" ]] && GCOV_BUILD=1; done

if [[ -z "$VERSION" || "$VERSION" == "--gcov" ]]; then
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

# gcov artefacts
GCOV_SO="${BUILD_DIR}/gcov_ctrl.so"
GCOV_GCDA_DIR="${BUILD_DIR}/src"       # where .gcda files accumulate at runtime

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

_normalize_nrf_uri() {
    # The open5GS NF config templates in this tree default their NRF *client* URI
    # to http://127.0.0.200:7777 — an SCP/indirect-communication address that the
    # 'main' profile never starts.  Left as-is, no NF can register with or be
    # discovered through NRF (PCF/SMF policy creates then hang), and a meson
    # rebuild regenerates the broken value.  Rewrite each NF's ACTIVE (non-
    # commented) NRF client URI to the address NRF actually binds, so direct
    # NF↔NRF communication works without manual edits after every rebuild.
    local nrf_cfg; nrf_cfg="$(_config nrf)"
    [[ -f "$nrf_cfg" ]] || return 0
    # NRF bind address = first sbi.server 'address:' in nrf.yaml
    local nrf_addr
    nrf_addr="$(grep -A8 'sbi:' "$nrf_cfg" \
        | grep -m1 -E '^[[:space:]]*-?[[:space:]]*address:' \
        | sed -E 's/.*address:[[:space:]]*//; s/[[:space:]]*$//')"
    [[ -n "$nrf_addr" ]] || nrf_addr="127.0.0.10"
    local fixed=0
    for nf in "${NFS[@]}"; do
        local cfg; cfg="$(_config "$nf")"
        [[ -f "$cfg" ]] || continue
        # Only touch active lines (commented '#  - uri:' lines are not matched by
        # the '- uri:' anchor) that point somewhere other than the real NRF addr.
        if grep -qE "^[[:space:]]*- uri: http://127\.0\.0\.200:7777" "$cfg"; then
            sed -i -E "s|^([[:space:]]*)- uri: http://127\.0\.0\.200:7777|\1- uri: http://${nrf_addr}:7777|" "$cfg"
            fixed=1
        fi
    done
    (( fixed )) && echo "  [config] normalized NRF client URI -> http://${nrf_addr}:7777"
    return 0
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
_DEPS_GCOV=(lcov)

_install_deps() {
    local want=("${_DEPS[@]}")
    (( GCOV_BUILD )) && want+=("${_DEPS_GCOV[@]}")

    local missing=()
    for pkg in "${want[@]}"; do
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
# setup — clone, checkout version, build (ASAN by default; gcov with --gcov)
# ---------------------------------------------------------------------------
cmd_setup() {
    if (( GCOV_BUILD )); then
        echo "=== Setting up open5GS ${VERSION} [gcov + UBSan build] ==="
        echo "    NOTE: ASAN disabled (gcov/ASAN conflict). UBSan retained for crash detection."
    else
        echo "=== Setting up open5GS ${VERSION} [ASAN + UBSan build] ==="
    fi

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
        git -C "${OPEN5GS_DIR}" fetch --all --tags --quiet
    fi

    # Checkout requested version (tag, branch, or commit SHA)
    echo "  Checking out ${VERSION} ..."
    git -C "${OPEN5GS_DIR}" checkout "${VERSION}"
    # If VERSION is a remote branch, fast-forward to its latest commit
    if git -C "${OPEN5GS_DIR}" show-ref --verify --quiet "refs/remotes/origin/${VERSION}"; then
        echo "  Fast-forwarding branch ${VERSION} to origin/${VERSION} ..."
        git -C "${OPEN5GS_DIR}" reset --hard "origin/${VERSION}"
    fi

    # Configure with meson (reconfigure if build dir already exists)
    echo "  Configuring ${BUILD_DIR} ..."
    (
        cd "${OPEN5GS_DIR}"
        if (( GCOV_BUILD )); then
            # ASAN conflicts with gcov (allocator init order); UBSan is compatible.
            # UBSan with halt_on_error=1 aborts on UB → pgrep detects the crash.
            _MESON_EXTRA=(-Db_coverage=true -Db_sanitize=undefined -Db_lundef=false)
        else
            _MESON_EXTRA=(-Db_sanitize=address,undefined -Db_lundef=false)
        fi
        if [[ -f "${BUILD_DIR}/build.ninja" ]]; then
            meson setup "build_${VERSION}" \
                --buildtype=debug \
                "${_MESON_EXTRA[@]}" \
                --prefix="$(pwd)/install" \
                --reconfigure
        else
            mkdir -p "build_${VERSION}"
            meson setup "build_${VERSION}" \
                --buildtype=debug \
                "${_MESON_EXTRA[@]}" \
                --prefix="$(pwd)/install"
        fi
    )

    # Build
    echo "  Building with ninja ..."
    ninja -C "${BUILD_DIR}"

    # Install to prefix so NFs find their configs (freeDiameter, TLS certs, etc.)
    echo "  Installing to $(pwd)/install ..."
    ninja -C "${BUILD_DIR}" install

    # Build gcov_ctrl.so (signal-driven counter reset/dump for per-request coverage)
    if (( GCOV_BUILD )); then
        _build_gcov_ctrl
    fi

    # Return build directory ownership to the invoking user so gcov can write
    # temporary .gcov files during gcovr analysis (build ran as root via sudo).
    if [[ -n "${SUDO_USER:-}" ]]; then
        echo "  Fixing build directory ownership → ${SUDO_USER} ..."
        chown -R "${SUDO_USER}:${SUDO_USER}" "${BUILD_DIR}"
        chown -R "${SUDO_USER}:${SUDO_USER}" "${OPEN5GS_DIR}/install" 2>/dev/null || true
    fi

    echo ""
    if (( GCOV_BUILD )); then
        echo "=== gcov build complete: ${BUILD_DIR} ==="
        echo "    .gcda files will accumulate in: ${GCOV_GCDA_DIR}/"
        echo "    gcov_ctrl.so: ${GCOV_SO}"
        echo "    Run: sudo $0 start ${VERSION} --gcov"
        echo "    Coverage report: $0 gcov-report ${VERSION}"
    else
        echo "=== Build complete: ${BUILD_DIR} ==="
        echo "    Run: sudo $0 start ${VERSION}"
    fi
}

_build_gcov_ctrl() {
    local src="${SCRIPT_DIR}/gcov_ctrl.c"
    if [[ ! -f "$src" ]]; then
        echo "  WARNING: gcov_ctrl.c not found at ${src} — skipping gcov_ctrl.so build" >&2
        return 0
    fi
    echo "  Building gcov_ctrl.so → ${GCOV_SO} ..."
    # -ldl: dlsym(RTLD_NEXT, "sigaction") for the crash-flush sigaction interposer.
    gcc -shared -fPIC -O0 -o "${GCOV_SO}" "${src}" -ldl -lgcov
    echo "  gcov_ctrl.so built successfully"
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

    if (( GCOV_BUILD )); then
        echo "=== Starting open5GS ${VERSION} NFs [gcov mode] ==="
    else
        echo "=== Starting open5GS ${VERSION} NFs ==="
    fi
    mkdir -p "${LOG_DIR}" "${PID_DIR}"
    _ensure_mongodb || true
    _normalize_nrf_uri || true

    if (( GCOV_BUILD )); then
        if [[ ! -f "${GCOV_SO}" ]]; then
            echo "  WARNING: gcov_ctrl.so not found at ${GCOV_SO}" >&2
            echo "           Run: $0 setup ${VERSION} --gcov   (to build it first)" >&2
        else
            export LD_PRELOAD="${GCOV_SO}${LD_PRELOAD:+:${LD_PRELOAD}}"
            echo "  LD_PRELOAD=${LD_PRELOAD}"
            echo "  .gcda dir : ${GCOV_GCDA_DIR}"
        fi
        # UBSan: abort on undefined behaviour so pgrep-based detect_crash() fires.
        # halt_on_error=1 turns UB into SIGABRT; print_stacktrace writes to log.
        # suppressions: skip the benign MHD alignment false positive that otherwise
        # kills the metrics-enabled NFs (amf/smf/upf/pcf) at startup. See ubsan.supp.
        unset ASAN_OPTIONS 2>/dev/null || true
        export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1:suppressions=${SCRIPT_DIR}/ubsan.supp:log_path=${LOG_DIR}/ubsan"
        # Enable core dumps for post-hoc analysis of any crash
        ulimit -c unlimited 2>/dev/null || true
        echo "  UBSan     : halt_on_error=1 (log: ${LOG_DIR}/ubsan.*)"
        echo "  Core dumps: enabled ($(cat /proc/sys/kernel/core_pattern))"
    else
        # ASAN: log crashes to file, don't halt so all NFs keep running
        # detect_odr_violation=0: suppress freeDiameter false positive (multiple .fdx plugins
        # each define fd_ext_depends; ASAN flags it as ODR violation but it is harmless).
        export ASAN_OPTIONS="${ASAN_OPTIONS:-halt_on_error=0:abort_on_error=0:detect_leaks=0:detect_odr_violation=0:log_path=${LOG_DIR}/asan}"
        export UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=0:print_stacktrace=1:log_path=${LOG_DIR}/ubsan}"
    fi

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

    # Make ASAN log files world-readable so the fuzzer can read stack traces.
    # ASAN writes logs as root:root 640; a background loop chmod-fixes new files.
    (while sleep 2; do chmod 644 "${LOG_DIR}"/asan.* 2>/dev/null || true; done) &
    disown $! 2>/dev/null || true

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
# gcov-watch — live terminal coverage summary, updating as .gcda files change
# ---------------------------------------------------------------------------
cmd_gcov_watch() {
    local nf_filter="${3:-}"   # optional: nrf, amf, smf, … — defaults to all NFs
    local interval="${4:-10}"  # refresh interval in seconds (default 10)

    if ! command -v lcov >/dev/null 2>&1; then
        echo "ERROR: lcov not found. Install with: sudo apt-get install lcov" >&2
        exit 1
    fi
    if [[ ! -d "${GCOV_GCDA_DIR}" ]]; then
        echo "ERROR: .gcda directory not found: ${GCOV_GCDA_DIR}" >&2
        echo "       Run: sudo $0 setup ${VERSION} --gcov && sudo $0 start ${VERSION} --gcov" >&2
        exit 1
    fi

    # Restrict watch directory to the NF subdirectory when requested
    local watch_dir="${GCOV_GCDA_DIR}"
    [[ -n "$nf_filter" ]] && watch_dir="${GCOV_GCDA_DIR}/${nf_filter}"

    if [[ -n "$nf_filter" ]]; then
        echo "=== gcov live watch — NF: ${nf_filter}  (Ctrl+C to stop) ==="
    else
        echo "=== gcov live watch — all NFs  (Ctrl+C to stop) ==="
    fi

    local gcda_count
    gcda_count=$(find "${watch_dir}" -name '*.gcda' 2>/dev/null | wc -l)
    if (( gcda_count == 0 )); then
        echo ""
        echo "  WARNING: no .gcda files in ${watch_dir}"
        echo "  Ensure open5GS was built and started with --gcov, then run the fuzzer."
        echo "  Waiting for .gcda files..."
        echo ""
    else
        echo "  found ${gcda_count} .gcda file(s) in ${watch_dir}"
        echo ""
    fi

    # Export vars used by _lcov_print_summary inside the pipe subshell
    export _GCOV_BUILD_DIR="${BUILD_DIR}"
    export _GCOV_ROOT="${OPEN5GS_DIR}"
    export _GCOV_NF_FILTER="${nf_filter}"

    if command -v inotifywait >/dev/null 2>&1; then
        echo "  mode: inotifywait (rerenders on each .gcda write)"
        echo ""
        _lcov_print_summary
        inotifywait -m -r -e close_write "${watch_dir}" \
            --include '.*\.gcda$' -q \
        | while read -r _ _ _; do
            _lcov_print_summary
        done
    else
        echo "  mode: polling every ${interval}s"
        echo ""
        while true; do
            _lcov_print_summary
            sleep "${interval}"
        done
    fi
}

_lcov_print_summary() {
    printf '─%.0s' {1..78}; echo ""
    echo "  $(date '+%H:%M:%S')  gcov coverage — open5GS ${VERSION:-}"
    printf '─%.0s' {1..78}; echo ""

    # Use PID-unique temp file to avoid conflicts with parallel runs
    local info="/tmp/gcov-watch-live-$$.info"
    local obj_dir="${_GCOV_BUILD_DIR}"
    [[ -n "${_GCOV_NF_FILTER:-}" ]] && obj_dir="${_GCOV_BUILD_DIR}/src/${_GCOV_NF_FILTER}"

    # Capture coverage — suppress verbose progress but show errors
    local lcov_err
    lcov_err="$(lcov --capture \
         --directory    "${obj_dir}" \
         --base-directory "${_GCOV_ROOT}" \
         --output-file  "${info}" \
         --gcov-tool    gcov \
         --ignore-errors source,gcov \
         2>&1 >/dev/null)" || true

    if [[ ! -s "${info}" ]]; then
        echo "  No coverage data — NF may not be running with --gcov, or no SIGUSR2 dump yet."
        [[ -n "${lcov_err}" ]] && echo "  lcov: ${lcov_err}" | tail -2
        rm -f "${info}"
        return
    fi

    # Filter to NF source files only when requested
    if [[ -n "${_GCOV_NF_FILTER:-}" ]]; then
        lcov --extract "${info}" \
             "*/src/${_GCOV_NF_FILTER}/*" \
             --output-file "${info}" \
             --ignore-errors source \
             >/dev/null 2>&1 || true
        if [[ ! -s "${info}" ]]; then
            echo "  No data for '${_GCOV_NF_FILTER}' after filter — SIGUSR2 not yet received?"
            rm -f "${info}"
            return
        fi
    fi

    # Display summary — || true prevents pipefail exit when grep has no output
    lcov --summary "${info}" 2>&1 | grep -v '^Reading' || true
    rm -f "${info}"
}

# ---------------------------------------------------------------------------
# gcov-report — generate lcov HTML coverage report from accumulated .gcda data
# ---------------------------------------------------------------------------
cmd_gcov_report() {
    if ! command -v lcov >/dev/null 2>&1; then
        echo "ERROR: lcov not found. Install with: sudo apt-get install lcov" >&2
        exit 1
    fi
    if [[ ! -d "${GCOV_GCDA_DIR}" ]]; then
        echo "ERROR: .gcda directory not found: ${GCOV_GCDA_DIR}" >&2
        echo "       Run setup and start with --gcov first." >&2
        exit 1
    fi

    local report_dir="/tmp/open5gs-${VERSION}-gcov-report"
    local info_file="/tmp/open5gs-${VERSION}.info"

    echo "=== Generating gcov coverage report for open5GS ${VERSION} ==="
    echo "  Capturing coverage data from ${GCOV_GCDA_DIR} ..."
    lcov --capture \
         --directory "${GCOV_GCDA_DIR}" \
         --base-directory "${OPEN5GS_DIR}" \
         --output-file "${info_file}" \
         --gcov-tool gcov \
         --ignore-errors source 2>/dev/null || true

    if [[ ! -s "${info_file}" ]]; then
        echo "ERROR: lcov produced no coverage data. Are the NFs running with --gcov?" >&2
        exit 1
    fi

    # Strip system headers and test files to keep the report focused on NF code
    lcov --remove "${info_file}" \
         '/usr/*' '*/tests/*' '*/build/_deps/*' \
         --output-file "${info_file}" --ignore-errors source 2>/dev/null || true

    echo "  Generating HTML report → ${report_dir}/index.html ..."
    genhtml "${info_file}" \
            --output-directory "${report_dir}" \
            --title "open5GS ${VERSION} coverage" \
            --legend --show-details 2>/dev/null || true

    echo ""
    echo "  Coverage info : ${info_file}"
    echo "  HTML report   : ${report_dir}/index.html"
    echo ""
    echo "  Quick summary:"
    lcov --summary "${info_file}" 2>/dev/null || true
}

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
    if (( GCOV_BUILD )); then
        if [[ -f "${GCOV_SO}" ]]; then
            export LD_PRELOAD="${GCOV_SO}${LD_PRELOAD:+:${LD_PRELOAD}}"
        fi
        unset ASAN_OPTIONS 2>/dev/null || true
        export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1:suppressions=${SCRIPT_DIR}/ubsan.supp:log_path=${LOG_DIR}/ubsan"
        ulimit -c unlimited 2>/dev/null || true
    else
        export ASAN_OPTIONS="${ASAN_OPTIONS:-halt_on_error=0:abort_on_error=0:detect_leaks=0:detect_odr_violation=0:log_path=${LOG_DIR}/asan}"
        export UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=0:print_stacktrace=1:log_path=${LOG_DIR}/ubsan}"
    fi

    "$bin" -c "$cfg" -l "$log" >> "$log" 2>&1 &
    local pid=$!
    disown "$pid" 2>/dev/null || true
    echo "$pid" > "$pf"

    if ! (( GCOV_BUILD )); then
        (while sleep 2; do chmod 644 "${LOG_DIR}"/asan.* 2>/dev/null || true; done) &
        disown $! 2>/dev/null || true
    fi

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
    setup)       cmd_setup              ;;
    start)       cmd_start              ;;
    stop)        cmd_stop               ;;
    restart)     cmd_restart            ;;
    status)      cmd_status             ;;
    watch)       cmd_watch "$@"         ;;
    start-nf)    cmd_start_nf "$@"      ;;
    gcov-report) cmd_gcov_report        ;;
    gcov-watch)  cmd_gcov_watch  "$@"  ;;
    *)
        cat <<EOF
Usage: $0 <command> [version] [--gcov]

Commands:
  setup        [version] [--gcov]  clone open5GS, checkout version, build
                                   default: ASAN+UBSan build
                                   --gcov:  gcov coverage build (no ASAN)
  start        [version] [--gcov]  start all NFs (requires root)
                                   --gcov: preload gcov_ctrl.so (SIGUSR1=reset, SIGUSR2=dump)
  stop         [version]           stop all NFs
  restart      [version] [--gcov]  stop then start
  status       [version]           show running/down status
  watch        [version] [--errors] tail all NF logs (Ctrl+C to stop)
  start-nf     <version> <nf> [--gcov]  restart a single NF
  gcov-report  [version]           generate lcov HTML report from accumulated .gcda data
  gcov-watch   [version] [nf] [interval]  live terminal coverage summary (Ctrl+C to stop)
                                   nf: nrf|amf|smf|udm|… (default: all)
                                   interval: seconds between refreshes (default: 10)

version defaults to the latest release on GitHub.  open5GS is cloned to ${OPEN5GS_DIR}.

Examples:
  sudo $0 setup                          # ASAN build (default)
  sudo $0 setup v2.7.7 --gcov            # gcov coverage build
  sudo $0 start --gcov                   # start NFs with coverage instrumentation
  $0 gcov-report v2.7.7                  # generate HTML coverage report
  $0 gcov-watch  v2.7.7 nrf              # live NRF coverage in terminal
  $0 gcov-watch  v2.7.7 nrf 5           # refresh every 5 seconds
  $0 watch --errors
  $0 status
  sudo $0 start-nf v2.7.5 nrf
EOF
        exit 1
        ;;
esac
