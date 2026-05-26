#!/usr/bin/env bash
# ella.sh — Build, manage and fuzz ella-core 5G network
#
# Snap (pre-built) commands:
#   sudo ./ella.sh setup-net              create dummy n3/n6 interfaces + N2 address
#   sudo ./ella.sh start                  start snap service + log redirect
#   sudo ./ella.sh stop                   stop snap service
#   sudo ./ella.sh restart                stop then start snap service
#   sudo ./ella.sh status                 show snap service status
#   sudo ./ella.sh watch [--errors]       tail live logs (optionally filter warn/error)
#
# Source-build (ASAN) commands:
#   sudo ./ella.sh setup [version]        clone, install Go, build with -asan
#   sudo ./ella.sh start-source           stop snap, run ASAN binary directly
#   sudo ./ella.sh stop-source            kill ASAN process
#   sudo ./ella.sh restart-source         stop-source + start-source

set -euo pipefail

# Use the invoking user's home even under sudo
if [[ -n "${SUDO_USER:-}" ]]; then
    REAL_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
else
    REAL_HOME="$HOME"
fi

SNAP_SVC="ella-core.cored"
ELLA_REPO="https://github.com/ellanetworks/core.git"
ELLA_DIR="${REAL_HOME}/ella-core"
ELLA_BINARY="${ELLA_DIR}/ella-core-asan"
ELLA_CONFIG="/var/snap/ella-core/common/core.yaml"

LOG_DIR="/tmp/ella-logs"
LOG_FILE="${LOG_DIR}/cored.log"
JOURNAL_PID="${LOG_DIR}/journal.pid"
SOURCE_PID="${LOG_DIR}/source.pid"
SESSION_KEEPER_PID="${LOG_DIR}/session_keeper.pid"

N2_ADDR="10.3.0.2"
N3_IFACE="ens5"
N3_ADDR="192.168.100.1/24"
N6_IFACE="ens3"
N6_ADDR="192.168.200.1/24"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_start_log_tail() {
    mkdir -p "$LOG_DIR"
    if [[ -f "$JOURNAL_PID" ]]; then
        kill "$(cat "$JOURNAL_PID")" 2>/dev/null || true
        rm -f "$JOURNAL_PID"
    fi
    journalctl -u "snap.${SNAP_SVC}" -f --output=cat >> "$LOG_FILE" &
    echo $! > "$JOURNAL_PID"
    echo "  Log tail PID $(cat "$JOURNAL_PID") → ${LOG_FILE}"
}

# ---------------------------------------------------------------------------
# Database seeding helpers
# ---------------------------------------------------------------------------

# Require sqlite3; install it silently if missing.
_require_sqlite3() {
    if ! command -v sqlite3 &>/dev/null; then
        echo "  Installing sqlite3..."
        apt-get install -y --no-install-recommends sqlite3 -qq 2>/dev/null
    fi
}

# Patch ella.db: replace UUID string primary keys with numeric string IDs so
# that Go's database/sql can scan them into int fields without error.
#
# Background: ella v1.10.0 stores all table primary keys as UUID TEXT values
# (e.g. "7a04a59f-fe4a-591f-9018-dc7385c9428a") but some sqlair query structs
# declare the ID field as int.  database/sql can convert "1" → int, but not a
# UUID → int, so any SELECT that returns a UUID row causes:
#   "sql: Scan error: converting driver.Value type string (...UUID...) to int"
# This crashes the NGSetup handler (hang, no response) and the UPF reconciler.
#
# Fix: delete the UUID rows and re-insert equivalent rows with id='1','2',…
# Also clear the dqlite raft log (raft.db) so it does not replay the old
# UUID inserts on the next startup.
_seed_db() {
    local DB="/var/snap/ella-core/common/data/ella.db"
    local DATA_DIR="/var/snap/ella-core/common/data"

    _require_sqlite3

    if [[ ! -f "$DB" ]]; then
        echo "  ella.db not found — skipping seed (ella will create it on first start)."
        return
    fi

    echo "  Backing up ella.db → /tmp/ella_db_backup_$(date +%Y%m%d_%H%M%S).db"
    cp "$DB" "/tmp/ella_db_backup_$(date +%Y%m%d_%H%M%S).db" 2>/dev/null || true

    # Delete the dqlite raft log so ella does not replay UUID inserts on startup.
    # For a single-node deployment this is safe: ella recreates raft.db from the
    # current ella.db state on next boot.
    echo "  Clearing raft log..."
    rm -f  "${DATA_DIR}/raft/raft.db"
    rm -rf "${DATA_DIR}/raft/snapshots"
    mkdir -p "${DATA_DIR}/raft/snapshots"

    echo "  Patching ella.db (UUID IDs → numeric IDs)..."
    sqlite3 "$DB" << 'EOSQL'
-- Temporarily switch off WAL so we get a clean single-file checkpoint.
PRAGMA journal_mode=DELETE;

-- Reset the FSM applied-index so new raft entries (starting from index 1
-- in the fresh log) are actually executed.  With lastApplied left at its
-- prior high value, every new entry has index <= lastApplied and the FSM
-- skips it (returning nil), which causes result.(int) to panic at line 181.
UPDATE fsm_state SET "lastApplied" = 0;

-- Clear tables that hold UUID primary keys (the sqlair int-scan bug triggers
-- on any SELECT that returns these rows).  Keep: operator, users, api_tokens,
-- jwt_secret, cluster_*, audit_logs, schema_version, bgp_*.
DELETE FROM ip_leases;
DELETE FROM subscribers;
DELETE FROM policies;
DELETE FROM network_slices;
DELETE FROM data_networks;
DELETE FROM profiles;
DELETE FROM home_network_keys;
DELETE FROM daily_usage;
DELETE FROM flow_reports;

-- Re-insert minimal working config with numeric string IDs.
-- database/sql converts '1' → int without error (unlike a UUID string).
-- ipv6Pool column absent on v1.10.0 snap; the v1.11.0 binary adds it via
-- migration 13 on first boot (backfills this row with DEFAULT '').
INSERT OR IGNORE INTO data_networks (id, name, ipPool, dns, mtu)
    VALUES ('1', 'internet', '10.45.0.0/22', '8.8.8.8', 1400);

INSERT OR IGNORE INTO profiles (id, name, ueAmbrUplink, ueAmbrDownlink)
    VALUES ('1', 'default', '200 Mbps', '200 Mbps');

-- SST=1 SD='' matches the default NSSAI sent by our fuzzer's NGSetup template.
INSERT OR IGNORE INTO network_slices (id, sst, sd, name)
    VALUES ('1', 1, '', 'default');

INSERT OR IGNORE INTO policies
    (id, name, profileID, sliceID, dataNetworkID, var5qi, arp, sessionAmbrUplink, sessionAmbrDownlink)
    VALUES ('1', 'default', '1', '1', '1', 9, 1, '200 Mbps', '200 Mbps');

-- Workaround for ella v1.10.0 bug (PR #1332, not yet in any snap release):
--
-- Root cause: fsm_state.lastApplied retains its prior high value across
-- raft.db deletion, so new raft entries (index 1, 2, …) satisfy
-- l.Index <= lastApplied and FSM.Apply returns nil without executing the
-- SQL.  DeleteExpiredSessions then does result.(int) on the nil return and
-- panics.  The real fix is `UPDATE fsm_state SET "lastApplied" = 0` above.
--
-- Belt-and-suspenders: also insert one pre-expired sentinel session so the
-- first cleanup always deletes ≥1 row (belt-and-suspenders for edge cases).
-- Note: user_id='0' has no matching users row; dqlite FK enforcement only
-- fires on INSERT/UPDATE, and the direct write here bypasses it.
-- Do NOT create a _keep_session_sentinel trigger — dqlite runs FK checks
-- inside its transaction, and the trigger's INSERT fails with
-- "FOREIGN KEY constraint failed", causing FSM.ApplyBatch to panic.
DROP TRIGGER IF EXISTS _keep_session_sentinel;

INSERT OR REPLACE INTO sessions (id, user_id, token_hash, created_at, expires_at)
    VALUES ('0', '0', x'00', 0, 0);

-- Ensure fuzz user exists with known credentials (roleID=1 = admin).
-- bcrypt hash for "password123" generated with cost=10.
INSERT INTO users (email, roleID, hashedPassword)
    VALUES ('fuzz@test.com', 1,
            '$2b$10$X4Li6o4weHhudJvFqmChqeCI/ZQ0mzAdJ22dp/pyUliWcDXruTgzm')
ON CONFLICT(email) DO UPDATE SET
    hashedPassword = '$2b$10$X4Li6o4weHhudJvFqmChqeCI/ZQ0mzAdJ22dp/pyUliWcDXruTgzm',
    roleID = 1;

-- Switch back to WAL for normal operation.
PRAGMA journal_mode=WAL;
EOSQL

    echo "  ella.db patched — numeric IDs installed, raft log cleared."
}

# Wait until ella's SCTP N2 listener is in LISTEN state (or timeout).
# Uses 'ss' (iproute2) to check the kernel socket table — no Python needed.
_wait_for_sctp() {
    local timeout=45
    local elapsed=0

    echo -n "  Waiting for SCTP ${N2_ADDR}:38412 to be ready"
    while ! ss -lnp 2>/dev/null | grep -q "${N2_ADDR}:38412"; do
        sleep 1
        elapsed=$((elapsed + 1))
        echo -n "."
        if [[ $elapsed -ge $timeout ]]; then
            echo " timed out after ${timeout}s"
            return 1
        fi
    done
    echo " ready (${elapsed}s)"
}

# Background loop that re-inserts the anti-panic sentinel session every 10 s.
# ella's DeleteExpiredSessions cleanup fires every 30 s; by keeping a
# pre-expired row (expires_at=0) in the table, the DELETE always matches at
# least one row, preventing the nil.(int) type-assertion panic (PR #1332 bug).
_start_session_keeper() {
    _stop_session_keeper 2>/dev/null || true
    local DB="/var/snap/ella-core/common/data/ella.db"
    (
        while true; do
            sqlite3 "$DB" \
                "INSERT OR REPLACE INTO sessions (id, user_id, token_hash, created_at, expires_at) VALUES ('0', '0', x'00', 0, 0);" \
                2>/dev/null || true
            sleep 10
        done
    ) &
    local pid=$!
    disown $pid 2>/dev/null || true
    mkdir -p "$LOG_DIR"
    echo $pid > "$SESSION_KEEPER_PID"
    echo "  Session keeper started (PID $pid)"
}

_stop_session_keeper() {
    if [[ -f "$SESSION_KEEPER_PID" ]]; then
        kill "$(cat "$SESSION_KEEPER_PID")" 2>/dev/null || true
        rm -f "$SESSION_KEEPER_PID"
    fi
}

_go_bin() {
    # Prefer Go installed by this script (/usr/local/go), then PATH
    if [[ -x /usr/local/go/bin/go ]]; then
        echo /usr/local/go/bin/go
    elif command -v go &>/dev/null; then
        command -v go
    else
        echo ""
    fi
}

_install_go() {
    local required_version="$1"   # exact version string from go.mod, e.g. "1.26.2"
    local required_minor="${required_version%%.*}"  # "1"
    required_minor="${required_version#*.}"         # "26.2"
    required_minor="${required_minor%%.*}"          # "26"

    local go="$(_go_bin)"
    if [[ -n "$go" ]]; then
        local installed_minor
        installed_minor="$("$go" version | grep -oP 'go\K[0-9]+\.[0-9]+' | cut -d. -f2)"
        if (( installed_minor >= required_minor )); then
            echo "  Go (minor ${installed_minor}) satisfies 1.${required_minor}+ requirement."
            return
        fi
        echo "  Installed Go minor ${installed_minor} < required ${required_minor}, upgrading."
    fi

    local arch
    arch="$(dpkg --print-architecture)"
    [[ "$arch" == "amd64" ]] || [[ "$arch" == "arm64" ]] || {
        echo "ERROR: Unsupported arch: $arch" >&2; exit 1
    }

    # Download the exact version stated in go.mod — no API lookup needed
    local tarball="go${required_version}.linux-${arch}.tar.gz"
    echo "  Downloading go${required_version} from go.dev/dl ..."
    curl -fsSL --max-time 120 \
        "https://go.dev/dl/${tarball}" -o "/tmp/${tarball}"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "/tmp/${tarball}"
    rm "/tmp/${tarball}"
    echo "  Go ${required_version} installed at /usr/local/go/bin/go."
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

case "${1:-status}" in

    # ── Network setup ──────────────────────────────────────────────────────
    setup-net)
        for pair in "${N3_IFACE}:${N3_ADDR}" "${N6_IFACE}:${N6_ADDR}"; do
            iface="${pair%%:*}"
            addr="${pair##*:}"
            if ! ip link show "$iface" &>/dev/null; then
                ip link add "$iface" type dummy
                echo "  Created dummy interface $iface."
            else
                echo "  $iface already exists, skipping."
            fi
            ip link set "$iface" up
            if ip addr show "$iface" | grep -q "${addr%%/*}"; then
                echo "  ${addr} already on $iface, skipping."
            else
                ip addr add "$addr" dev "$iface"
                echo "  Assigned ${addr} to $iface."
            fi
        done
        if ip addr show lo | grep -q "${N2_ADDR}/32"; then
            echo "  ${N2_ADDR} already on lo, skipping."
        else
            ip addr add "${N2_ADDR}/32" dev lo
            echo "  Added ${N2_ADDR}/32 to lo."
        fi
        echo "Network setup done."
        ;;

    # ── Source build with ASAN ─────────────────────────────────────────────
    setup)
        VERSION="${2:-}"

        echo "=== Installing build dependencies ==="
        apt-get update -qq
        apt-get install -y --no-install-recommends \
            git gcc libpcap-dev libasan8 ca-certificates curl

        echo "=== Cloning ella-core ==="
        if [[ -d "${ELLA_DIR}/.git" ]]; then
            echo "  Repo exists, fetching all refs..."
            git -C "$ELLA_DIR" fetch --all --tags
        else
            git clone "$ELLA_REPO" "$ELLA_DIR"
        fi

        # Checkout requested version/tag/commit/branch, or latest tag if none given
        if [[ -z "$VERSION" ]]; then
            VERSION="$(git -C "$ELLA_DIR" tag --sort=-version:refname | head -1)"
            [[ -z "$VERSION" ]] && VERSION="main"
            echo "  No version specified, using: ${VERSION}"
        fi
        git -C "$ELLA_DIR" checkout "$VERSION"
        # If VERSION is a remote branch, fast-forward to its latest commit
        if git -C "$ELLA_DIR" show-ref --verify --quiet "refs/remotes/origin/${VERSION}"; then
            echo "  Fast-forwarding branch ${VERSION} to origin/${VERSION} ..."
            git -C "$ELLA_DIR" reset --hard "origin/${VERSION}"
        fi
        echo "  Checked out: $VERSION"

        # Read exact Go version from go.mod so we download the right tarball
        GO_REQUIRED="$(grep '^go ' "${ELLA_DIR}/go.mod" | awk '{print $2}')"
        echo "  go.mod requires Go ${GO_REQUIRED}"

        echo "=== Installing Go ==="
        _install_go "$GO_REQUIRED"
        export PATH="/usr/local/go/bin:${PATH}"
        GO="$(_go_bin)"

        echo "=== Building with ASAN ==="
        pushd "$ELLA_DIR" > /dev/null
        CGO_ENABLED=1 "$GO" build \
            -asan \
            -o ella-core-asan \
            ./cmd/core
        popd > /dev/null

        echo ""
        echo "Build complete: ${ELLA_BINARY}"
        echo "Run 'sudo $0 start-source' to launch the ASAN binary."
        ;;

    # ── Start ASAN source binary ───────────────────────────────────────────
    start-source)
        [[ -x "$ELLA_BINARY" ]] || {
            echo "ERROR: ${ELLA_BINARY} not found. Run 'sudo $0 setup' first." >&2
            exit 1
        }
        [[ -f "$ELLA_CONFIG" ]] || {
            echo "ERROR: ${ELLA_CONFIG} not found. Install the snap first." >&2
            exit 1
        }

        # Stop snap service to free the ports
        snap stop "$SNAP_SVC" 2>/dev/null || true

        mkdir -p "$LOG_DIR"
        # Truncate old log so NfMonitor starts fresh
        > "$LOG_FILE"

        export ASAN_OPTIONS="halt_on_error=1:abort_on_error=1:log_path=${LOG_DIR}/asan"

        nohup "$ELLA_BINARY" -config "$ELLA_CONFIG" \
            >> "$LOG_FILE" 2>&1 &
        echo $! > "$SOURCE_PID"
        echo "ella-core ASAN started (PID $(cat "$SOURCE_PID"))."
        echo "  Binary:  ${ELLA_BINARY}"
        echo "  Log:     ${LOG_FILE}"
        echo "  ASAN:    ${LOG_DIR}/asan.<pid>"
        ;;

    # ── Stop ASAN source binary ────────────────────────────────────────────
    stop-source)
        if [[ -f "$SOURCE_PID" ]]; then
            local_pid="$(cat "$SOURCE_PID")"
            kill -TERM "$local_pid" 2>/dev/null || true
            # Wait up to 5s for clean exit
            for _ in {1..10}; do
                kill -0 "$local_pid" 2>/dev/null || break
                sleep 0.5
            done
            kill -KILL "$local_pid" 2>/dev/null || true
            rm -f "$SOURCE_PID"
            echo "ella-core ASAN stopped."
        else
            pkill -x ella-core-asan 2>/dev/null || true
            echo "ella-core ASAN stopped (no PID file)."
        fi
        ;;

    # ── Restart ASAN source binary ─────────────────────────────────────────
    restart-source)
        _stop_session_keeper
        "${BASH_SOURCE[0]}" stop-source || true
        snap stop "$SNAP_SVC" 2>/dev/null || true   # release the dqlite file lock
        sleep 1
        _seed_db
        "${BASH_SOURCE[0]}" start-source
        _start_session_keeper
        _wait_for_sctp
        ;;

    # ── Snap commands ──────────────────────────────────────────────────────
    start)
        snap start "$SNAP_SVC"
        _start_log_tail
        _start_session_keeper
        echo "ella-core (snap) started."
        ;;
    stop)
        _stop_session_keeper
        snap stop "$SNAP_SVC"
        if [[ -f "$JOURNAL_PID" ]]; then
            kill "$(cat "$JOURNAL_PID")" 2>/dev/null || true
            rm -f "$JOURNAL_PID"
        fi
        echo "ella-core (snap) stopped."
        ;;
    restart)
        _stop_session_keeper
        snap stop "$SNAP_SVC" || true
        sleep 1
        _seed_db
        snap start "$SNAP_SVC"
        _start_log_tail
        _start_session_keeper
        _wait_for_sctp
        echo "ella-core (snap) restarted."
        ;;
    status)
        snap services "$SNAP_SVC"
        if [[ -f "$SOURCE_PID" ]] && kill -0 "$(cat "$SOURCE_PID")" 2>/dev/null; then
            echo "ASAN source binary running (PID $(cat "$SOURCE_PID"))."
        fi
        ;;
    watch)
        mkdir -p "$LOG_DIR" && touch "$LOG_FILE"
        case "${2:-}" in
            --errors)
                tail -f "$LOG_FILE" | grep --line-buffered -E \
                    '"level":"(warn|error|fatal)"'
                ;;
            --crashes)
                tail -f "$LOG_FILE" \
                    | grep --line-buffered -E \
                        '"level":"fatal"|panic:|runtime error:|goroutine [0-9]+ \[|SIGSEGV|SIGABRT|signal: ' \
                    | grep --line-buffered -v \
                        'upf_n3_n6_entrypoint_func\|Loading bpf objects\|invalid func unknown\|failed to load eBPF\|failed to load N3'
                ;;
            *)
                tail -f "$LOG_FILE"
                ;;
        esac
        ;;

    # ── Standalone DB seed (without restart) ──────────────────────────────
    seed-db)
        # Requires ella to be stopped first (check both source binary and snap).
        if pgrep -x ella-core-asan &>/dev/null; then
            echo "ERROR: stop ella-core ASAN binary first (sudo ./ella.sh stop-source)." >&2
            exit 1
        fi
        if systemctl is-active --quiet "snap.${SNAP_SVC}" 2>/dev/null; then
            echo "ERROR: stop snap ella-core first (sudo systemctl stop snap.${SNAP_SVC})." >&2
            exit 1
        fi
        _seed_db
        echo "Done. Start ella-core to apply."
        ;;

    # ── Fetch JWT for fuzzing ──────────────────────────────────────────────
    # Logs in as fuzz@test.com / password123 and saves the token to
    # /tmp/ella-logs/jwt.token.  Prints an export command ready to copy.
    get-token)
        TOKEN_FILE="${LOG_DIR}/jwt.token"
        mkdir -p "$LOG_DIR"

        RESPONSE="$(curl -sk --http2 \
            -X POST "https://${N2_ADDR}:5002/api/v1/auth/login" \
            -H "Content-Type: application/json" \
            -d '{"email":"fuzz@test.com","password":"password123"}' 2>&1)"

        TOKEN="$(echo "$RESPONSE" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    # v1.11.0: {'result': {'token': '...'}}  (nested)
    # v1.10.0: {'token': '...'}              (flat)
    tok = d.get('token') or (d.get('result') or {}).get('token', '')
    print(tok)
except Exception:
    pass
" 2>/dev/null)"

        if [[ -z "$TOKEN" ]]; then
            echo "ERROR: login failed. Response: $RESPONSE" >&2
            exit 1
        fi

        echo "$TOKEN" > "$TOKEN_FILE"
        echo "Token saved to ${TOKEN_FILE}"
        echo ""
        echo "  export JWT=\"${TOKEN}\""
        echo ""
        echo "Run the above, then start your fuzzing campaign."
        ;;

    *)
        echo "Usage: $0 {setup-net|setup [ver]|start|stop|restart|status|watch [--errors|--crashes]|start-source|stop-source|restart-source|seed-db|get-token}" >&2
        exit 1
        ;;
esac
