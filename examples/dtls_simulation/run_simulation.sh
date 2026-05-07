#!/usr/bin/env bash
# Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# One-shot DTLS simulation driver: configure → build → mint test certs
# → run server + client → render result.txt (ASCII timeline) and
# result.svg (browser-viewable sequence diagram).
#
# Usage:
#   ./run_simulation.sh                      # default: 5 ping/pong, port 32444
#   ./run_simulation.sh --count 10           # custom payload count
#   ./run_simulation.sh --port 33333         # custom UDP port
#   ./run_simulation.sh --no-build           # reuse existing build/
#   ./run_simulation.sh --no-certs           # reuse existing certs/

set -euo pipefail

# --------------------------------------------------------------------------
# CLI parsing
# --------------------------------------------------------------------------
COUNT=5
PORT=32444
DO_BUILD=1
DO_CERTS=1
HERE="$(cd "$(dirname "$0")" && pwd)"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --count)    COUNT="$2"; shift 2 ;;
        --port)     PORT="$2";  shift 2 ;;
        --no-build) DO_BUILD=0; shift ;;
        --no-certs) DO_CERTS=0; shift ;;
        -h|--help)
            sed -n '2,12p' "$0"; exit 0 ;;
        *) echo "unknown flag: $1" >&2; exit 2 ;;
    esac
done

cd "$HERE"

# --------------------------------------------------------------------------
# Resolve OpenSSL 3 location (brew on macOS, system on Linux)
# --------------------------------------------------------------------------
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
if [[ "$(uname)" == "Darwin" ]] && command -v brew >/dev/null 2>&1; then
    BREW_OPENSSL="$(brew --prefix openssl@3 2>/dev/null || true)"
    if [[ -n "$BREW_OPENSSL" ]]; then
        OPENSSL_BIN="$BREW_OPENSSL/bin/openssl"
        export OPENSSL_ROOT_DIR="$BREW_OPENSSL"
    fi
fi

OSSL_VER=$("$OPENSSL_BIN" version | awk '{print $2}')
case "$OSSL_VER" in
    3.*) ;;
    *) echo "ERROR: OpenSSL 3.0+ required, found '$OSSL_VER'" >&2; exit 1 ;;
esac
echo "[*] OpenSSL: $OSSL_VER ($OPENSSL_BIN)"

# --------------------------------------------------------------------------
# Build
# --------------------------------------------------------------------------
if [[ $DO_BUILD -eq 1 ]]; then
    CMAKE_ARGS=()
    if [[ -n "${OPENSSL_ROOT_DIR:-}" ]]; then
        CMAKE_ARGS+=("-DOPENSSL_ROOT_DIR=$OPENSSL_ROOT_DIR")
    fi
    cmake -B build -S . "${CMAKE_ARGS[@]}" >/dev/null
    cmake --build build -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)" >/dev/null
    echo "[+] built"
fi

# --------------------------------------------------------------------------
# Certs
# --------------------------------------------------------------------------
if [[ $DO_CERTS -eq 1 ]] || [[ ! -f certs/server.pem ]]; then
    OPENSSL_BIN="$OPENSSL_BIN" ./gen_test_certs.sh ./certs >/dev/null
    echo "[+] minted test certs in $HERE/certs/"
fi

# --------------------------------------------------------------------------
# Run
# --------------------------------------------------------------------------
SERVER_LOG="$HERE/build/server.log"
CLIENT_LOG="$HERE/build/client.log"

# Free the port if a previous run left a process behind.
pkill -f "dtls_server_node.*--port $PORT" 2>/dev/null || true
sleep 0.2

./build/dtls_server_node \
    --cert certs/server.pem --key certs/server.key --ca certs/ca.pem \
    --bind 127.0.0.1 --port "$PORT" > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT

# Give the server a beat to bind.
sleep 0.5
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "ERROR: server failed to start" >&2
    cat "$SERVER_LOG" >&2
    exit 1
fi

set +e
./build/dtls_client_node \
    --cert certs/client.pem --key certs/client.key --ca certs/ca.pem \
    --server 127.0.0.1 --port "$PORT" --count "$COUNT" > "$CLIENT_LOG" 2>&1
CLIENT_RC=$?
set -e

# Allow the server to log close_notify before we kill it.
sleep 0.3
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true

# --------------------------------------------------------------------------
# Render result.txt (side-by-side ASCII timeline)
# --------------------------------------------------------------------------
RESULT_TXT="$HERE/build/result.txt"
{
    echo "DTLS round-trip simulation summary"
    echo "==================================="
    echo "port            : $PORT"
    echo "ping count      : $COUNT"
    echo "client exit     : $CLIENT_RC ($([ $CLIENT_RC -eq 0 ] && echo PASS || echo FAIL))"
    echo "openssl         : $OSSL_VER"
    echo
    echo "--- timeline (server | client) ---"
    paste -d '|' \
        <(awk '/server\]/ {print}' "$SERVER_LOG" | sed 's/^\[server\] //') \
        <(awk '/client\]/ {print}' "$CLIENT_LOG" | sed 's/^\[client\] //') \
        | column -t -s '|'
} > "$RESULT_TXT"

# --------------------------------------------------------------------------
# Render result.svg (sequence diagram)
# --------------------------------------------------------------------------
RESULT_SVG="$HERE/build/result.svg"
python3 - "$SERVER_LOG" "$CLIENT_LOG" "$RESULT_SVG" <<'PYEOF'
import re, sys
from html import escape

server_log, client_log, out_path = sys.argv[1], sys.argv[2], sys.argv[3]

# Pull events from both logs and merge in order. The simulator already
# prefixes every line with [client] / [server] so we can interleave by
# scanning each file linearly and stamping a synthetic ordinal.
events = []
def parse(log_path, side):
    with open(log_path) as f:
        for line in f:
            line = line.rstrip()
            if not line:
                continue
            events.append((side, line))

parse(server_log, "server")
parse(client_log, "client")

# Heuristic: pair sends and receives in order so the diagram has direction
# arrows. We don't need wall-clock — just narrative order.
arrows = []
def push(direction, label):
    arrows.append((direction, label))

ci = si = 0
client_lines = [e[1] for e in events if e[0] == "client"]
server_lines = [e[1] for e in events if e[0] == "server"]

# Walk through in a simple zip-style merge: most events naturally pair up
# 1:1 (client send → server receive → server send → client receive).
i = j = 0
while i < len(client_lines) or j < len(server_lines):
    if i < len(client_lines):
        cl = client_lines[i]
        if "->" in cl:
            push("c2s", cl.split("->",1)[1].strip())
            i += 1
            continue
        if "rx" in cl or "PASS" in cl or "FAIL" in cl or "handshake" in cl:
            push("note-c", cl)
            i += 1
            continue
        i += 1
    if j < len(server_lines):
        sl = server_lines[j]
        if "->" in sl:
            push("s2c", sl.split("->",1)[1].strip())
            j += 1
            continue
        if "<-" in sl or "rx" in sl or "handshake" in sl:
            push("note-s", sl)
            j += 1
            continue
        j += 1

# Layout
LANE_C, LANE_S = 120, 460
ROW_H = 28
TOP = 70
H = TOP + ROW_H * (len(arrows) + 2)

svg = []
svg.append(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 {H}" font-family="ui-monospace, monospace" font-size="11">')
svg.append('<style>.lane{stroke:#999;stroke-width:1}.act{stroke:#3a6;stroke-width:1.5;fill:none}.note{fill:#666}.lbl{fill:#222}.ok{fill:#3a6}.bad{fill:#c33}</style>')
svg.append(f'<rect width="100%" height="100%" fill="#fff"/>')
svg.append(f'<text x="{LANE_C}" y="30" text-anchor="middle" font-weight="700">DTLS client</text>')
svg.append(f'<text x="{LANE_S}" y="30" text-anchor="middle" font-weight="700">DTLS server</text>')
svg.append(f'<text x="{(LANE_C+LANE_S)/2}" y="50" text-anchor="middle" fill="#888">round-trip simulation (vsomeip feature/dtls-udp)</text>')
svg.append(f'<line class="lane" x1="{LANE_C}" y1="{TOP-10}" x2="{LANE_C}" y2="{H-20}"/>')
svg.append(f'<line class="lane" x1="{LANE_S}" y1="{TOP-10}" x2="{LANE_S}" y2="{H-20}"/>')

for idx, (kind, label) in enumerate(arrows):
    y = TOP + idx * ROW_H
    short = escape(re.sub(r'\s+', ' ', label)[:80])
    if kind == "c2s":
        svg.append(f'<line class="act" x1="{LANE_C}" y1="{y}" x2="{LANE_S}" y2="{y}" marker-end="url(#a)"/>')
        svg.append(f'<text class="lbl" x="{(LANE_C+LANE_S)/2}" y="{y-3}" text-anchor="middle">{short}</text>')
    elif kind == "s2c":
        svg.append(f'<line class="act" x1="{LANE_S}" y1="{y}" x2="{LANE_C}" y2="{y}" marker-end="url(#a)"/>')
        svg.append(f'<text class="lbl" x="{(LANE_C+LANE_S)/2}" y="{y-3}" text-anchor="middle">{short}</text>')
    elif kind == "note-c":
        cls = "ok" if "OK" in short or "PASS" in short else ("bad" if "FAIL" in short else "note")
        svg.append(f'<text class="{cls}" x="{LANE_C}" y="{y}" text-anchor="middle">⟢ {short}</text>')
    elif kind == "note-s":
        cls = "ok" if "OK" in short else ("bad" if "FAIL" in short else "note")
        svg.append(f'<text class="{cls}" x="{LANE_S}" y="{y}" text-anchor="middle">⟢ {short}</text>')

svg.append('<defs><marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#3a6"/></marker></defs>')
svg.append('</svg>')

with open(out_path, "w") as f:
    f.write("\n".join(svg))
PYEOF

# --------------------------------------------------------------------------
# Done
# --------------------------------------------------------------------------
echo
echo "=========================================="
echo " DTLS simulation: $([ $CLIENT_RC -eq 0 ] && echo 'PASS' || echo 'FAIL')"
echo "=========================================="
echo "  server log : $SERVER_LOG"
echo "  client log : $CLIENT_LOG"
echo "  text       : $RESULT_TXT"
echo "  diagram    : $RESULT_SVG"
echo
exit $CLIENT_RC
