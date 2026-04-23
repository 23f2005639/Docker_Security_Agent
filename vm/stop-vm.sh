#!/usr/bin/env bash
set -e

PID_FILE="/tmp/falco-vm.pid"

if [ ! -f "$PID_FILE" ]; then
    echo "No VM running (pid file not found)"
    exit 0
fi

PID=$(cat "$PID_FILE")

if kill -0 "$PID" 2>/dev/null; then
    echo "Stopping VM (pid $PID)..."
    kill "$PID"
    rm -f "$PID_FILE"
    echo "VM stopped"
else
    echo "VM process $PID not found (already stopped)"
    rm -f "$PID_FILE"
fi
