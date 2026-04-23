#!/usr/bin/env bash
set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DISK="$REPO_ROOT/docker/falco-vm/falco-vm.qcow2"
SEED="$REPO_ROOT/docker/falco-vm/seed.iso"
PID_FILE="/tmp/falco-vm.pid"

if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        echo "VM already running (pid $PID)"
        exit 0
    else
        rm -f "$PID_FILE"
    fi
fi

if [ ! -f "$DISK" ]; then
    echo "ERROR: disk image not found at $DISK"
    exit 1
fi

echo "Booting Falco VM..."

qemu-system-x86_64 \
    -name falco-vm \
    -m 4096 \
    -smp 2 \
    -enable-kvm \
    -cpu host \
    -hda "$DISK" \
    -cdrom "$SEED" \
    -netdev user,id=net0,hostfwd=tcp::8765-:8765,hostfwd=tcp::2222-:22 \
    -device virtio-net-pci,netdev=net0 \
    -virtfs local,path="$REPO_ROOT",mount_tag=host-project,security_model=mapped,id=host-project \
    -display none \
    -serial file:/tmp/falco-vm-serial.log \
    -daemonize \
    -pidfile "$PID_FILE"

echo "VM started (pid $(cat $PID_FILE))"
echo "SSH:       ssh -p 2222 -i ~/.ssh/falco_vm -o StrictHostKeyChecking=no ubuntu@localhost"
echo "Dashboard: http://localhost:8765  (after ./start.sh --vm)"
