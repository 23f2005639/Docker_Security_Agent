#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VM_MODE=0

for arg in "$@"; do
  case "$arg" in
    --vm) VM_MODE=1 ;;
  esac
done

echo "================================================================"
echo " Container Sentinel - Starting Attack Environment"
if [ "$VM_MODE" = "1" ]; then
echo " Mode: QEMU VM (Falco enabled)"
else
echo " Mode: Local (no Falco)"
fi
echo "================================================================"
echo ""

if [ "$VM_MODE" = "1" ]; then

  echo "[1/6] Booting Falco VM..."
  "$SCRIPT_DIR/vm/launch.sh"

  echo ""
  echo "[2/6] Waiting for VM SSH to become available..."
  SSH="ssh -p 2222 -i $HOME/.ssh/falco_vm -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 ubuntu@localhost"
  TRIES=0
  until $SSH exit 2>/dev/null; do
    TRIES=$((TRIES + 1))
    if [ "$TRIES" -ge 40 ]; then
      echo "ERROR: VM did not become reachable in 120s"
      echo "Check boot log: tail /tmp/falco-vm-serial.log"
      exit 1
    fi
    echo "  Attempt $TRIES/40..."
    sleep 3
  done
  echo "  VM is up."

  echo ""
  echo "[3/6] Syncing project files and Falco config..."
  # Mount 9p share if not already mounted
  $SSH "sudo mkdir -p /mnt/host-project && (mountpoint -q /mnt/host-project || sudo mount -t 9p -o trans=virtio,version=9p2000.L host-project /mnt/host-project) 2>/dev/null || true"
  # Sync entire project (picks up falco_router.py and any new files)
  $SSH "rsync -a --exclude='docker/falco-vm' /mnt/host-project/ /home/ubuntu/project/ 2>/dev/null || true"
  $SSH "chown -R ubuntu:ubuntu /home/ubuntu/project 2>/dev/null || true"
  # Push Falco config
  $SSH "sudo mkdir -p /etc/falco/rules.d"
  $SSH "sudo cp /home/ubuntu/project/docker/falco/falco.yaml /etc/falco/falco.yaml"
  $SSH "sudo cp /home/ubuntu/project/docker/falco/rules.yaml /etc/falco/rules.d/sentinel_rules.yaml"
  echo "  Files synced."

  echo ""
  echo "[4/6] Starting Falco (modern_ebpf)..."
  $SSH "sudo pkill -x falco 2>/dev/null || true; sleep 1; sudo falco -o engine.kind=modern_ebpf -c /etc/falco/falco.yaml < /dev/null >> /tmp/falco.log 2>&1 &" || true
  sleep 3
  $SSH "pgrep -x falco > /dev/null && echo '  Falco running.' || { echo '  WARNING: Falco failed to start. Log:'; tail -5 /tmp/falco.log 2>/dev/null; }" || true

  echo ""
  echo "[5/6] Starting Docker containers..."
  $SSH "cd /home/ubuntu/project/docker && docker compose up -d nginx-target flask-target redis-target attacker"

  echo ""
  echo "[6/6] Restarting FastAPI backend with updated code..."
  # sentinel.service (Restart=always) manages uvicorn — just restart it to pick up new code
  $SSH "sudo systemctl restart sentinel"
  sleep 3

  echo ""
  echo "================================================================"
  echo " Dashboard:    http://localhost:8765/"
  echo " Logs page:    http://localhost:8765/logs"
  echo " Falco log:    ssh -p 2222 -i ~/.ssh/falco_vm ubuntu@localhost 'sudo journalctl -u falco-kmod -f'"
  echo " Backend log:  ssh -p 2222 -i ~/.ssh/falco_vm ubuntu@localhost 'tail -f /tmp/sentinel.log'"
  echo " Stop VM:      ./vm/stop-vm.sh"
  echo "================================================================"

else
  # ----- Local mode (original behavior, no Falco) -----

  echo "[1/3] Building and starting vulnerable sandbox..."
  docker compose -f "$SCRIPT_DIR/docker/docker-compose.yml" up -d --build

  echo ""
  echo "[2/3] Waiting for containers to be ready..."
  sleep 4

  echo ""
  echo "[3/3] Container status:"
  docker compose -f "$SCRIPT_DIR/docker/docker-compose.yml" ps

  echo ""
  echo "================================================================"
  echo " Starting FastAPI backend at http://localhost:8765"
  echo " Attack panel: http://localhost:8765/"
  echo " Logs page:    http://localhost:8765/logs"
  echo "================================================================"
  echo ""

  cd "$SCRIPT_DIR/src"
  uvicorn main:app --host 0.0.0.0 --port 8765 --reload
fi
