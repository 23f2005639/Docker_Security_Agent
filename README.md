# Container Sentinel

A container security platform built for a BCA final year project. It spins up an intentionally vulnerable Docker environment, lets you trigger real container attack techniques, and uses an AI agent layer to detect and analyze what happened.

## What it does

- Runs a sandboxed network of deliberately insecure containers (nginx, Flask, Redis)
- Provides a web dashboard to trigger attacks: Docker socket escape, namespace escape, Redis lateral movement, authorization bypass, and CVE simulations
- An AI agent layer (built on the OpenAI Agents SDK) watches each attack in real time, runs a scanner, monitors container behavior, checks network activity, and produces a structured security report
- Optional Falco integration via a QEMU VM for kernel-level runtime detection using eBPF

## Architecture

```
FastAPI backend  ──  attack modules  ──  target containers (Docker)
       │
       └──  AI agent runner (sidecar)
                 ├── Scanner agent     (Trivy, image analysis)
                 ├── Monitor agent     (container events)
                 ├── Network agent     (traffic patterns)
                 └── Reporter agent    (structured findings)
```

The UI is plain HTML/JS served by FastAPI. The agent runner connects to the backend over WebSocket, waits for attack completions, orchestrates the four agents, and streams findings back to the dashboard.

## Requirements

- Docker and Docker Compose
- Python 3.11+
- An OpenAI API key (for the AI agent layer)

For the VM mode (Falco):
- QEMU/KVM
- An SSH key at `~/.ssh/falco_vm`

## Setup

**1. Clone and install dependencies**

```bash
git clone <repo-url>
cd container-sentinel
pip install -r requirements.txt
```

**2. Set your API key**

```bash
cp .env.example .env
# Edit .env and set OPENAI_API_KEY
```

**3. Run (local mode, no Falco)**

```bash
./start.sh
```

Open [http://localhost:8765](http://localhost:8765).

**4. Run with Falco (VM mode)**

This requires a pre-built Ubuntu VM image with Falco and Docker installed inside it.

**4a. Create the VM image (one-time setup)**

```bash
# Install dependencies (Fedora/RHEL)
sudo dnf install -y qemu-img cloud-utils genisoimage

# Create the VM directory
mkdir -p docker/falco-vm

# Download Ubuntu 22.04 cloud image
wget https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img \
  -O docker/falco-vm/falco-vm.qcow2

# Resize to 20GB
qemu-img resize docker/falco-vm/falco-vm.qcow2 20G

# Generate SSH key for VM access
ssh-keygen -t ed25519 -f ~/.ssh/falco_vm -N ""

# Create cloud-init user-data
cat > /tmp/user-data <<EOF
#cloud-config
users:
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $(cat ~/.ssh/falco_vm.pub)
packages:
  - docker.io
  - rsync
EOF

# Create seed.iso
cloud-localds docker/falco-vm/seed.iso /tmp/user-data
```

**4b. First boot — install Falco and Docker inside the VM**

Boot the VM and wait for cloud-init to finish before running any apt commands:

```bash
./vm/launch.sh
ssh -p 2222 -i ~/.ssh/falco_vm -o StrictHostKeyChecking=no ubuntu@localhost

# Inside the VM — wait for cloud-init first
sudo cloud-init status --wait

# Install Falco
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
  sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] \
  https://download.falco.org/packages/deb stable main" | \
  sudo tee /etc/apt/sources.list.d/falcosecurity.list
sudo apt-get update
sudo apt-get install -y linux-headers-$(uname -r) falco
# Select "modern_ebpf" driver when prompted

# Install Docker CE (the cloud image ships with an old docker.io)
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu jammy stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker ubuntu

# Fix Docker DNS for container builds
echo '{"dns": ["8.8.8.8", "1.1.1.1"]}' | sudo tee /etc/docker/daemon.json
sudo systemctl enable docker && sudo systemctl start docker

exit
```

**4c. Sync project files and install Python deps**

```bash
# From the host
ssh-keygen -R "[localhost]:2222"   # clear stale host key if needed

ssh -p 2222 -i ~/.ssh/falco_vm -o StrictHostKeyChecking=no ubuntu@localhost \
  "sudo mkdir -p /mnt/host-project && \
   sudo mount -t 9p -o trans=virtio,version=9p2000.L host-project /mnt/host-project && \
   rsync -a --safe-links --exclude='evn/' /mnt/host-project/ /home/ubuntu/project/"

ssh -p 2222 -i ~/.ssh/falco_vm ubuntu@localhost \
  "sudo apt-get install -y python3-pip && \
   cd /home/ubuntu/project && pip3 install -r requirements.txt"
```

**4d. Create the sentinel systemd service**

```bash
ssh -p 2222 -i ~/.ssh/falco_vm ubuntu@localhost "sudo tee /etc/systemd/system/sentinel.service <<EOF
[Unit]
Description=Container Sentinel Backend
After=network.target docker.service

[Service]
User=ubuntu
WorkingDirectory=/home/ubuntu/project/src
ExecStart=/usr/bin/python3 -m uvicorn main:app --host 0.0.0.0 --port 8765
Restart=always
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF"

ssh -p 2222 -i ~/.ssh/falco_vm ubuntu@localhost \
  "sudo systemctl daemon-reload && sudo systemctl enable sentinel"
```

**4e. Start**

```bash
./start.sh --vm
```

## Project structure

```
src/
  main.py              FastAPI app entry point
  attacks/             Attack modules (docker socket, nsenter, Redis, etc.)
  ai_agents/           Agent orchestration and individual agents
  falco_router.py      Falco event ingestion endpoint
docker/
  docker-compose.yml   Vulnerable sandbox containers
  flask-target/        Intentionally vulnerable Flask app
  falco/               Falco config and rules
ui/                    Frontend HTML pages
vm/                    VM launch/stop scripts
```

## Warning

The Docker environment is deliberately insecure — privileged containers, exposed Docker socket, unauthenticated Redis. Run this on a dedicated machine or VM, not on your daily system.

## License

Apache 2.0
