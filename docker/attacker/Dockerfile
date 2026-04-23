FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    nmap \
    redis-tools \
    curl \
    wget \
    python3 \
    python3-pip \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release \
    iproute2 \
    iputils-ping \
    netcat-openbsd \
    procps \
    util-linux \
    && rm -rf /var/lib/apt/lists/*

# Install Docker CLI (for docker-in-docker attacks via docker.sock)
RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

RUN echo \
    "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] \
    https://download.docker.com/linux/ubuntu focal stable" \
    > /etc/apt/sources.list.d/docker.list

RUN apt-get update && apt-get install -y docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

CMD ["tail", "-f", "/dev/null"]
