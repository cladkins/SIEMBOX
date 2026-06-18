FROM debian:bookworm-slim

LABEL maintainer="SIEMBox"
LABEL description="Authenticated managed log forwarder for SIEMBox"

ENV DEBIAN_FRONTEND=noninteractive

# Runtime dependencies. `systemd` is installed only for its `journalctl`
# binary, used to ship the host's systemd journal (the shipper never runs
# systemd itself). The rest match what the shipper script needs.
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash \
        netcat-openbsd \
        coreutils \
        ca-certificates \
        curl \
        jq \
        systemd \
    && rm -rf /var/lib/apt/lists/*

# Docker CLI (client only) for the optional docker source. Static binary,
# selected per build architecture (TARGETARCH is provided by Buildx).
ARG TARGETARCH
ARG DOCKER_VERSION=27.3.1
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) docker_arch=x86_64 ;; \
        arm64) docker_arch=aarch64 ;; \
        *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://download.docker.com/linux/static/stable/${docker_arch}/docker-${DOCKER_VERSION}.tgz" -o /tmp/docker.tgz; \
    tar -xzf /tmp/docker.tgz -C /usr/local/bin --strip-components=1 docker/docker; \
    rm /tmp/docker.tgz; \
    docker --version

# Copy managed shipper script
COPY shipper-managed.sh /usr/local/bin/shipper
RUN chmod +x /usr/local/bin/shipper

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD pgrep -f shipper || exit 1

# Run managed shipper (requires API authentication)
CMD ["/usr/local/bin/shipper"]
