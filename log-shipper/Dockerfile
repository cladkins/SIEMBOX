FROM debian:bookworm-slim

LABEL maintainer="SIEMBox"
LABEL description="Authenticated managed log forwarder for SIEMBox"

ENV DEBIAN_FRONTEND=noninteractive

# Runtime dependencies. `systemd` is installed only for its `journalctl`
# binary, used to ship the host's systemd journal (the shipper never runs
# systemd itself). `nmap` runs asset-discovery scans SIEMBox dispatches to the
# shipper; `nuclei` (installed below) runs dispatched vulnerability scans (see
# shipper-managed.sh's poll_and_run_scans). `unzip` is only needed to unpack the
# nuclei release archive. The rest match what the shipper script needs.
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash \
        netcat-openbsd \
        coreutils \
        ca-certificates \
        curl \
        jq \
        nmap \
        unzip \
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

# Nuclei (vulnerability scanner) for dispatched vuln scans. Official release
# binary, selected per build architecture. Templates are NOT baked in -- the
# shipper fetches/updates them at runtime (see warm_nuclei_templates); set
# NUCLEI_UPDATE_TEMPLATES=false to manage them yourself (e.g. a mounted volume).
ARG NUCLEI_VERSION=3.3.9
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) nuclei_arch=amd64 ;; \
        arm64) nuclei_arch=arm64 ;; \
        *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${nuclei_arch}.zip" -o /tmp/nuclei.zip; \
    unzip -o /tmp/nuclei.zip -d /tmp/nuclei; \
    mv /tmp/nuclei/nuclei /usr/local/bin/nuclei; \
    rm -rf /tmp/nuclei /tmp/nuclei.zip; \
    nuclei -version

# Copy managed shipper script
COPY shipper-managed.sh /usr/local/bin/shipper
RUN chmod +x /usr/local/bin/shipper

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD pgrep -f shipper || exit 1

# Run managed shipper (requires API authentication)
CMD ["/usr/local/bin/shipper"]
