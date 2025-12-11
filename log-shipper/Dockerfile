FROM alpine:latest

LABEL maintainer="SIEMBox"
LABEL description="Authenticated managed log forwarder for SIEMBox"

# Install required packages
RUN apk add --no-cache \
    bash \
    netcat-openbsd \
    coreutils \
    docker-cli \
    ca-certificates \
    tzdata \
    curl \
    jq

# Copy managed shipper script
COPY shipper-managed.sh /usr/local/bin/shipper-managed
RUN chmod +x /usr/local/bin/shipper-managed

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD pgrep -f shipper-managed || exit 1

# Run managed shipper (requires API authentication)
CMD ["/usr/local/bin/shipper-managed"]
