FROM alpine:latest

LABEL maintainer="SIEMBox"
LABEL description="Universal log forwarder for SIEMBox"

# Install required packages
RUN apk add --no-cache \
    bash \
    netcat-openbsd \
    coreutils \
    docker-cli \
    ca-certificates \
    tzdata

# Copy shipper script
COPY shipper.sh /usr/local/bin/shipper
RUN chmod +x /usr/local/bin/shipper

# Create config directory
RUN mkdir -p /config

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD pgrep -f shipper || exit 1

# Run shipper
CMD ["/usr/local/bin/shipper"]
