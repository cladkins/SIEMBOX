# Multi-stage build for SIEMBox Backend

# Stage 1: Build
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies
RUN npm ci

# Copy source code
COPY src ./src
COPY migrations ./migrations

# Build TypeScript
RUN npm run build

# Stage 2: Production
FROM node:20-alpine

ARG TARGETARCH=amd64
ARG NUCLEI_VERSION

WORKDIR /app

# Install NMAP for asset discovery scanning
RUN apk add --no-cache nmap

# Install Nuclei for vulnerability scanning
# Using wget to download the latest release binary
RUN apk add --no-cache wget unzip && \
    NUCLEI_VERSION="${NUCLEI_VERSION:-$(wget -qO- --timeout=30 --tries=3 "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest" | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')}" && \
    if [ -z "$NUCLEI_VERSION" ]; then echo "Failed to resolve Nuclei version"; exit 1; fi && \
    wget -q --timeout=30 --tries=3 "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip" -O /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /usr/local/bin && \
    rm /tmp/nuclei.zip && \
    chmod +x /usr/local/bin/nuclei && \
    apk del wget unzip

# Install production dependencies only
COPY package*.json ./
RUN npm ci --only=production

# Copy built files from builder
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/migrations ./migrations

# Create logs directory
RUN mkdir -p logs

# Expose ports
EXPOSE 3000
EXPOSE 514/udp
EXPOSE 514/tcp

# Run migrations and start server
CMD ["sh", "-c", "node dist/scripts/migrate.js && node dist/server.js"]
