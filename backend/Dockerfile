# syntax=docker/dockerfile:1
# Multi-stage build for SIEMBox Backend

# Stage 1: Build
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies (npm cache persisted across builds via BuildKit)
RUN --mount=type=cache,target=/root/.npm npm ci

# Copy source code
COPY src ./src
COPY migrations ./migrations

# Build TypeScript
RUN npm run build

# Stage 2: Production
FROM node:20-alpine

WORKDIR /app

# Install NMAP for asset discovery scanning
RUN apk add --no-cache nmap

# Install Nuclei for vulnerability scanning.
# Pin the version and download per-arch (TARGETARCH is provided automatically
# by Buildx) so native arm64 builds get an arm64 binary instead of amd64.
ARG TARGETARCH
ARG NUCLEI_VERSION=3.9.0
RUN apk add --no-cache wget unzip && \
    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip" -O /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /usr/local/bin && \
    rm /tmp/nuclei.zip && \
    chmod +x /usr/local/bin/nuclei && \
    apk del wget unzip

# Download Nuclei templates (CVE, default, etc.)
RUN nuclei -update-templates -silent

# Install production dependencies only
COPY package*.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --only=production

# Copy built files from builder
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/migrations ./migrations

# Create logs directory
RUN mkdir -p logs

# Expose ports
EXPOSE 8421
EXPOSE 514/udp
EXPOSE 514/tcp

# Run migrations and start server
CMD ["sh", "-c", "node dist/scripts/migrate.js && node dist/server.js"]
