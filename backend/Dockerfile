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

WORKDIR /app

# Install NMAP for asset discovery scanning
RUN apk add --no-cache nmap

# Install Nuclei for vulnerability scanning
# Using wget to download the latest release binary
RUN apk add --no-cache wget unzip && \
    NUCLEI_VERSION=$(wget -qO- "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest" | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/') && \
    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -O /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /usr/local/bin && \
    rm /tmp/nuclei.zip && \
    chmod +x /usr/local/bin/nuclei && \
    apk del wget unzip

# Download Nuclei templates (CVE, default, etc.)
RUN nuclei -update-templates -silent

# Install production dependencies only
COPY package*.json ./
RUN npm ci --only=production

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
