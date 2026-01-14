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
