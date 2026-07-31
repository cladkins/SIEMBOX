# syntax=docker/dockerfile:1
# Multi-stage build for SIEMBox Frontend

# Stage 1: Build
FROM node:20-alpine AS builder

WORKDIR /app

# Build arguments
ARG VITE_API_URL
ENV VITE_API_URL=$VITE_API_URL

# Copy package files
COPY package*.json ./

# Install dependencies (npm cache persisted across builds via BuildKit)
RUN --mount=type=cache,target=/root/.npm npm ci

# Copy source code
COPY . .

# Type-check, then build. The type-check gates the image: a vue-tsc-catchable
# error (undefined reference, type mismatch) fails the build instead of shipping
# (vite build alone does NOT type-check).
RUN npm run type-check && npm run build

# Stage 2: Production with Nginx
FROM nginx:alpine

# Copy built files
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy nginx configuration as a template -- the base image's own entrypoint
# (docker-entrypoint.d/20-envsubst-on-templates.sh, still wired up since this
# Dockerfile only overrides CMD, never ENTRYPOINT) envsubst's it into
# conf.d/default.conf at container start, substituting BACKEND_UPSTREAM (see
# compose.yaml/compose.prod.yaml). nginx's own runtime variables ($uri, $host,
# etc.) pass through untouched -- that script only substitutes names that are
# actual container env vars, and those aren't.
COPY nginx.conf.template /etc/nginx/templates/default.conf.template

# Expose port
EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
