# Cortex Management Server — Docker Image
# Fleet management for CortexOS nodes
#
# Build:  docker build -t cortex-management-server .
# Run:    docker run -d -p 9443:9443 -v mgmt-data:/app/data cortex-management-server

FROM node:22-slim

LABEL maintainer="Ivan Honer <ivanuser>"
LABEL description="Cortex Management Server — Fleet management for CortexOS nodes"
LABEL version="0.5.1"

# Install minimal system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies first (cache layer)
COPY package*.json ./
RUN npm ci --production && npm cache clean --force

# Copy application source
COPY src/ ./src/
COPY dashboard/ ./dashboard/
COPY scripts/ ./scripts/
COPY README.md ./

# Create data directory
RUN mkdir -p /app/data

# ─── Environment ─────────────────────────────────────────────
ENV NODE_ENV=production
ENV PORT=9443
ENV DATA_DIR=/app/data

# ─── Expose & Volume ────────────────────────────────────────
EXPOSE 9443
VOLUME ["/app/data"]

# ─── Health check ────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:9443/api/health || exit 1

CMD ["node", "src/server.js"]
