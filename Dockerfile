# --- Build stage -------------------------------------------------------------
FROM node:20-bullseye AS build
WORKDIR /app

COPY backend/package*.json ./backend/
COPY frontend/package*.json ./frontend/
RUN cd frontend && npm ci && cd ../backend && npm ci

COPY frontend ./frontend
RUN cd frontend && npm run build

COPY backend ./backend
RUN mkdir -p backend/frontend/dist && cp -r frontend/dist/* backend/frontend/dist/
RUN cd backend && npm run build

# --- Tools stage -------------------------------------------------------------
FROM debian:stable-slim AS tools
WORKDIR /tmp
RUN apt-get update && apt-get install -y curl ca-certificates && rm -rf /var/lib/apt/lists/*
# Pin to an existing release (v2.6.5 was removed and returns 404)
# Use a published release asset that exists (v2.10.1 tarball 404s)
ENV SUBFINDER_VERSION=v2.10.1
RUN set -eux; \
  curl -fL --retry 3 -o subfinder.tar.gz \
  https://github.com/projectdiscovery/subfinder/releases/download/${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION#v}_linux_amd64.tar.gz; \
  mkdir -p /tmp/subfinder && tar -xzf subfinder.tar.gz -C /tmp/subfinder; \
  install -m 0755 $(find /tmp/subfinder -type f -name subfinder | head -n1) /usr/local/bin/subfinder; \
  rm -rf /tmp/subfinder subfinder.tar.gz
RUN set -eux; \
  curl -fL --retry 3 -o httpx.tar.gz https://github.com/projectdiscovery/httpx/releases/download/${HTTPX_VERSION}/httpx_${HTTPX_VERSION#v}_linux_amd64.tar.gz; \
  mkdir -p /tmp/httpx && tar -xzf httpx.tar.gz -C /tmp/httpx; \
  install -m 0755 $(find /tmp/httpx -type f -name httpx | head -n1) /usr/local/bin/httpx; \
  rm -rf /tmp/httpx httpx.tar.gz

# naabu (port scanner)
RUN set -eux; \
  curl -fL --retry 3 -o naabu.tar.gz https://github.com/projectdiscovery/naabu/releases/download/${NAABU_VERSION}/naabu_${NAABU_VERSION#v}_linux_amd64.tar.gz; \
  mkdir -p /tmp/naabu && tar -xzf naabu.tar.gz -C /tmp/naabu; \
  install -m 0755 $(find /tmp/naabu -type f -name naabu | head -n1) /usr/local/bin/naabu; \
  rm -rf /tmp/naabu naabu.tar.gz

# katana (crawler)
RUN set -eux; \
  curl -fL --retry 3 -o katana.tar.gz https://github.com/projectdiscovery/katana/releases/download/${KATANA_VERSION}/katana_${KATANA_VERSION#v}_linux_amd64.tar.gz; \
  mkdir -p /tmp/katana && tar -xzf katana.tar.gz -C /tmp/katana; \
  install -m 0755 $(find /tmp/katana -type f -name katana | head -n1) /usr/local/bin/katana; \
  rm -rf /tmp/katana katana.tar.gz

# --- Runtime stage -----------------------------------------------------------
FROM node:20-bullseye-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production

COPY --from=build /app/backend/package*.json ./
RUN npm ci --omit=dev

COPY --from=build /app/backend/dist ./dist
COPY --from=build /app/backend/frontend/dist ./frontend/dist

# Copy CLI tools built in tools stage
COPY --from=tools /usr/local/bin/subfinder /usr/local/bin/httpx /usr/local/bin/naabu /usr/local/bin/katana /usr/local/bin/

# Install OS packages for scanners used by the backend (nmap, dig, curl)
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap dnsutils curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Create non-root user and drop privileges
RUN groupadd -g 1001 nodeapp \
 && useradd -r -u 1001 -g nodeapp nodeapp \
 && chown -R nodeapp:nodeapp /app
USER nodeapp

ENV PORT=8080
EXPOSE 8080

# Basic healthcheck for container orchestration
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+process.env.PORT+'/api/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))" || exit 1

CMD ["node", "dist/server.js"]
