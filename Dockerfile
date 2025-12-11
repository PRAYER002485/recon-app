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

ENV HTTPX_VERSION=v1.6.10
ENV NAABU_VERSION=v2.3.3
ENV KATANA_VERSION=v1.1.3
RUN apt-get update && apt-get install -y curl unzip

ENV SUBFINDER_VERSION=v2.10.1
RUN set -eux; \
  curl -fL --retry 3 -o subfinder.zip \
  https://github.com/projectdiscovery/subfinder/releases/download/${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION#v}_linux_amd64.zip; \
  mkdir -p /tmp/subfinder && unzip subfinder.zip -d /tmp/subfinder; \
  install -m 0755 $(find /tmp/subfinder -type f -name subfinder | head -n1) /usr/local/bin/subfinder; \
  rm -rf /tmp/subfinder subfinder.zip

RUN set -eux; \
  curl -fL --retry 3 -o httpx.zip https://github.com/projectdiscovery/httpx/releases/download/${HTTPX_VERSION}/httpx_${HTTPX_VERSION#v}_linux_amd64.zip; \
  mkdir -p /tmp/httpx && unzip httpx.zip -d /tmp/httpx; \
  install -m 0755 $(find /tmp/httpx -type f -name httpx | head -n1) /usr/local/bin/httpx; \
  rm -rf /tmp/httpx httpx.zip

# naabu (port scanner)
RUN set -eux; \
  curl -fL --retry 3 -o naabu.zip https://github.com/projectdiscovery/naabu/releases/download/${NAABU_VERSION}/naabu_${NAABU_VERSION#v}_linux_amd64.zip; \
  mkdir -p /tmp/naabu && unzip naabu.zip -d /tmp/naabu; \
  install -m 0755 $(find /tmp/naabu -type f -name naabu | head -n1) /usr/local/bin/naabu; \
  rm -rf /tmp/naabu naabu.zip

# katana (crawler)
RUN set -eux; \
  curl -fL --retry 3 -o katana.zip https://github.com/projectdiscovery/katana/releases/download/${KATANA_VERSION}/katana_${KATANA_VERSION#v}_linux_amd64.zip; \
  mkdir -p /tmp/katana && unzip katana.zip -d /tmp/katana; \
  install -m 0755 $(find /tmp/katana -type f -name katana | head -n1) /usr/local/bin/katana; \
  rm -rf /tmp/katana katana.zip

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
