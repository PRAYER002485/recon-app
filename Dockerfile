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
ENV SUBFINDER_VERSION=v2.6.5
ENV HTTPX_VERSION=v1.6.10
ENV NAABU_VERSION=v2.3.3
ENV KATANA_VERSION=v1.1.3
RUN curl -L -o subfinder.tar.gz https://github.com/projectdiscovery/subfinder/releases/download/${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION#v}_linux_amd64.tar.gz \
 && tar -xzf subfinder.tar.gz \
 && mv subfinder /usr/local/bin/subfinder \
 && chmod +x /usr/local/bin/subfinder
RUN curl -L -o httpx.tar.gz https://github.com/projectdiscovery/httpx/releases/download/${HTTPX_VERSION}/httpx_${HTTPX_VERSION#v}_linux_amd64.tar.gz \
 && tar -xzf httpx.tar.gz \
 && mv httpx /usr/local/bin/httpx \
 && chmod +x /usr/local/bin/httpx

# naabu (port scanner)
RUN curl -L -o naabu.tar.gz https://github.com/projectdiscovery/naabu/releases/download/${NAABU_VERSION}/naabu_${NAABU_VERSION#v}_linux_amd64.tar.gz \
 && tar -xzf naabu.tar.gz \
 && mv naabu /usr/local/bin/naabu \
 && chmod +x /usr/local/bin/naabu

# katana (crawler)
RUN curl -L -o katana.tar.gz https://github.com/projectdiscovery/katana/releases/download/${KATANA_VERSION}/katana_${KATANA_VERSION#v}_linux_amd64.tar.gz \
 && tar -xzf katana.tar.gz \
 && mv katana /usr/local/bin/katana \
 && chmod +x /usr/local/bin/katana

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
