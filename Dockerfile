# Override NODE_IMAGE only with another verified multi-architecture digest.
ARG NODE_IMAGE=node:22-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392
FROM ${NODE_IMAGE} AS build
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev --ignore-scripts
FROM ${NODE_IMAGE} AS runtime
ENV NODE_ENV=production HUB_DATA_DIR=/data HUB_MASTER_KEY_FILE=/secrets/master.key HUB_BOOTSTRAP_TOKEN_FILE=/secrets/bootstrap.token HUB_HOST=0.0.0.0 HUB_CONTAINER_MODE=true
WORKDIR /app
COPY --from=build --chown=node:node /app/dist ./dist
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node package.json ./
COPY --chown=node:node public ./public
COPY deploy/container-init.sh /usr/local/bin/wheremymcp-init
USER 1000:1000
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 CMD node -e "fetch('http://127.0.0.1:8080/health/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node","dist/main.js"]
