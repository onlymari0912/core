# Build stage
FROM node:16 AS builder

WORKDIR /app

# Install root dependencies
COPY package.json package-lock.json ./
RUN npm ci

# Copy source and build config
COPY tsconfig.json ./
COPY src/ ./src/

# Compile TypeScript
RUN npx tsc

# Bundle with ncc into build-env (externalize pug and ts-node)
COPY build-env/package.json build-env/package-lock.json ./build-env/
COPY build-env/assets/ ./build-env/assets/
COPY build-env/typescript/ ./build-env/typescript/
RUN npx ncc build ./dist/AsphyxiaCore.js -o ./build-env --external pug --external ts-node

# Install build-env runtime deps and copy bundled typescript
WORKDIR /app/build-env
RUN npm ci
RUN cp -r typescript ./node_modules/

# Runtime stage
FROM node:16-slim

# Install tini for proper signal handling (allows Ctrl+C to work)
ENV TINI_VERSION=v0.19.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /tini
RUN chmod +x /tini

WORKDIR /app/build-env

# Copy the fully built build-env directory
COPY --from=builder /app/build-env ./

# Copy plugins directory
COPY plugins/ /app/build-env/plugins/

# Create savedata directory
RUN mkdir -p /app/build-env/savedata

EXPOSE 8083
EXPOSE 5700

# Use tini as entrypoint so SIGINT/SIGTERM are forwarded to node
ENTRYPOINT ["/tini", "--"]
CMD ["node", "index.js", "-b", "0.0.0.0"]
