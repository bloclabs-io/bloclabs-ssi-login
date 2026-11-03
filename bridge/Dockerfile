# syntax=docker/dockerfile:1

# Build stage: compile the TypeScript with the development dependencies.
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci --no-audit --no-fund
COPY src ./src
RUN npm run build

# Runtime stage: the compiled JavaScript only. The bridge has no runtime dependencies,
# so nothing from node_modules is copied (docs/adr/0005-bridge-stack.md).
FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app/dist/src ./dist/src
COPY package.json ./
USER node
EXPOSE 8090
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget -qO- "http://127.0.0.1:${BRIDGE_PORT:-8090}/healthz" > /dev/null || exit 1
CMD ["node", "dist/src/main.js"]
