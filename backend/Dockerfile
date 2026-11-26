# Stage 1 — Build strict TypeScript backend
FROM node:22-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig*.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

# Stage 2 — Minimal non-root runtime
FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=development
ENV PORT=5050
ENV DEV_IDP_ENABLED=true
RUN addgroup -S choreo && adduser -S choreo -G choreo
COPY --from=builder --chown=choreo:choreo /app/node_modules ./node_modules
COPY --from=builder --chown=choreo:choreo /app/dist ./dist
COPY --from=builder --chown=choreo:choreo /app/package.json ./package.json
USER choreo
EXPOSE 5050
CMD ["node", "dist/server.js"]
