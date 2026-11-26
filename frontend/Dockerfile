# Stage 1 — Build React 19 + Vite SPA
FROM node:22-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Stage 2 — Hardened Nginx with strict CSP and SPA callback routing
FROM nginx:1.27-alpine AS runtime
COPY --from=builder /app/dist /usr/share/nginx/html
COPY --from=builder /app/dist/index.html /usr/share/nginx/html/404.html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
