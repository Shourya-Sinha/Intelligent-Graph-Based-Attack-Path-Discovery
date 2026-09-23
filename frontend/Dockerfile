# Frontend — production hardened: build + nginx, dev via npm run dev
FROM node:20-alpine AS base
WORKDIR /app
COPY package.json ./
RUN npm install
COPY . .

# dev stage (default for docker-compose dev)
FROM base AS dev
EXPOSE 5173
CMD ["npm","run","dev"]

# prod builder
FROM base AS builder
RUN npm run build

# prod nginx
FROM nginx:alpine AS prod
COPY --from=builder /app/dist /usr/share/nginx/html
# nginx proxy for /api and /ws to backend
RUN printf 'server {\n  listen 80;\n  root /usr/share/nginx/html;\n  index index.html;\n  location / { try_files $uri $uri/ /index.html; }\n  location /api/ { proxy_pass http://backend:8000; proxy_set_header Host $host; }\n  location /ws/ { proxy_pass http://backend:8000; proxy_http_version 1.1; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection \"upgrade\"; }\n}\n' > /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx","-g","daemon off;"]
