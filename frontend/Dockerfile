# Build context must be the project root (context: .)
# so that shared/contracts/ is accessible alongside frontend/

# Stage 1: development (Vite dev server with HMR)
FROM node:20-alpine AS development
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install --frozen-lockfile || npm install
COPY shared /app/shared
COPY frontend .
EXPOSE 3000
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "3000"]

# Stage 2: build
FROM node:20-alpine AS build
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install --frozen-lockfile || npm install
COPY shared /app/shared
COPY frontend .
RUN npm run build

# Stage 3: production (nginx)
FROM nginx:alpine AS production
COPY --from=build /app/frontend/dist /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
