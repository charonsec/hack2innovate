FROM node:18-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=optional --no-audit --no-fund
COPY tsconfig.json tsconfig.node.json vite.config.ts tailwind.config.ts postcss.config.js index.html ./
COPY src ./src
RUN npm run build

FROM nginx:1.25-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]