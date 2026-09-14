FROM node:18-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=optional --no-audit --no-fund
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:18-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY package*.json ./
RUN npm ci --omit=dev --omit=optional --no-audit --no-fund
COPY --from=build /app/dist ./dist
EXPOSE 3001
CMD ["node", "dist/server.js"]