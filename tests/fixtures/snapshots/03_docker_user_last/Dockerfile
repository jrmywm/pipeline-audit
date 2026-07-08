FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY . .
EXPOSE 3000
USER 1001
ENTRYPOINT ["node", "server.js"]