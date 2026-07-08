# syntax=docker/dockerfile:1.6
FROM node:20

ENV NODE_ENV=production
ENV API_KEY=sk-1234567890abcdef1234567890abcdef

WORKDIR /app
COPY . .

RUN npm ci

CMD ["node", "index.js"]