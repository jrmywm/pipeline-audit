FROM node:20
ARG UID=1001
RUN addgroup -S app && adduser -S app -G app --uid $UID
USER $UID
WORKDIR /app
COPY . .
CMD ["node", "index.js"]