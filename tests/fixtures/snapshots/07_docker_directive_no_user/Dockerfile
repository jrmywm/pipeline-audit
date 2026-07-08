# syntax=docker/dockerfile:1.6
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y curl
WORKDIR /app
COPY . .
CMD ["./app"]