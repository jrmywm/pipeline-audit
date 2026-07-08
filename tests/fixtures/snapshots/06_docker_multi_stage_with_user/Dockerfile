FROM golang:1.22 AS builder
WORKDIR /src
COPY . .
RUN go build -o /app .

FROM alpine:3.19
RUN addgroup -S app && adduser -S app -G app
USER 1001
COPY --from=builder /app /app
ENTRYPOINT ["/app"]