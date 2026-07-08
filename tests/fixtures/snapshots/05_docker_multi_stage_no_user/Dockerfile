FROM golang:1.22 AS builder
WORKDIR /src
COPY . .
RUN go build -o /app .

FROM alpine:3.19
COPY --from=builder /app /app
ENTRYPOINT ["/app"]