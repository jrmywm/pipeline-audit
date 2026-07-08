FROM alpine:3.19
RUN addgroup -S app && adduser -S app -G app
USER 1001
WORKDIR /home/app
COPY . .
CMD ["./run.sh"]