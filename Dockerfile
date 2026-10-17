# syntax=docker/dockerfile:1
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/pslmon ./cmd/pslmon

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata \
 && adduser -D -H -u 10001 pslmon \
 && mkdir -p /data && chown pslmon:pslmon /data
COPY --from=build /out/pslmon /usr/local/bin/pslmon
USER pslmon
ENV DB_PATH=/data/pslmon.db \
    LISTEN_ADDR=:8080
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=6s --start-period=10s --retries=3 CMD ["pslmon", "healthcheck"]
ENTRYPOINT ["pslmon"]
