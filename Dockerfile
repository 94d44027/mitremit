FROM golang:1.25.6-alpine AS builder
WORKDIR /build
COPY mitre-mitigates.go .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s" \
    -o mitre-sync \
    mitre-mitigates.go

FROM alpine:3.23
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -g 1000 appgroup \
    && adduser -u 1000 -G appgroup -D appuser
WORKDIR /app
COPY --from=builder --chown=appuser:appgroup /build/mitre-sync .
USER appuser
ENV TMPDIR=/tmp \
    HOME=/tmp
VOLUME ["/tmp/.mitre-cache"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD /app/mitre-sync -h || exit 1
ENTRYPOINT ["/app/mitre-sync"]