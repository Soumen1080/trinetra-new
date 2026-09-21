# Multi-stage build for scanner-source
FROM golang:alpine AS builder

WORKDIR /src
COPY scanners/cbom-go ./cbom-go
COPY scanners/source ./source

WORKDIR /src/source
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/scanner-source ./cmd/main.go

# Runtime stage with Python and Semgrep
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir semgrep==1.176.1

COPY --from=builder /bin/scanner-source /usr/local/bin/scanner-source
COPY rules /rules

RUN mkdir -p /scan-workdir /artifact-store

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/scanner-source"]
CMD ["-addr", ":8080", "-input-root", "/scan-workdir", "-artifact-store", "/artifact-store", "-rules", "/rules"]
