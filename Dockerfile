# Build stage
FROM golang:1.23.1 AS builder

WORKDIR /build

# Copy source code files
COPY . ./
RUN go mod download

# Build static binary
RUN env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o astra-scanner .

# Production stage
FROM scratch AS prod

# Copy CA certificates for HTTPS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Copy binary from build stage
COPY --from=builder /build/astra-scanner /astra-scanner

# Create a working directory for output
WORKDIR /app

# Run the binary
ENTRYPOINT ["/astra-scanner"]
