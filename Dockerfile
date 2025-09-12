# Build stage
FROM golang:1.21-alpine AS builder

# Install dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o security-scanner main.go

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy binary from builder stage
COPY --from=builder /app/security-scanner .

# Copy configuration
COPY --from=builder /app/.security-scanner.yaml .

# Set executable permissions
RUN chmod +x ./security-scanner

# Create directory for workspace mounting
RUN mkdir /workspace

# Set default command
ENTRYPOINT ["./security-scanner"]

# Default to scanning workspace directory
CMD ["/workspace"]
