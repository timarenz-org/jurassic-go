# Multi-stage build for jurassic-go (Jurassic Park System).
# golang:1.21-alpine keeps an old Go standard library in the binary, so container SCA
# (--scan-go-standard-library) reports Go stdlib CVEs in addition to module CVEs.
FROM golang:1.21-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
COPY main.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -mod=mod -o /app/jurassic-go .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/jurassic-go /app/jurassic-go
COPY fsn /app/fsn

EXPOSE 8080
ENV PORT=8080

ENTRYPOINT ["/app/jurassic-go"]
