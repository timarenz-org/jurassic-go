# Multi-stage build for Jurassic-Go (InGen Isla Nublar Park Operations API)
# Uses Go 1.21-alpine so container SCA scanners (--scan-go-standard-library / Snyk Container)
# detect both 3rd-party .go.buildinfo modules and Go 1.21.13 standard library advisories.
FROM golang:1.21-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
COPY main.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -mod=mod -o /app/jurassic-go .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/jurassic-go /app/jurassic-go

EXPOSE 8080
ENV PORT=8080

ENTRYPOINT ["/app/jurassic-go"]
