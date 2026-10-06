FROM golang:1.25 AS builder
WORKDIR /src
COPY go.mod go.sum ./
COPY internal/facilitation ./internal/facilitation
COPY internal/axon/identity ./internal/axon/identity
COPY internal/axon/params ./internal/axon/params
COPY internal/axon/names ./internal/axon/names
COPY internal/axon/authoritative ./internal/axon/authoritative
COPY cmd/axon-dns ./cmd/axon-dns
RUN CGO_ENABLED=0 go build -trimpath -o /out/axon-dns ./cmd/axon-dns

# ISC BIND 9.20, pinned to the integration-tested image. Update deliberately with tests.
FROM internetsystemsconsortium/bind9:9.20@sha256:071465f88068854d0ceadd9b985fb1acae4071e80754e545cd811fde57541ad0
COPY --from=builder /out/axon-dns /usr/local/bin/axon-dns
COPY packaging/authoritative-dns/entrypoint.sh /usr/local/bin/axon-dns-entrypoint
RUN chmod 755 /usr/local/bin/axon-dns-entrypoint
EXPOSE 1053/tcp 1053/udp
ENTRYPOINT ["/usr/local/bin/axon-dns-entrypoint"]
