# ---------- Build ----------
FROM golang:1.25-alpine AS build
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Build natively for the builder's arch (no GOARCH=amd64!)
RUN CGO_ENABLED=0 go build -o /out/wg-go-installer main.go

# ---------- Runtime ----------
FROM alpine:3.20
RUN apk add --no-cache iptables ip6tables iproute2
COPY --from=build /out/wg-go-installer /usr/local/bin/wg-go-installer
VOLUME ["/etc/wireguard", "/var/lib/wg-go", "/clients"]
ENTRYPOINT ["/usr/local/bin/wg-go-installer"]
