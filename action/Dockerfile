FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /awsdeny .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates curl jq
COPY --from=builder /awsdeny /usr/local/bin/awsdeny
COPY action/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
