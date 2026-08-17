FROM golang:1.26-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /google-password-notifier ./cmd/notifier/

FROM gcr.io/distroless/static-debian12

COPY --from=builder /google-password-notifier /google-password-notifier

ENTRYPOINT ["/google-password-notifier"]
