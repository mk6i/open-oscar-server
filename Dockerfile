FROM golang:1.25.5-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o open_oscar_server ./cmd/server

FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/open_oscar_server /app/

EXPOSE 5190 8080 9898 1088 4000/udp

CMD ["/app/open_oscar_server"]
