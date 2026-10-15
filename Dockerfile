FROM golang:1.27.2-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o open_oscar_server ./cmd/server

FROM alpine:3.24

WORKDIR /app

COPY --from=builder /app/open_oscar_server /app/

EXPOSE 5190 5191 8080 8081 9898 1088 4000/udp

CMD ["/app/open_oscar_server"]
