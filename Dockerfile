# Stage 1: Build Go binary
FROM golang:latest AS builder
WORKDIR /app
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o terminal .

# Stage 2: Install xterm.js locally
FROM node:latest AS webbuilder
WORKDIR /web/
COPY package.json .
RUN npm install

# Stage 3: Runtime
FROM alpine:3.20
RUN apk add --no-cache bash
WORKDIR /app/
COPY --from=builder /app/terminal .
COPY --from=webbuilder /web/node_modules/ /app/web/
COPY index.html /app/web/index.html

EXPOSE 8080
CMD ["./terminal"]

