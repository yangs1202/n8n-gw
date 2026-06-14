FROM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/n8n-gw ./cmd/n8n-proxy

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/n8n-gw /n8n-gw
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/n8n-gw"]
