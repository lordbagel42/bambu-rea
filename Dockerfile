# Static bambu-api binary on a distroless base. SQLite is pure Go (modernc), so
# CGO stays off and the image is the binary plus CA certificates.
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w -X main.version=${VERSION}" -o /out/bambu-api ./cmd/bambu-api

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/bambu-api /bambu-api
# /data is the persistent volume; -db defaults there through BAMBU_DB.
ENV BAMBU_API_ADDR=:8080 BAMBU_DB=/data/bambu-api.sqlite
EXPOSE 8080
USER nonroot
ENTRYPOINT ["/bambu-api"]
