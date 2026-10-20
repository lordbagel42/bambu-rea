# bambu-api stays a static CGO-free binary (SQLite is pure Go). Camera
# streaming adds bambu-tunnel, a small cgo helper that loads Bambu Studio's
# closed network plugin (libBambuSource.so) in its own process; the plugin is
# fetched from Bambu's CDN at build time and pinned by hash, never vendored.
FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w -X main.version=${VERSION}" -o /out/bambu-api ./cmd/bambu-api \
 && CGO_ENABLED=1 GOFLAGS=-trimpath go build -ldflags="-s -w" -o /out/bambu-tunnel ./cmd/bambu-tunnel

# Bambu Studio network plugin (Linux x86_64). Discovery:
# GET https://api.bambulab.com/v1/iot-service/api/slicer/resource?slicer/plugins/cloud=<studio version>
ARG PLUGIN_VERSION=02.08.04.60
ARG PLUGIN_URL=https://public-cdn.bblmw.com/upgrade/studio/plugins/02.08.04.60/fd41e5cc78/linux_02.08.04.60.zip
ARG PLUGIN_SHA256=f73d12ec8a179160b78bc58e28dcb71f04bbee3669f3ef45375164ae7d3b8c59
RUN apt-get update && apt-get install -y --no-install-recommends unzip \
 && curl -fsSL -o /tmp/plugin.zip "$PLUGIN_URL" \
 && echo "$PLUGIN_SHA256  /tmp/plugin.zip" | sha256sum -c - \
 && mkdir -p /out/plugin \
 && unzip -q /tmp/plugin.zip -d /out/plugin libBambuSource.so libagora_rtc_sdk.so libagora-fdkaac.so

# libagora_rtc_sdk.so (X1/H2 live view) links X11/DRM, so the runtime is slim
# Debian rather than distroless.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates libstdc++6 libx11-6 libxext6 libxfixes3 libxdamage1 libdrm2 zlib1g \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 65532 --home /nonexistent --shell /usr/sbin/nologin nonroot
COPY --from=build /out/bambu-api /out/bambu-tunnel /usr/local/bin/
COPY --from=build /out/plugin /opt/bambu-plugin
# /data is the persistent volume; -db defaults there through BAMBU_DB.
ENV BAMBU_API_ADDR=:8080 BAMBU_DB=/data/bambu-api.sqlite \
    BAMBU_SOURCE_LIB=/opt/bambu-plugin/libBambuSource.so LD_LIBRARY_PATH=/opt/bambu-plugin
EXPOSE 8080
USER nonroot
ENTRYPOINT ["/usr/local/bin/bambu-api"]
