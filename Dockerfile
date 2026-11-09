# The snapshot builder image (cmd/shipward-snapshot): one static Go binary on Chainguard's static base (no shell, no
# package manager), running as the nonroot user (65532). It runs once a day and needs a writable /tmp for the
# downloads; the root file system can stay read-only.
#
#   docker build -t shipward-snapshot . && docker run --rm -e SNAPSHOT_SIGNING_KEY=... -v "$PWD/out:/out" shipward-snapshot -out /out
#
# Images are pinned by digest; Renovate (.github/renovate.json5) proposes updates.
FROM golang:1.26.10-trixie@sha256:fd9a91f0ece5664556f4851d06dce5e5b505a71166dffd385a03ba9d200b6983 AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /shipward-snapshot ./cmd/shipward-snapshot

FROM cgr.dev/chainguard/static:latest@sha256:9e2306b457ff71ce370043dc68c7b52bb1e6622c1c6c6714edbed57496f3116e
COPY --from=build /shipward-snapshot /shipward-snapshot
USER 65532:65532
ENTRYPOINT ["/shipward-snapshot"]
