FROM golang:1.16-alpine AS build
ARG VERSION=latest
ARG GIT_HASH

WORKDIR /src

# Allow for caching
COPY go.mod go.sum ./
RUN go mod download

COPY / .

RUN GO111MODULE=on GOFLAGS=-mod=vendor CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -a -ldflags "-s -w -X github.com/spdx/spdx-sbom-generator/version.Version=${VERSION} -X github.com/spdx/spdx-sbom-generator/version.GitHash=${GIT_HASH}" \
    -o spdx-sbom-generator ./cmd/generator/generator.go

FROM golang:1.16-alpine
ENV USERNAME=spdx-sbom-generator

COPY --from=build /src/spdx-sbom-generator /spdx-sbom-generator

ENTRYPOINT ["/spdx-sbom-generator"]

CMD ["-h"]
