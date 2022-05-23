#!/usr/bin/env bash
for ARCH in amd64 arm arm64; do
  echo "## Building ${ARCH}"
  GOOS=linux GOARCH=${ARCH} go build -o bin/patu.${ARCH} patu.go
done
