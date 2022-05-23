FROM golang:alpine AS build

RUN mkdir /build
ADD . /build/
WORKDIR /build
RUN go build -o patu patu.go

FROM alpine
COPY --from=build /build/patu /patu/patu
RUN adduser -S -D -H -h /patu patu && chown patu: /patu/patu && chmod +x /patu/patu
USER patu
EXPOSE 80/tcp
ENTRYPOINT ["/patu/patu"]
