FROM golang:alpine AS build
RUN apk add make git
RUN mkdir /build
ADD . /build/
WORKDIR /build
RUN make

FROM alpine
COPY --from=build /build/bin/patu /patu/patu
RUN adduser -S -D -H -h /patu patu && chown patu: /patu/patu && chmod +x /patu/patu
USER patu
EXPOSE 80/tcp
ENTRYPOINT ["/patu/patu"]
