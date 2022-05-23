# Golang patu http server

This is a debugging http server written in Golang to support on going debugging/testing

## Usage

Basic usage will require a listening hostname:port (Using 0.0.0.0 binds to all IPs)

```
patu --listen 0.0.0.0:80 
```

Adding `--verbose` adds more details. 

## Metrics

Metrics are available via `/metrics`

## Building

A simple `make` should suffice to build the binary after checkout

## Building in docker

To setup the cross compile build environmentg
```
sudo apt-get docker-ce docker-ce-cli containerd.io install binfmt-support qemu-user-static
docker buildx create --use --name cross-platform-build
```

To check the platforms we can build
```
docker buildx inspect --bootstrap cross-platform-build
```

To build and push at the same time
```
docker buildx build -f Dockerfile --platform linux/amd64,linux/arm64 -t visago/patu --push .
```
