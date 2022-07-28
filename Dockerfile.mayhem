FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential meson afl++ bison flex pkg-config libxml2-dev cmake libwayland-dev wayland-protocols

COPY . /repo
WORKDIR /repo/build
RUN meson .. -Denable-x11=false -Denable-docs=false --prefix=/install
RUN ninja install

FROM ubuntu:22.04 as package
COPY --from=builder /repo/build/fuzz-keymap /
