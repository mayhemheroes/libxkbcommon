FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential meson afl++ bison flex pkg-config libxml2-dev cmake libwayland-dev wayland-protocols clang

COPY . /repo
WORKDIR /repo/build
RUN meson .. -Denable-x11=false -Denable-docs=false --prefix=/install
RUN ninja install
WORKDIR /repo/src
RUN clang -c utils.c -I /repo/build
RUN clang++ /repo/mayhem/fuzz_istrcmp.cpp -fsanitize=fuzzer,address /repo/src/utils.o -o /fuzz

FROM ubuntu:22.04 as package
COPY --from=builder /repo/build/fuzz-keymap /
COPY --from=builder /fuzz /fuzz_istrcmp
