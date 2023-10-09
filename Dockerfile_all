# Minimal docker image with the whole repository
FROM gcc:latest as build
COPY ./src /distwalk
WORKDIR /distwalk
RUN make clean && make

FROM busybox:glibc AS distwalk
COPY --from=build distwalk /distwalk
WORKDIR /distwalk
