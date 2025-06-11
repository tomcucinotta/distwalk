# Minimal docker image with the whole repository
FROM gcc:latest as build
RUN apt-get update && apt-get install -y \
    libssl-dev
COPY ./src /distwalk
WORKDIR /distwalk
RUN make clean all 

FROM busybox:glibc AS distwalk
COPY --from=build distwalk /distwalk
WORKDIR /distwalk
