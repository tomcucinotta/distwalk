# Minimal docker image with the whole repository
FROM gcc:latest as build
RUN apt-get update && apt-get install -y \
    libssl-dev
COPY ./src /distwalk

WORKDIR /distwalk
RUN make clean all 

FROM busybox:glibc AS distwalk
COPY --from=build distwalk /distwalk
COPY --from=build /lib/x86_64-linux-gnu/libssl.so.3 /lib
COPY --from=build /lib/x86_64-linux-gnu/libcrypto.so.3 /lib
RUN chmod +x /lib/libssl.so.3 /lib/libcrypto.so.3

WORKDIR /distwalk
