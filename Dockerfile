FROM debian:buster AS build

RUN apt-get update -y && \
    apt-get install -y golang

WORKDIR /build

COPY . .

RUN go build

FROM debian:buster

COPY --from=build /build/minica /usr/bin/minica

RUN apt-get update -y && \
    apt-get install --no-install-recommends -y \
      curl ca-certificates openssl

WORKDIR /test
COPY tests.sh .
RUN ./tests.sh