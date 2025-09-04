FROM golang:1.12.4 as build
WORKDIR /go/src/minica
COPY main.go .
RUN go get && \
    CGO_ENABLED=0 go build -o /go/bin/minica

FROM scratch as run
COPY --from=build /go/bin/minica /minica
ENTRYPOINT ["/minica"]
CMD ["--help"]
