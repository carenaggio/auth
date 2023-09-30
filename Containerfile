FROM docker.io/library/golang:1.21 as build

WORKDIR /go/src/app
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 go build -tags netgo -ldflags '-extldflags -static -s' -o /go/bin/auth *.go

FROM gcr.io/distroless/static-debian12
LABEL org.opencontainers.image.source https://github.com/carenaggio/auth
COPY --from=build /go/bin/auth /
CMD ["/auth"]
