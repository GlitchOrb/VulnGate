FROM golang:1.24 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/graphd ./services/graph/cmd/graphd

FROM gcr.io/distroless/base-debian12
COPY --from=build /out/graphd /graphd
EXPOSE 8090
ENTRYPOINT ["/graphd"]
