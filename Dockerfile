FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/limitplane ./cmd/limitplane

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/limitplane /limitplane
COPY limitplane.example.json /etc/limitplane/config.json
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/limitplane"]
CMD ["--config", "/etc/limitplane/config.json"]
