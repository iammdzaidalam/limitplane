FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
# cross-compile for the target instead of building under emulation
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/limitplane ./cmd/limitplane

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/limitplane /limitplane
COPY limitplane.example.json /etc/limitplane/config.json
EXPOSE 8080
# numeric, so the kubelet can verify runAsNonRoot
USER 65532:65532
ENTRYPOINT ["/limitplane"]
CMD ["--config", "/etc/limitplane/config.json"]
