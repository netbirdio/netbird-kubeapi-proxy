FROM gcr.io/distroless/static:nonroot
ARG TARGETOS
ARG TARGETARCH
LABEL org.opencontainers.image.title="NetBird Kubernetes API Proxy" \
      org.opencontainers.image.description="Authorization proxy of Kubernetes API server using NetBird connections as identities." \
      org.opencontainers.image.source="https://github.com/netbirdio/netbird-kubeapi-proxy" \
      org.opencontainers.image.vendor="NetBird" \
      org.opencontainers.image.licenses="BSD-3-Clause"
COPY bin/${TARGETOS}-${TARGETARCH}/netbird-kubeapi-proxy /usr/local/bin/
USER 65532:65532
ENTRYPOINT ["netbird-kubeapi-proxy"]
