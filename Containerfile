# Hardened runtime image for kcc: a static musl binary on distroless/static, non-root,
# no shell, no package manager. Deployment, the seccomp allowlist and the verification
# procedure are in deploy/podman/README.md.
#
# Build with the Docker image format so Podman keeps the HEALTHCHECK:
#
#   podman build --format docker -t kcc:test .
#
# Both bases are pinned by the digest of their multi-arch index, so every architecture
# resolves through the same pinned list. Refresh a pin (and say so in the commit):
#
#   curl -sI -H 'Accept: application/vnd.oci.image.index.v1+json' \
#     https://gcr.io/v2/distroless/static-debian13/manifests/latest | grep -i content-digest
#
# or `skopeo inspect --raw docker://<image>:<tag> | sha256sum`.

FROM docker.io/library/rust:1.100.0-alpine@sha256:de1e0058543a81ed7b046629167db587c67a94bdf37cce14eb27f0ec83baaffb AS builder

# `ring` compiles C and needs the musl headers; confined to this throwaway stage.
RUN apk add --no-cache musl-dev

# Set by `podman build` / `docker buildx` to the target platform (amd64 or arm64). The
# builder runs on the target architecture (CI builds each one on a native runner).
ARG TARGETARCH

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY catalog ./catalog

# --locked: the committed Cargo.lock is the dependency record. The explicit musl triple
# makes staticness a property of this instruction rather than of the base, and the check
# below turns a dynamically linked binary into a failed build instead of an image that
# dies on `distroless/static` (no loader) with an unhelpful "no such file or directory".
# A dynamic ELF records its interpreter path; a static one has none. Checked with `grep`
# because the builder has no `file`/`readelf` and must not grow packages for it. The
# binary is not run here: the builder is root and kcc refuses root (exit 77).
# The cache mounts keep the registry and target directory between local rebuilds; they
# never reach the image.
RUN --mount=type=cache,id=kcc-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=kcc-target,target=/src/target \
    set -eu; \
    case "${TARGETARCH:-amd64}" in \
      amd64) triple=x86_64-unknown-linux-musl ;; \
      arm64) triple=aarch64-unknown-linux-musl ;; \
      *) echo "unsupported TARGETARCH ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    rustup target add "${triple}"; \
    cargo build --release --locked -p kcc --target "${triple}"; \
    cp "target/${triple}/release/kcc" /kcc; \
    strip /kcc; \
    if grep -qa 'ld-linux\|ld-musl' /kcc; then \
      echo "FATAL: kcc is dynamically linked; distroless/static has no loader." >&2; \
      exit 1; \
    fi

# distroless/static: CA bundle, tzdata, /etc/passwd with `nonroot` (65532) and /tmp, and
# neither a shell nor a package manager.
FROM gcr.io/distroless/static-debian13@sha256:448810357cc8e67b7208988abdba0f5ec3d3aebee0a5b13eb624979792cffc0f

ARG VERSION="0.1.0"
ARG VCS_REF=""
ARG BUILD_DATE=""
LABEL org.opencontainers.image.title="keenetic-control-center" \
      org.opencontainers.image.description="Web UI, MCP server and CLI for Keenetic and Netcraze routers." \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.source="https://github.com/andrico21/keenetic-control-center" \
      org.opencontainers.image.base.name="gcr.io/distroless/static-debian13@sha256:448810357cc8e67b7208988abdba0f5ec3d3aebee0a5b13eb624979792cffc0f"

COPY --from=builder --chmod=0755 /kcc /kcc

# State lives in a volume, configuration is mounted read-only, the master key comes from
# a Podman secret. The root filesystem is read-only at run time.
ENV KCC_STATE_DIR=/var/lib/kcc \
    KCC_MASTER_KEY_FILE=/run/secrets/kcc-master-key \
    HOME=/var/lib/kcc

# Web UI and MCP over TLS. The optional metrics listener (9090) is deliberately not
# exposed: publish it on host loopback only (deploy/podman/README.md).
EXPOSE 8443

USER 65532:65532

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
  CMD ["/kcc","healthcheck","--config","/etc/kcc/kcc.toml"]

ENTRYPOINT ["/kcc"]
CMD ["serve","--config","/etc/kcc/kcc.toml"]
