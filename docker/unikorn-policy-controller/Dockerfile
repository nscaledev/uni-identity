FROM gcr.io/distroless/static:nonroot

# This is implcitly created by 'docker buildx build'
ARG TARGETARCH

# The compile gate exec's this vendored binary (`cerbos compile`) on every
# candidate policy store before publishing it.  The upstream image is FROM
# scratch with a static binary, so a single COPY is safe.  The tag is pinned:
# it must match CERBOS_VERSION in the Makefile (enforced by the
# validate-cerbos-version guard).
COPY --from=ghcr.io/cerbos/cerbos:0.53.0 /cerbos /usr/local/bin/cerbos

COPY bin/${TARGETARCH}-linux/unikorn-policy-controller /

ENTRYPOINT ["/unikorn-policy-controller"]
