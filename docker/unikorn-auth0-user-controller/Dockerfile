FROM gcr.io/distroless/static:nonroot

# This is implcitly created by 'docker buildx build'
ARG TARGETARCH

COPY bin/${TARGETARCH}-linux/unikorn-auth0-user-controller /

ENTRYPOINT ["/unikorn-auth0-user-controller"]
