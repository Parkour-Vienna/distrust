# Use distroless as minimal base image to package the distrust binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY distrust /
USER nonroot:nonroot

ENTRYPOINT ["/distrust"]
