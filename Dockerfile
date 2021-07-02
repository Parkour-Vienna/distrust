# Use distroless as minimal base image to package the distrust binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM debian:buster-slim
WORKDIR /
COPY distrust /
RUN useradd -ms /bin/bash nonroot

EXPOSE 3000

ENTRYPOINT ["/distrust"]
