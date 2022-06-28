FROM curlimages/curl:7.66.0 AS build

ENV RELEASE h2-2018-03-18.zip
ENV SHA256 a45e7824b4f54f5d9d65fb89f22e1e75ecadb15ea4dcf8c5d432b80af59ea759

WORKDIR /tmp

RUN echo "$SHA256  $RELEASE" > $RELEASE.sha256 && \
	curl -sSL https://www.h2database.com/$RELEASE -o $RELEASE && \
	sha256sum -b -c $RELEASE.sha256 && \
	unzip $RELEASE && rm -f $RELEASE

# Copy binaries to minimal container image as part of Docker multistage build.
FROM gcr.io/distroless/java:11
WORKDIR /opt
COPY --from=build /tmp/h2/bin /opt/h2

# Make sure process runs as non-root user and group.
USER 1000:1000

# Expose default H2 TCP port.
EXPOSE 9092
# Configure container to run H2 server.
ENTRYPOINT ["java", "-Djava.security.egd=file:/dev/urandom", "-cp", "/opt/h2/h2-1.4.197.jar", "org.h2.tools.Server", "-tcp", "-tcpAllowOthers"]
