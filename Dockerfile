# Multi-stage build: The final stage adds just 9 MB of our Go binary on the top of the base image, e.g.:
# fedora             29       24508ec0e667    260MB
# karm/serve-file    1.0.0    3cebf268c53e    269MB

# build stage
#############
# Why 25 and not 29? newer Curl/NSS on Fedora 27+ fails to handshake with the test
# certificates on the grounds of "unsupported purpose"; TODO: revisit cert extensions
FROM fedora:25 AS build-env
LABEL Author="Michal Karm Babacek <karm@email.cz"
ENV GOPATH /gopath
ENV PROJECT_DIR ${GOPATH}/src/github.com/Karm/serve-file/
ENV PATH ${PATH}:/opt/go/bin/:/opt/linux-amd64/
ENV GO_VERSION 1.11.4
ENV GLIDE_VERSION 0.13.2
WORKDIR /opt
RUN dnf install git gcc -y
RUN curl -L -O https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz
RUN tar -xvf go${GO_VERSION}.linux-amd64.tar.gz
RUN curl -L -O https://github.com/Masterminds/glide/releases/download/v${GLIDE_VERSION}/glide-v${GLIDE_VERSION}-linux-amd64.tar.gz
RUN tar -xvf glide-v${GLIDE_VERSION}-linux-amd64.tar.gz
ADD . ${PROJECT_DIR}
WORKDIR ${PROJECT_DIR}
RUN glide install
RUN GOARCH=amd64 GOOS=linux go build
RUN go test

# final stage
#############
FROM fedora:29
LABEL Author="Michal Karm Babacek <karm@email.cz"
RUN useradd -s /sbin/nologin serveit
RUN mkdir -p /opt/serveit && chown serveit /opt/serveit && chgrp serveit /opt/serveit && chmod ug+rwxs /opt/serveit
WORKDIR /opt/serveit/
EXPOSE 8443/tcp 6060/tcp
USER serveit
COPY --from=build-env /gopath/src/github.com/Karm/serve-file/serve-file /opt/serveit/
CMD ["/opt/serveit/serve-file"]
