FROM fedora:29
LABEL Author="Michal Karm Babacek <karm@email.cz"
RUN useradd -s /sbin/nologin serveit
RUN mkdir -p /opt/serveit && chown serveit /opt/serveit && chgrp serveit /opt/serveit && chmod ug+rwxs /opt/serveit
WORKDIR /opt/serveit
EXPOSE 443/tcp
USER serveit
ADD serve-file /opt/serveit
CMD ["/opt/serveit/serve-file"]