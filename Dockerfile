ARG ARCH="amd64"
ARG OS="linux"
FROM scratch
LABEL description="Prometheus collector / reflector endpoint, built in golang" owner="dockerfile@paulschou.com"

EXPOSE      9550
ADD ./LICENSE /LICENSE
ADD ./prom-collector "/prom-collector"
ENTRYPOINT  [ "/prom-collector" ]
