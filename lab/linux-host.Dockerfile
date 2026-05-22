ARG BASE_IMAGE=debian:12-slim
FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        iproute2 \
        iputils-ping \
        net-tools \
        nginx \
        openssh-server \
        procps \
        python3 \
        socat \
    && rm -rf /var/lib/apt/lists/*

COPY lab/start-linux-host.sh /usr/local/bin/start-linux-host.sh
RUN chmod +x /usr/local/bin/start-linux-host.sh

CMD ["/usr/local/bin/start-linux-host.sh"]
