FROM ubuntu:18.04

LABEL maintainer="Team STINGAR <team-stingar@duke.edu>"
LABEL name="rdphoney"
LABEL version="1.9.1"
LABEL release="1"
LABEL summary="RDPHoney Honeypot Container"
LABEL description="RDPHoney is a simple RDP connection honeypot"
LABEL authoritative-source-url="https://github.com/CommunityHoneyNetwork/rdphoney"
LABEL changelog-url="https://github.com/CommunityHoneyNetwork/rdphoney/commits/master"

# Set DOCKER var - used by RDPHoney init to determine logging
ENV DOCKER "yes"
ENV RDPHONEY_GROUP "rdphoney"
ENV RDPHONEY_USER "rdphoney"
ENV RDPHONEY_DIR "/opt"
ENV RDPHONEY_JSON_DIR "/etc/rdphoney/"
ENV DEBIAN_FRONTEND "noninteractive"

# hadolint ignore=DL3008,DL3005
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install --no-install-recommends -y python3-apt python3-dev python3-pip python3-setuptools python-twisted-core jq \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r -g 1000 ${RDPHONEY_GROUP} && \
    useradd -r -u 1000 -m -g ${RDPHONEY_GROUP} ${RDPHONEY_USER} && \
    touch /var/log/honeyrdp.log && \
    mkdir ${RDPHONEY_JSON_DIR} && \
    chown ${RDPHONEY_USER}:${RDPHONEY_GROUP} /var/log/honeyrdp.log ${RDPHONEY_JSON_DIR} && \
    chmod 644 /var/log/honeyrdp.log

WORKDIR ${RDPHONEY_DIR}

COPY entrypoint.sh requirements.txt /code/
RUN python3 -m pip install --no-cache-dir --upgrade pip setuptools pika requests fluent-logger cymruwhois \
  && python3 -m pip install -r /code/requirements.txt

COPY rdphoney ${RDPHONEY_DIR}/rdphoney
COPY rdphoney.cfg.dist ${RDPHONEY_DIR}

# Set permissions on rdphoney directory
RUN chown -R ${RDPHONEY_USER} ${RDPHONEY_DIR} && \
    chmod +x /code/entrypoint.sh

USER ${RDPHONEY_USER}

ENTRYPOINT ["/code/entrypoint.sh"]
