FROM ubuntu:18.04

LABEL maintainer Alexander Merck <alexander.t.merck@gmail.com>
LABEL name "rdphoney"
LABEL version "0.1"
LABEL release "1"
LABEL summary "RDPHoney Honeypot Container"
LABEL description "RDPHoney is a simple RDP connection honeypot"
LABEL authoritative-source-url "https://github.com/CommunityHoneyNetwork/communityhoneynetwork"
LABEL changelog-url "https://github.com/breakfastdub/rdphoney/commits/master"

# Set DOCKER var - used by RDPHoney init to determine logging
ENV DOCKER "yes"
ENV RDPHONEY_GROUP "rdphoney"
ENV RDPHONEY_USER "rdphoney"
ENV RDPHONEY_DIR "/opt"
ENV RDPHONEY_JSON "/etc/rdphoney/rdphoney.json"

RUN apt-get update \
      && apt-get install -y python-apt \
      && apt-get install -y python3-dev python3-pip python-twisted-core jq

RUN groupadd -r -g 1000 ${RDPHONEY_GROUP} && \
    useradd -r -u 1000 -m -g ${RDPHONEY_GROUP} ${RDPHONEY_USER} && \
    touch /var/log/honeyrdp.log && \
    chown ${RDPHONEY_USER}:${RDPHONEY_GROUP} /var/log/honeyrdp.log && \
    chmod 644 /var/log/honeyrdp.log

WORKDIR ${RDPHONEY_DIR}

COPY entrypoint.sh requirements.txt /code/
RUN pip3 install --no-cache-dir --upgrade pip setuptools pika requests fluent-logger cymruwhois && \
    pip3 install -r /code/requirements.txt

COPY rdphoney ${RDPHONEY_DIR}/rdphoney
COPY rdphoney.cfg.dist ${RDPHONEY_DIR}

# Set permissions on rdphoney directory
RUN chown -R ${RDPHONEY_USER} ${RDPHONEY_DIR} && \
    chmod +x /code/entrypoint.sh

USER ${RDPHONEY_USER}

ENTRYPOINT ["/code/entrypoint.sh"]