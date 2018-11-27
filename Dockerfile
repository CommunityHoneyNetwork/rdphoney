FROM centos:centos7

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
ENV playbook "rdphoney.yml"

RUN yum install -y epel-release \
    && yum install -y ansible

RUN echo "localhost ansible_connection=local" >> /etc/ansible/hosts
ADD . /opt/
RUN ansible-playbook /opt/${playbook}

ENTRYPOINT ["/sbin/runsvdir", "-P", "/etc/service"]
