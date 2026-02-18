# buildbot/buildbot-worker-python-node

# This example docker file show how to customize the base worker docker image
# to add build dependencies to build the python+nodejs buildbot_www package

FROM        buildbot/buildbot-worker:master@sha256:21c050440c64fffdae89f2d33862ee3c26652b9fe21f2e2d98d2bd453ea43e1a
MAINTAINER  Buildbot maintainers

# This will make apt-get install without question
ARG         DEBIAN_FRONTEND=noninteractive

USER root

# Install required npm packages
RUN  curl -sL https://deb.nodesource.com/setup_6.x | bash - && \
        apt-get update && apt-get install -y -o APT::Install-Recommends=false -o APT::Install-Suggests=false \
        nodejs \
        git && \
    rm -rf /var/lib/apt/lists/*

USER buildbot
