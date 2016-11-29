FROM ubuntu:16.04

ENV DEBIAN_FRONTEND noninteractive

RUN /bin/echo -e "deb http://se.archive.ubuntu.com/ubuntu xenial main restricted universe\ndeb http://archive.ubuntu.com/ubuntu xenial-updates main restricted universe\ndeb http://security.ubuntu.com/ubuntu xenial-security main restricted universe" > /etc/apt/sources.list

RUN apt-get update && \
    apt-get -y dist-upgrade && \
    apt-get -y install \
        python3-pip \
        python-virtualenv \
        libpython3-dev \
        python-setuptools \
        build-essential \
        libffi-dev \
        libssl-dev \
        iputils-ping \
    && apt-get clean

RUN rm -rf /var/lib/apt/lists/*

RUN adduser --system --no-create-home --shell /bin/false --group pyop

COPY . /opt/pyop/src/
COPY docker/setup.sh /opt/pyop/setup.sh
COPY docker/start.sh /start.sh
RUN /opt/pyop/setup.sh

# Add Dockerfile to the container as documentation
COPY Dockerfile /Dockerfile

WORKDIR /

EXPOSE 9090

CMD ["bash", "/start.sh"]
