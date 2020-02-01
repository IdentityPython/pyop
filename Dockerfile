FROM ubuntu:16.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && \
    apt-get -y dist-upgrade && \
    apt-get -y install \
        python3-pip \
        libpython3-dev \
        python-setuptools \
        build-essential \
        libssl-dev \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY ./ /usr/src/pyop
WORKDIR /usr/src/pyop
RUN python3 setup.py bdist_wheel && pip3 install dist/pyop-*.whl && \
    pip3 install -r example/requirements.txt

ENV FLASK_APP=pyop
EXPOSE 9090

CMD gunicorn -w 1 -b 0.0.0.0:9090 "example.wsgi:app" --certfile example/https.crt --keyfile example/https.key
