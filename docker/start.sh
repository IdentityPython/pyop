#!/bin/sh

set -e
set -x

. /opt/pyop/bin/activate

# nice to have in docker run output, to check what
# version of something is actually running.
/opt/pyop/bin/pip freeze

export PYTHONPATH=/opt/pyop/src

start-stop-daemon --start \
    -c pyop:pyop \
    --exec /opt/pyop/bin/gunicorn \
    --pidfile /var/run/pyop.pid \
    --chdir /opt/pyop/src \
    -- \
    example.wsgi:app \
    -b :9090 \
    --certfile example/https.crt \
    --keyfile example/https.key

