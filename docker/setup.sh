#!/bin/bash
#
# Install all requirements
#

set -e
set -x

PYPI="https://pypi.nordu.net/simple/"
ping -c 1 -q pypiserver.docker && PYPI="http://pypiserver.docker:8080/simple/"

echo "#############################################################"
echo "$0: Using PyPi URL ${PYPI}"
echo "#############################################################"

virtualenv -p python3 /opt/pyop
/opt/pyop/bin/pip install -U pip

# setup.py points to current directory
# so we need to change to the right one.
cd /opt/pyop/src

/opt/pyop/bin/python3 setup.py install
/opt/pyop/bin/pip install Flask
/opt/pyop/bin/pip install gunicorn
