# pyOP example application
To run the example application, execute the following commands in main directory:

```bash
python setup.py bdsit_wheel # Build wheel locally in order to make changes and test with example
pip install dist/pyop-*.whl # Install wheel
pip install -r example/requirements.txt # install the dependencies
gunicorn example.wsgi:app -b 0.0.0.0:9090 --certfile https.crt --keyfile https.key # run the application
```

To run the application with Docker:
```bash
docker build .
docker run -d -p 9090:9090 <image_hash>
```

## Application Setup
 Helpful things to note before running example:
- Set any user data that needs to be returned in the **/userinfo** response **app.users** variable in app.py
- There are optional variables that might be required to be added to the **RSAKey()** to get example to work such as __kid__

## Getting started
Note that the **/registartion** endpoint should be used to register your RP/web application with the this example OP
This endpoint might be useful to specify things like:
- redirect_uris
- token_endpoint_auth_method (if using a different aside from basic auth method)
