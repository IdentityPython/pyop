# pyOP example application 
To run the example application, execute the following commands:

```bash
cd example/
pip install -r requirements.txt # install the dependencies
gunicorn wsgi:app -b :9090 --certfile https.crt --keyfile https.key # run the application
```