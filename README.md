# pySimpleHTTPSServer
Simple HTTPS Server in Python 

HTTPS server requires certificate.  For test purposes create certificate using below command:

openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
