'''
Created on 11 Jul 2020

@author: mitch
'''

from wsgiref.simple_server import make_server
import json
import ssl
import hashlib
import secrets
import base64
import re

# create hash by:  import hashlib;  hashlib.sha256(b"robot:robotpassword").hexdigest()
TEST_USER_HASH = '59d059b790d39db63da65d1c51362a2176b6f344dc7692c90fb833e54d3f0d28'
TEST_USER_MD5 = 'cm9ib3Q6cm9ib3RwYXNzd29yZA=='
TEST_USER_AGENT = 'lab/testUserAgent'

HTTP_DIGEST_REALM = 'auth.lab'
HTTP_DIGEST_OPAQUE = nonce = secrets.token_hex()

FAKE_USER_DB = { 'labuser' : 'labuserpassword' }

def password_lookup(user):

    return FAKE_USER_DB.get(user)

def md5(s):

    return hashlib.md5(bytes(s, 'utf-8')).hexdigest()

def doSSL(sock, certfile, keyfile, ca_certs=None):
    
    ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH, cafile=None, capath=None, cadata=None)
    
    return ssl.wrap_socket(sock, do_handshake_on_connect=True,
                                    server_side=True, certfile=certfile,
                                    keyfile=keyfile,
                                    ssl_version=ssl.PROTOCOL_TLS,
                                    ca_certs=ca_certs)
    

def authenticate(environ):
    
    if ('HTTP_AUTHORIZATION' in environ):
        
        if ('Basic' in environ['HTTP_AUTHORIZATION']):
            
            userPass = environ['HTTP_AUTHORIZATION'].replace('Basic ', '')
            
            return (hashlib.sha256(bytes(base64.b64decode(userPass))).hexdigest() == TEST_USER_HASH)

        elif ('Digest' in environ['HTTP_AUTHORIZATION']):

            print(environ)
            auth_values = environ['HTTP_AUTHORIZATION'].split(',')

            username = ''            
            match = re.match(r'.*username="(.*?)",?.*', environ['HTTP_AUTHORIZATION'])
            if (match is not None):
                username = match.group(1).replace('"', '')

            realm = ''
            match = re.match(r'.*realm="(.*?)",?.*', environ['HTTP_AUTHORIZATION'])
            if (match is not None):
                realm = match.group(1).replace('"', '')

            nc = ''
            match = re.match(r'.*nc=(.*?),.*', environ['HTTP_AUTHORIZATION'])
            if (match is not None):
                nc = match.group(1).replace('"', '')

            nonce = ''
            match = re.match(r'.* nonce="(.*?)",?.*', environ['HTTP_AUTHORIZATION'])
            if (match is not None):
                nonce = match.group(1).replace('"', '')

            cnonce = ''
            match = re.match(r'.*cnonce="(.*?)",?.*', environ['HTTP_AUTHORIZATION'])
            if (match is not None):
                cnonce = match.group(1).replace('"', '')

            qop = ''
            match = re.match(r'.*qop=(.*?),.*', environ['HTTP_AUTHORIZATION'])
            if (match is not None):
                qop = match.group(1).replace('"', '')

            response = ''
            match = re.match(r'.*response="(.*?)",?.*', environ['HTTP_AUTHORIZATION'])
            if (match is not None):
                response = match.group(1).replace('"', '')

            method = environ['REQUEST_METHOD']
            path = environ['PATH_INFO']


            #print('%s:%s:%s' % (username, realm, password_lookup(username)))
            #print('%s:%s' % (method, path))
            HA1 = str(md5('%s:%s:%s' % (username, realm, password_lookup(username))))
            HA2 = str(md5('%s:%s' % (method, path)))

            #print('%s:%s:%s:%s:%s:%s' % (HA1, nonce, nc, cnonce, qop, HA2))

            response_calc = str(md5('%s:%s:%s:%s:%s:%s' % (HA1, nonce, nc, cnonce, qop, HA2)))

            print('Calculated Response: %s' % (response_calc))
            print('Client Response: %s' % (response))

            return response_calc == response

        
    return False

def checkUserAgent(environ):
    
    if ('HTTP_USER_AGENT' in environ):
        
        return (environ['HTTP_USER_AGENT'] == TEST_USER_AGENT)
    
    return False


# test with below:
# curl -H "Content-Type: application/json" -A "lab/testUserAgent" --request POST --data '{"data":"test","function":"deploy"}' --user robot:robotpassword --insecure https://localhost:8000
def simple_auth_app(environ, start_response):
    
    print('Environment: ')
    print(environ)
    
    if (authenticate(environ) and checkUserAgent(environ)):
        
        if (environ['CONTENT_TYPE'] == 'application/json'):
    
            request_body_size = 0
            try:
                request_body_size = int(environ.get('CONTENT_LENGTH', 0))
            except (ValueError):
                request_body_size = 0
        
            request_body = environ['wsgi.input'].read(request_body_size)
            
            data = None
            try:
                data = json.loads(request_body)
            except (ValueError):
                print('Invalid JSON Data received')
                
            print('Received Data')
            print(data)
    

            
            status = '200 OK'
            headers = [('Content-type', 'application/json; charset=utf-8')]
        
            start_response(status, headers)
        
            #ret = [("%s: %s\n" % (key, value)).encode("utf-8") for key, value in environ.items()]
            ret = bytes(json.dumps(data), 'utf-8')
            return [ret]
        
        else:
            status = '400 Bad Request'
            headers = [('Content-type', 'text/plain; charset=utf-8')]
              
            start_response(status, headers)
            
            return [b'400 Bad Request']            
    
    else:
        status = '403 Forbidden'
        headers = [('Content-type', 'text/plain; charset=utf-8')]
          
        start_response(status, headers)
        
        return [b'403 Forbidden']


def simple_digest_auth_app(environ, start_response):

    if (authenticate(environ)):

        status = '200 OK'   

        start_response(status, [])

        return [b'Digest Authentication Successful']

    else:
        
        status = '401 Unauthorized'
        nonce = secrets.token_hex()
        headers = [('WWW-Authenticate', 'Digest realm="%s",qop="auth",nonce="%s",opaque="%s"' % (HTTP_DIGEST_REALM, nonce, HTTP_DIGEST_OPAQUE))]

        start_response(status, headers)

        return [b'401 Unauthorized']

# test with below:
# curl -H "Content-Type: application/json" --request POST --data '{"data":"test","function":"deploy"}' localhost:8000
def simple_app_v2(environ, start_response):
    
    request_body_size = 0
    try:
        request_body_size = int(environ.get('CONTENT_LENGTH', 0))
    except (ValueError):
        request_body_size = 0

    request_body = environ['wsgi.input'].read(request_body_size)
    data = json.loads(request_body)
    print('Received Data')
    print(data)

    status = '200 OK'
    #headers = [('Content-type', 'text/plain; charset=utf-8')]
    headers = [('Content-type', 'application/json; charset=utf-8')]

    start_response(status, headers)

    #ret = [("%s: %s\n" % (key, value)).encode("utf-8") for key, value in environ.items()]
    ret = bytes(json.dumps(data), 'utf-8')
    return [ret]

def simple_app(environ, start_response):

    status = '200 OK'
    headers = [('Content-type', 'application/json; charset=utf-8')]

    start_response(status, headers)

    #ret = [("%s: %s\n" % (key, value)).encode("utf-8") for key, value in environ.items()]
    ret = bytes(json.dumps({'data':1}), 'utf-8')
    return [ret]
    
with make_server('', 8000, simple_digest_auth_app) as httpd:
    print("Serving HTTP on port 8000...")
    
    print(httpd.socket)
    httpd.socket = doSSL(httpd.socket, 'cert.pem', 'key.pem', ca_certs=None)
    
    # Respond to requests until process is killed
    httpd.serve_forever()
    
    # Alternative: serve one request, then exit
    #httpd.handle_request()
    
