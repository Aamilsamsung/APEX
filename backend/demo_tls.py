"""Run a registered local TLS endpoint with the currently active sandbox certificate."""
from __future__ import annotations
import http.server, ssl, threading, time
from . import core

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b'AEGIS sandbox TLS endpoint')
    def log_message(self,*args): pass

def serve(port=8443, hostname='service-01.demo.local'):
    core.seed()
    print(f'AEGIS sandbox TLS server at https://127.0.0.1:{port} for {hostname}')
    last=None
    while True:
        with core.connect() as db:
            cert=db.execute('SELECT path,key_path,id FROM certificates WHERE hostname=? AND active=1',(hostname,)).fetchone()
        if not cert:
            # Inventory may be reset by test fixtures or a concurrent sandbox reset.
            # Stop cleanly instead of raising an unhandled background-thread exception.
            print(f'AEGIS sandbox TLS server stopped: no active certificate for {hostname}')
            return
        if cert['id']!=last:
            last=cert['id']; print('Deploying certificate',last)
        server=http.server.HTTPServer(('127.0.0.1',port),Handler)
        server.timeout=0.5
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert['path'],cert['key_path'])
        server.socket=context.wrap_socket(server.socket,server_side=True)
        try:
            while True:
                server.handle_request()
                with core.connect() as db:
                    active=db.execute('SELECT id FROM certificates WHERE hostname=? AND active=1',(hostname,)).fetchone()
                if not active or active['id']!=last: break
        finally: server.server_close()

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description='Authorized loopback TLS sandbox server')
    parser.add_argument('--port',type=int,default=8443)
    parser.add_argument('--hostname',default='service-01.demo.local')
    args=parser.parse_args()
    if not 1024<=args.port<=65535: parser.error('port must be between 1024 and 65535')
    if not args.hostname.endswith('.demo.local'): parser.error('only sandbox demo.local hostnames are supported')
    serve(port=args.port,hostname=args.hostname)
