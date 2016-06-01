"""
Invokes webserver to be run at 127.0.0.1:8080
Should be run as: python3 -m ttproto.coordinator
"""
from .coord_webserver import *

if __name__ == "__main__":

    __shutdown = False

    def shutdown():
        global __shutdown
        __shutdown = True

server = http.server.HTTPServer(("0.0.0.0", 8080), RequestHandler)
print('Server is ready')
while not __shutdown:
    server.handle_request()
