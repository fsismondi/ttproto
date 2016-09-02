"""
Invokes webserver to be run at 127.0.0.1:2080
Should be run as: python3 -m ttproto.ts_coap
"""
from .webserver import *

SERVER_CONFIG = ("0.0.0.0", 2080)

if __name__ == "__main__":

    reopen_log_file(None, None)

    __shutdown = False

    def shutdown():
        global __shutdown
        __shutdown = True

    for d in TMPDIR, DATADIR, LOGDIR:
        try:
            os.makedirs(d)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise


def reopen_log_file(signum, frame):
    global log_file
    log_file = open(os.path.join(LOGDIR, "webserver.log"), "a")


reopen_log_file(None, None)

# log rotation
# -> reopen the log file upon SIGHUP
signal.signal(signal.SIGHUP, reopen_log_file)

server = http.server.HTTPServer(SERVER_CONFIG, RequestHandler)
print('Server is ready: %s:%s'%(SERVER_CONFIG))
while not __shutdown:
    try:
        l = log_file
        server.handle_request()
    except select.error:
        # do not abort when we receive a signal
        if l == log_file:
            raise

    if len(sys.argv) > 1:
        break
