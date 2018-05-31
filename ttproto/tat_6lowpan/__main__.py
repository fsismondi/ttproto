"""
Invokes webserver to be run at 127.0.0.1:2082
Should be run as: python3 -m ttproto.tat_6lowpan
"""
from .webserver import *

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
    log_file = open(os.path.join(LOGDIR, "tat-6lowpan-webserver.log"), "a")


reopen_log_file(None, None)

# log rotation
# -> reopen the log file upon SIGHUP
signal.signal(signal.SIGHUP, reopen_log_file)

server = http.server.HTTPServer(("127.0.0.1", 2082), RequestHandler)

print('Server is ready')
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
