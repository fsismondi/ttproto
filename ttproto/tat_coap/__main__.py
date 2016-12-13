"""
Invokes webserver to be run at 127.0.0.1:2080
Should be run as: python3 -m ttproto.tat_coap
"""
import select
from .webserver import *
from .amqp_interface import *

SERVER_CONFIG = ("0.0.0.0", 2080)
# either amqp (amqp interface) or http (webserver)
INTERFACE = 'amqp'


def shutdown():
    global __shutdown
    __shutdown = True


def reopen_log_file(signum, frame):
    global log_file
    log_file = open(os.path.join(LOGDIR, "ttproto.tat_coap.log"), "a")


if __name__ == "__main__":

    logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)
    reopen_log_file(None, None)

    # log rotation
    # -> reopen the log file upon SIGHUP
    signal.signal(signal.SIGHUP, reopen_log_file)

    job_id = 0

    __shutdown = False

    for d in TMPDIR, DATADIR, LOGDIR:
        try:
            os.makedirs(d)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise

    if INTERFACE == 'http':
        def reopen_log_file(signum, frame):
            global log_file
            log_file = open(os.path.join(LOGDIR, "webserver.log"), "a")

        server = http.server.HTTPServer(SERVER_CONFIG, RequestHandler)
        print('Server is ready: %s:%s' %SERVER_CONFIG)
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

    elif INTERFACE == 'amqp':
        print('Starting AMQP interface of TAT')
        ## AMQP CONNECTION ##
        bootstrap_amqp_interface()

