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

    result = Analyzer('tat_privacy').analyse('./tests/test_dumps/coap/TD_COAP_CORE_01_PASS.pcap', 'TD_COAP_ANALYSIS_1')

    for res in result:
        print(res)
    if result[1] != 'pass' and len(result[5]) > 0:
        import traceback

        traceback.print_tb(result[5][0][2])
    shutdown()

def reopen_log_file(signum, frame):
    global log_file
    log_file = open(os.path.join(LOGDIR, "tat-6lowpan-webserver.log"), "a")


reopen_log_file(None, None)

# log rotation
# -> reopen the log file upon SIGHUP
signal.signal(signal.SIGHUP, reopen_log_file)

server = http.server.HTTPServer(("0.0.0.0", 2082), RequestHandler)
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
