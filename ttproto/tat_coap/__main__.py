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

    if INTERFACE == 'http':
        def reopen_log_file(signum, frame):
            global log_file
            log_file = open(os.path.join(LOGDIR, "webserver.log"), "a")


        reopen_log_file(None, None)

        # log rotation
        # -> reopen the log file upon SIGHUP
        signal.signal(signal.SIGHUP, reopen_log_file)

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

        for d in TMPDIR, DATADIR, LOGDIR:
            try:
                os.makedirs(d)
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise

        ## AMQP API ENTRY POINTS ##
        logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.WARNING)

        connection = pika.BlockingConnection(pika.ConnectionParameters(
            host='localhost'))

        channel = connection.channel()

        services_queue_name = 'services_queue@%s' % COMPONENT_ID
        channel.queue_declare(queue=services_queue_name)

        channel.queue_bind(exchange=DEFAULT_EXCHANGE,
                           queue=services_queue_name,
                           routing_key='control.analysis.service')
        # Hello world message
        channel.basic_publish(
            body=json.dumps({'value': 'TAT is up!','_type': 'analysis.info'}),
            routing_key='control.analysis.info',
            exchange=DEFAULT_EXCHANGE,
        )

        channel.basic_qos(prefetch_count=1)
        channel.basic_consume(on_request, queue=services_queue_name)

        print(" [x] Awaiting for analysis requests")
        channel.start_consuming()