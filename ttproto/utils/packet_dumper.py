import os
import json
import pika
import signal
import shutil
import logging
from datetime import datetime

# use this as main and also lib:
try:
    from messages import *
    from pure_pcapy import Dumper, Pkthdr, DLT_RAW, DLT_IEEE802_15_4_NOFCS
except:
    from .messages import *
    from .pure_pcapy import Dumper, Pkthdr, DLT_RAW, DLT_IEEE802_15_4_NOFCS

try:
    # For Python 3.0 and later
    from urllib.parse import urlparse
except ImportError:
    # Fall back to Python 2
    from urlparse import urlparse

logger = logging.getLogger(__name__)

VERSION = '0.1.0'


def launch_amqp_data_to_pcap_dumper(amqp_url=None, amqp_exchange=None, topics=None, dump_dir=None):
    def signal_int_handler(self, frame):
        logger.info('got SIGINT, stopping dumper..')

        if pcap_dumper:
            pcap_dumper.stop()

    signal.signal(signal.SIGINT, signal_int_handler)

    if amqp_url and amqp_exchange:
        amqp_exchange = amqp_exchange
        amqp_url = amqp_url

    else:
        try:
            amqp_exchange = str(os.environ['AMQP_EXCHANGE'])
            print('Imported AMQP_EXCHANGE env var: %s' % amqp_exchange)
        except KeyError as e:
            amqp_exchange = "amq.topic"
            print('Cannot retrieve environment variables for AMQP EXCHANGE. Loading default: %s' % amqp_exchange)
        try:
            amqp_url = str(os.environ['AMQP_URL'])
            print('Imported AMQP_URL env var: %s' % amqp_url)
            p = urlparse(amqp_url)
            user = p.username
            server = p.hostname
            logger.info(
                "Env variables imported for AMQP connection, User: {0} @ Server: {1} ".format(user,
                                                                                              server))
        except KeyError:
            print('Cannot retrieve environment variables for AMQP connection. Loading defaults..')
            # load default values
            amqp_url = "amqp://{0}:{1}@{2}/{3}".format("guest", "guest", "localhost", "/")

    if topics:
        pcap_amqp_topic_subscriptions = topics
    else:
        pcap_amqp_topic_subscriptions = [
            MsgTestingToolTerminate.routing_key,
            '#.fromAgent.#',  # API v.0.1 fixme deprecate this
            'fromAgent.#',  # API v.1.0
        ]
    # init pcap_dumper
    pcap_dumper = AmqpDataPacketDumper(
        amqp_url=amqp_url,
        amqp_exchange=amqp_exchange,
        topics=pcap_amqp_topic_subscriptions,
        dump_dir=dump_dir,
    )
    # start pcap_dumper
    pcap_dumper.run()


class AmqpDataPacketDumper:
    """
    Sniffs data from serial captures from bus and dumps into pcap file (assumes that frames are DLT_IEEE802_15_4)
    Sniffs data from tun captures from bus and dumps into pcap file (assumes that frames are DLT_RAW)

    about pcap header:
        ts_sec: the date and time when this packet was captured. This value is in seconds since January 1,
            1970 00:00:00 GMT; this is also known as a UN*X time_t. You can use the ANSI C time() function
            from time.h to get this value, but you might use a more optimized way to get this timestamp value.
            If this timestamp isn't based on GMT (UTC), use thiszone from the global header for adjustments.

        ts_usec: in regular pcap files, the microseconds when this packet was captured, as an offset to ts_sec.
            In nanosecond-resolution files, this is, instead, the nanoseconds when the packet was captured, as
            an offset to ts_sec
            /!\ Beware: this value shouldn't reach 1 second (in regular pcap files 1 000 000;
            in nanosecond-resolution files, 1 000 000 000); in this case ts_sec must be increased instead!

        incl_len: the number of bytes of packet data actually captured and saved in the file. This value should
            never become larger than orig_len or the snaplen value of the global header.

        orig_len: the length of the packet as it appeared on the network when it was captured. If incl_len and
            orig_len differ, the actually saved packet size was limited by snaplen.
    """
    COMPONENT_ID = 'capture_dumper_%s' % uuid.uuid1()  # uuid in case several dumpers listening to bus
    DEFAULT_DUMP_DIR = 'tmp'

    DEFAULT_RAWIP_DUMP_FILENAME = "DLT_RAW.pcap"
    DEFAULT_802154_DUMP_FILENAME = "DLT_IEEE802_15_4_NO_FCS.pcap"
    NETWORK_DUMPS = [DEFAULT_802154_DUMP_FILENAME, DEFAULT_RAWIP_DUMP_FILENAME]

    DEFAULT_RAWIP_DUMP_FILENAME_WR = "DLT_RAW.pcap~"
    DEFAULT_802154_DUMP_FILENAME_WR = "DLT_IEEE802_15_4_NO_FCS.pcap~"
    NETWORK_DUMPS_TEMP = [DEFAULT_RAWIP_DUMP_FILENAME_WR, DEFAULT_802154_DUMP_FILENAME_WR]

    QUANTITY_MESSAGES_PER_PCAP = 100

    def __init__(self, amqp_url, amqp_exchange, topics, dump_dir=None):

        self.messages_dumped = 0
        self.url = amqp_url
        self.exchange = amqp_exchange

        if dump_dir:
            self.dump_dir = dump_dir
        else:
            self.dump_dir = self.DEFAULT_DUMP_DIR

        if not os.path.exists(self.dump_dir):
            os.makedirs(self.dump_dir)

        # pcap dumpers
        self.pcap_15_4_dumper = None
        self.pcap_raw_ip_dumper = None
        self.dumpers_init()

        # AMQP stuff
        self.connection = pika.BlockingConnection(pika.URLParameters(self.url))  # queues & default exchange declaration
        self.channel = self.connection.channel()

        self.data_queue_name = 'data@%s' % self.COMPONENT_ID
        self.channel.queue_declare(queue=self.data_queue_name,
                                   auto_delete=True,
                                   arguments={'x-max-length': 1000}
                                   )

        # subscribe to data plane channels
        for t in topics:
            self.channel.queue_bind(exchange=self.exchange,
                                    queue=self.data_queue_name,
                                    routing_key=t)

        # subscribe to channel where the terminate session message is published
        self.channel.queue_bind(exchange=self.exchange,
                                queue=self.data_queue_name,
                                routing_key=MsgTestingToolTerminate.routing_key)

        # publish Hello message in bus
        m = MsgTestingToolComponentReady(component=self.COMPONENT_ID)
        self.channel.basic_publish(
            body=m.to_json(),
            routing_key=m.routing_key,
            exchange=self.exchange,
            properties=pika.BasicProperties(
                content_type='application/json',
            )
        )

        self.channel.basic_qos(prefetch_count=1)
        self.channel.basic_consume(self.on_request, queue=self.data_queue_name)

    def dumpers_init(self):

        for net_dump_filename in self.NETWORK_DUMPS_TEMP:
            full_path = os.path.join(self.dump_dir, net_dump_filename)
            if os.path.isfile(full_path):
                os.remove(full_path)

        self.pcap_15_4_dumper = Dumper(
            filename=os.path.join(self.dump_dir, self.DEFAULT_802154_DUMP_FILENAME_WR),
            snaplen=2000,
            network=DLT_IEEE802_15_4_NOFCS
        )

        self.pcap_raw_ip_dumper = Dumper(
            filename=os.path.join(self.dump_dir, self.DEFAULT_RAWIP_DUMP_FILENAME_WR),
            snaplen=2000,
            network=DLT_RAW
        )

    def dump_packet(self, message):

        try:
            t = time.time()
            t_s = int(t)
            t_u_delta = int((t - t_s) * 1000000)
            if 'serial' in message.interface_name:
                raw_packet = bytes(message.data)
                packet_slip = bytes(message.data_slip)

                # lets build pcap header for packet
                pcap_packet_header = Pkthdr(
                    ts_sec=t_s,
                    ts_usec=t_u_delta,
                    incl_len=len(raw_packet),
                    orig_len=len(raw_packet),
                )

                self.pcap_15_4_dumper.dump(pcap_packet_header, raw_packet)

                self.messages_dumped += 1

                shutil.copyfile(
                    os.path.join(self.dump_dir, self.DEFAULT_802154_DUMP_FILENAME_WR),
                    os.path.join(self.dump_dir, self.DEFAULT_802154_DUMP_FILENAME)
                )

            elif 'tun' in message.interface_name:
                raw_packet = bytes(message.data)

                # lets build pcap header for packet
                pcap_packet_header = Pkthdr(
                    ts_sec=t_s,
                    ts_usec=t_u_delta,
                    incl_len=len(raw_packet),
                    orig_len=len(raw_packet),
                )

                self.pcap_raw_ip_dumper.dump(pcap_packet_header, raw_packet)

                self.messages_dumped += 1

                shutil.copyfile(
                    os.path.join(self.dump_dir, self.DEFAULT_RAWIP_DUMP_FILENAME_WR),
                    os.path.join(self.dump_dir, self.DEFAULT_RAWIP_DUMP_FILENAME)
                )

            else:
                logger.info('Raw packet not dumped to pcap: ' + repr(message))
                return

        except Exception as e:
            logger.error(e)

        logger.info('Messages dumped : ' + str(self.messages_dumped))

    def dumps_rotate(self):

        for net_dump_filename in self.NETWORK_DUMPS:
            full_path = os.path.join(self.dump_dir, net_dump_filename)
            if os.path.isfile(full_path):
                logger.info('rotating file dump: %s' % full_path)
                shutil.copyfile(
                    full_path,
                    os.path.join(self.dump_dir, datetime.now().strftime('%Y%m%d_%H%M%S_') + net_dump_filename),
                )

    def stop(self):
        logger.info("Stopping packet dumper..")
        self.channel.queue_delete(self.data_queue_name)
        self.channel.stop_consuming()
        self.connection.close()

    def on_request(self, ch, method, props, body):

        ch.basic_ack(delivery_tag=method.delivery_tag)

        try:
            m = Message.load_from_pika(method, props, body)
            logger.info('got event: %s' % type(m))

            if isinstance(m, MsgTestingToolTerminate):
                ch.stop_consuming()
                self.stop()

            elif isinstance(m, MsgPacketSniffedRaw):
                self.dump_packet(m)
                try:  # rotate files each X messages dumped
                    if self.messages_dumped != 0 and self.messages_dumped % self.QUANTITY_MESSAGES_PER_PCAP == 0:
                        self.dumps_rotate()
                        self.dumpers_init()

                except Exception as e:
                    logger.error(e)

            else:
                pass

        except NonCompliantMessageFormatError as e:
            print('* * * * * * API VALIDATION ERROR * * * * * * * ')
            print("AMQP MESSAGE LIBRARY COULD PROCESS JSON MESSAGE")
            print('* * * * * * * * * * * * * * * * * * * * * * * * *  \n')
            # raise NonCompliantMessageFormatError("AMQP MESSAGE LIBRARY COULD PROCESS JSON MESSAGE")

        except Exception as e:
            logger.error(e)
            req_body_dict = json.loads(body.decode('utf-8'), object_pairs_hook=OrderedDict)
            logger.error("Message: %s, body: %s" % (json.dumps(req_body_dict), str(body)))

    def run(self):
        print("Starting thread listening on the event bus")
        self.channel.start_consuming()
        print('Bye byes!')


if __name__ == '__main__':

    import multiprocessing

    logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)

    p = multiprocessing.Process(target=launch_amqp_data_to_pcap_dumper(), args=())
    p.start()
    for i in range(1, 1000):
        time.sleep(1)
        print(i)
    p.join()

