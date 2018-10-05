import os
import pika
import logging
import threading
import traceback

# for using it as library and as a __main__
try:
    from messages import *
except:
    from .messages import *

VERSION = '0.0.10'
AMQP_EXCHANGE = 'amq.topic'
MAX_LOG_LINE_LENGTH = 120

logger = logging.getLogger(__name__)

class AmqpSynchCallTimeoutError(Exception):
    pass


class AmqpListener(threading.Thread):
    DEFAULT_TOPIC_SUSBCRIPTIONS = ['#']
    DEFAULT_EXCHAGE = 'amq.topic'
    DEFAULT_AMQP_URL = 'amqp://guest:guest@locahost/'

    def __init__(self, amqp_url, amqp_exchange, callback, topics=None, use_message_typing=True, pre_declared_queue=None):

        self.COMPONENT_ID = 'amqp_listener_%s' % str(uuid.uuid4())[:8]

        self.stopping = False
        self.connection = None
        self.channel = None
        if pre_declared_queue:
            self.services_queue_name = pre_declared_queue
            self.queue_is_declared = True
        else:
            self.services_queue_name = 'services_queue@%s' % self.COMPONENT_ID
            self.queue_is_declared = False
        self.use_message_typing = use_message_typing

        threading.Thread.__init__(self)

        if callback is None:
            self.message_dispatcher = AmqpListener.default_message_handler
        else:
            self.message_dispatcher = callback

        if topics:  # subscribe only to passed list
            self.topics = topics
        else:
            self.topics = self.DEFAULT_TOPIC_SUSBCRIPTIONS

        if amqp_exchange:
            self.exchange = amqp_exchange
        else:
            self.exchange = self.DEFAULT_EXCHAGE

        if amqp_url:
            self.amqp_url = amqp_url
        else:
            self.amqp_url = self.DEFAULT_AMQP_URL

        self.amqp_connect()

    @classmethod
    def default_message_handler(cls, message_as_dict):
        clean_dict = dict((k, v) for k, v in message_as_dict.items() if v)
        print('-' * 120)
        print('%s : %s' % ('routing_key', clean_dict.pop('routing_key')))
        print('-' * 120)
        print(json.dumps(clean_dict, indent=4, sort_keys=True))

    def amqp_connect(self):
        self.connection = pika.BlockingConnection(pika.URLParameters(self.amqp_url))
        self.channel = self.connection.channel()

        # Declare queue if necessary
        if not self.queue_is_declared:
            self.channel.queue_declare(queue=self.services_queue_name,
                                       auto_delete=True,
                                       arguments={'x-max-length': 200})
            for t in self.topics:
                self.channel.queue_bind(exchange=self.exchange,
                                        queue=self.services_queue_name,
                                        routing_key=t)
        # Hello world message
        m = MsgTestingToolComponentReady(
            component=self.COMPONENT_ID,
            description="%s is READY" % self.COMPONENT_ID

        )

        # Send hello world message
        self.channel.basic_publish(
            body=m.to_json(),
            routing_key=m.routing_key,
            exchange=self.exchange,
            properties=pika.BasicProperties(
                content_type='application/json',
            )
        )

        # Start consuming
        self.channel.basic_qos(prefetch_count=1)
        self.channel.basic_consume(self.on_request, queue=self.services_queue_name)

    def stop(self):
        self.stopping = True
        self.channel.queue_delete(self.services_queue_name)
        self.channel.stop_consuming()
        self.connection.close()

    def on_request(self, ch, method, props, body):

        if self.use_message_typing:
            try:
                m = Message.load_from_pika(method, props, body)
                if m is None:
                    raise Exception("Couldnt build message from json %s, rkey: %s " % (body, method.routing_key))
                m.routing_key = method.routing_key
                logger.debug('Message in bus: %s' % repr(m)[:MAX_LOG_LINE_LENGTH])
                self.message_dispatcher(m)

            except NonCompliantMessageFormatError as e:
                logger.error('%s got a non compliant message error %s' % (self.__class__.__name__, e))

            except Exception as e:
                logger.error(e)
                logger.error('message received:\n\tr_key: %s\n\t%s' % (method.routing_key, body))
                raise e

            finally:
                ch.basic_ack(delivery_tag=method.delivery_tag)
        else:

            props_dict = {
                'content_type': props.content_type,
                'delivery_mode': props.delivery_mode,
                'correlation_id': props.correlation_id,
                'reply_to': props.reply_to,
                'message_id': props.message_id,
                'timestamp': props.timestamp,
                'user_id': props.user_id,
                'app_id': props.app_id,
            }

            body_dict = json.loads(body.decode('utf-8'), object_pairs_hook=OrderedDict)
            ch.basic_ack(delivery_tag=method.delivery_tag)
            text_based_message_representation = OrderedDict()
            text_based_message_representation.update({'routing_key': method.routing_key})
            text_based_message_representation.update(props_dict)
            text_based_message_representation.update(body_dict)
            self.message_dispatcher(text_based_message_representation)

    def run(self):
        logger.info("Starting thread listening on the event bus on topics %s" % self.topics)

        for i in range(1, 4):
            try:
                self.channel.start_consuming()

            except (pika.exceptions.ConnectionClosed,
                    pika.exceptions.ChannelError,
                    pika.exceptions.ChannelClosed) as err:
                if not self.stopping:
                    logger.error('[AmqpListener] Unexpected connection closed, reconnecting %s/%s' % (i, 4))
                    logger.error(traceback.format_exc())
                    self.amqp_connect()

        logger.info('%s says Bye byes!' % self.COMPONENT_ID)


def publish_message(connection, message):
    """
    Publishes message into the correct topic (uses Message object metadata)
    Creates temporary channel on it's own
    Connection must be a pika.BlockingConnection
    """

    channel = connection.channel()
    properties = pika.BasicProperties(**message.get_properties())
    channel.basic_publish(
        exchange=AMQP_EXCHANGE,
        routing_key=message.routing_key,
        properties=properties,
        body=message.to_json(),
    )

    if channel and channel.is_open:
        channel.close()


def amqp_request(connection, request_message, component_id, retries=10, time_between_retries=0.5, use_message_typing=False):
    """
    Publishes message into the correct topic (uses Message object metadata)
    Returns reply message.
    Uses reply_to and corr id amqp's properties for matching the reply
    Creates temporary channel, and queues on it's own
    Connection must be a pika.BlockingConnection
    """

    # check first that sender didnt forget about reply to and corr id
    assert request_message.reply_to
    assert request_message.correlation_id
    assert retries > 0

    channel = None
    response = None

    reply_queue_name = 'amqp_rpc_%s@%s' % (str(uuid.uuid4())[:8], component_id)

    channel = connection.channel()
    result = channel.queue_declare(queue=reply_queue_name, auto_delete=True)
    callback_queue = result.method.queue

    # bind and listen to reply_to topic
    channel.queue_bind(
        exchange=AMQP_EXCHANGE,
        queue=callback_queue,
        routing_key=request_message.reply_to
    )

    channel.basic_publish(
        exchange=AMQP_EXCHANGE,
        routing_key=request_message.routing_key,
        properties=pika.BasicProperties(**request_message.get_properties()),
        body=request_message.to_json(),
    )

    time.sleep(0.2)
    retries_left = retries

    while retries_left > 0:
        time.sleep(time_between_retries)
        method, props, body = channel.basic_get(reply_queue_name)
        if method:
            channel.basic_ack(method.delivery_tag)
            if hasattr(props, 'correlation_id') and props.correlation_id == request_message.correlation_id:
                break
        retries_left -= 1

    if retries_left > 0:

        if use_message_typing:
            try:
                response = Message.load_from_pika(method, props, body)
                if response is None:
                    raise Exception("Couldnt build message from json %s, rkey: %s " % (body, method.routing_key))

            except NonCompliantMessageFormatError as e:
                logger.error('amqp_request got a non compliant message error %s' %  e)

            except Exception as e:
                logger.error(e)
                logger.error('message received:\n\tr_key: %s\n\t%s' % (method.routing_key, body))
                raise e

        else:

            body_dict = json.loads(body.decode('utf-8'), object_pairs_hook=OrderedDict)
            response = MsgReply(request_message, **body_dict)
    else:
        # clean up
        channel.queue_delete(reply_queue_name)
        channel.close()
        raise AmqpSynchCallTimeoutError(
            "Response timeout! rkey: %s , request type: %s" % (
                request_message.routing_key,
                type(request_message)
            )
        )

    if channel and channel.is_open:
        # clean up
        channel.queue_delete(reply_queue_name)
        channel.close()

    return response

if __name__ == '__main__':

    try:
        AMQP_EXCHANGE = str(os.environ['AMQP_EXCHANGE'])
    except KeyError as e:
        AMQP_EXCHANGE = "amq.topic"

    try:
        AMQP_URL = str(os.environ['AMQP_URL'])
        print('Env vars for AMQP connection succesfully imported')

    except KeyError as e:
        AMQP_URL = "amqp://guest:guest@localhost/"

    def callback_function(message_received):
        print("Callback function received: \n\t" + repr(message_received))


    # EXAMPLE ON AMQP LISTENER

    # # amqp listener example:
    # amqp_listener_thread = AmqpListener(
    #     amqp_url=AMQP_URL,
    #     amqp_exchange=AMQP_EXCHANGE,
    #     callback=callback_function,
    #     topics='#'
    # )
    #
    # try:
    #     amqp_listener_thread.start()
    # except Exception as e:
    #     print(e)
    #
    # # publish message example
    # retries_left = 3
    # while retries_left > 0:
    #     try:
    #         connection = pika.BlockingConnection(pika.URLParameters(AMQP_URL))
    #         m = MsgTest()
    #         publish_message(connection, m)
    #         break
    #     except pika.exceptions.ConnectionClosed:
    #         retries_left -= 1
    #         print('retrying..')
    #         time.sleep(0.2)
    #
    # # example of a request sent into the bus
    # m = MsgTestSuiteGetTestCases()
    # try:
    #     r = amqp_request(connection, m, 'someImaginaryComponent')
    #     print("This is the response I got:\n\t" + repr(r))
    #
    # except AmqpSynchCallTimeoutError as e:
    #     print("Nobody answered to our request :'(")


    # EXAMPLE ON REQUEST REPLY FOR UI BUTTONS:
    con = pika.BlockingConnection(pika.URLParameters(AMQP_URL))
    channel = con.channel()

    # ui_request = MsgUiRequestConfirmationButton()
    # print("publishing .. %s" % repr(ui_request))
    # ui_reply = amqp_request(con, ui_request, 'dummy_component')
    # print(repr(ui_reply))


    req = MsgUiRequestSessionConfiguration()
    ui_reply = amqp_request(con, req,'dummy_component')
    print(ui_reply.users)