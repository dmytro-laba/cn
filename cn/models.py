import chu
from chu.connection import AsyncRabbitConnectionBase
from chu.rpc import AsyncTornadoRPCClient
import logging
import uuid
import pika
from pika.adapters import TornadoConnection
import tornado
import tornado.gen

from tornado.httpclient import AsyncHTTPClient

logger = logging.getLogger(__name__)


class AsyncRabbitConnect(AsyncRabbitConnectionBase):
    def __init__(self, host, user='guest', password='guest', vhost='/', *args, **kwargs):
        self._parameters = pika.ConnectionParameters(
            host=host,
            credentials=pika.PlainCredentials(user, password),
            virtual_host=vhost
        )
        super(AsyncRabbitConnect, self).__init__(host, *args, **kwargs)

    @tornado.gen.engine
    def reconnect(self, callback):
        logger.info('Attempting to acquire the connect_lock.')
        if not self.connect_lock.acquire(False):
            logger.info('AsyncRabbitClient.reconnect is already '
                        'attempting to connect (the connect_lock '
                        'could not be acquired).')
            callback()
            return

        try:
            logger.info('AsyncRabbitClient.reconnect attempting to '
                        'connect to host: %s' % self.host,
                        extra={'host': self.host})

            key = str(uuid.uuid4())
            TornadoConnection(parameters=self._parameters,
                              custom_ioloop=self.io_loop,
                              on_open_callback=(yield tornado.gen.Callback(key)))

            logger.info('Waiting for TornadoConnection to return control '
                        'via on_open_callback.')
            self.connection = yield tornado.gen.Wait(key)
            logger.info('Control has been returned.')

            logger.info('Opening a channel on the connection.')
            key = str(uuid.uuid4())
            self.connection.channel(on_open_callback=
                                    (yield tornado.gen.Callback(key)))

            logger.info('Waiting for connection.channel to return control '
                        'via on_open_callback.')
            self.channel = yield tornado.gen.Wait(key)
            logger.info('Control has been returned.')

            logger.info('Adding callbacks to warn us when the connection '
                        'has been closed and when backpressure is being '
                        'applied.')
            self.connection.add_on_close_callback(self.on_connection_closed)
            self.connection.add_backpressure_callback(self.on_backpressure)

            self.channel.add_on_close_callback(self.on_channel_closed)

            logger.info('Adding callbacks that are waiting for an open '
                        'connection to the tornado queue.')
            while self.connection_open_callbacks:
                cb = self.connection_open_callbacks.pop()
                self.io_loop.add_callback(cb)
            logger.info('Done adding callbacks.')

        except Exception as e:
            logger.critical('An unknown exception was raised when trying '
                            'to open a connection to rabbit: %s' %
                            str(e))
            raise
        finally:
            logger.info('Releasing the connect lock.')
            self.connect_lock.release()
            callback()


class AsyncRabbitClient(AsyncRabbitConnect, AsyncTornadoRPCClient):
    pass


class AsyncRabbitConsumer(AsyncRabbitConnect):
    @tornado.gen.engine
    def consume_queue(self, queue, no_ack=True):
        yield tornado.gen.Task(self.queue_declare, queue=queue)

        yield tornado.gen.Task(self.basic_consume,
                               consumer_callback=self.consume_message,
                               queue=queue, no_ack=no_ack)

    @tornado.gen.coroutine
    def consume_message(self, channel, method, properties, body):
        message = tornado.escape.json_decode(body)

        client = AsyncHTTPClient()
        response = yield client.fetch(**message)

        channel.basic_publish(exchange='',
                              routing_key=properties.reply_to,
                              properties=pika.BasicProperties(correlation_id=properties.correlation_id),
                              body=response.body.decode())
        channel.basic_ack(delivery_tag=method.delivery_tag)

