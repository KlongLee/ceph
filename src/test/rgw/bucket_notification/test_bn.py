import logging
import json
import tempfile
import random
import threading
import subprocess
import socket
import time
import os
import string
from http import server as http_server
from random import randint

from boto.s3.connection import S3Connection

from . import(
    get_config_host,
    get_config_port,
    get_access_key,
    get_secret_key
    )

from .api import PSTopicS3, \
    PSNotificationS3, \
    delete_all_s3_topics, \
    delete_all_objects, \
    put_object_tagging

from nose import SkipTest
from nose.tools import assert_not_equal, assert_equal
import boto.s3.tagging

# configure logging for the tests module
log = logging.getLogger(__name__)


TOPIC_SUFFIX = "_topic"
NOTIFICATION_SUFFIX = "_notif"


num_buckets = 0
run_prefix=''.join(random.choice(string.ascii_lowercase) for _ in range(6))

def gen_bucket_name():
    global num_buckets

    num_buckets += 1
    return run_prefix + '-' + str(num_buckets)


def set_contents_from_string(key, content):
    try:
        key.set_contents_from_string(content)
    except Exception as e:
        print('Error: ' + str(e))


class HTTPPostHandler(http_server.BaseHTTPRequestHandler):
    """HTTP POST hanler class storing the received events in its http server"""
    def do_POST(self):
        """implementation of POST handler"""
        try:
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)
            log.info('HTTP Server (%d) received event: %s', self.server.worker_id, str(body))
            self.server.append(json.loads(body))
        except:
            log.error('HTTP Server received empty event')
            self.send_response(400)
        else:
            if self.headers.get('Expect') == '100-continue':
                self.send_response(100)
            else:
                self.send_response(200)
        finally:
            if self.server.delay > 0:
                time.sleep(self.server.delay)
            self.end_headers()


class HTTPServerWithEvents(http_server.HTTPServer):
    """HTTP server used by the handler to store events"""
    def __init__(self, addr, handler, worker_id, delay=0):
        http_server.HTTPServer.__init__(self, addr, handler, False)
        self.worker_id = worker_id
        self.events = []
        self.delay = delay

    def append(self, event):
        self.events.append(event)

class HTTPServerThread(threading.Thread):
    """thread for running the HTTP server. reusing the same socket for all threads"""
    def __init__(self, i, sock, addr, delay=0):
        threading.Thread.__init__(self)
        self.i = i
        self.daemon = True
        self.httpd = HTTPServerWithEvents(addr, HTTPPostHandler, i, delay)
        self.httpd.socket = sock
        # prevent the HTTP server from re-binding every handler
        self.httpd.server_bind = self.server_close = lambda self: None
        self.start()

    def run(self):
        try:
            log.info('HTTP Server (%d) started on: %s', self.i, self.httpd.server_address)
            self.httpd.serve_forever()
            log.info('HTTP Server (%d) ended', self.i)
        except Exception as error:
            # could happen if the server r/w to a closing socket during shutdown
            log.info('HTTP Server (%d) ended unexpectedly: %s', self.i, str(error))

    def close(self):
        self.httpd.shutdown()

    def get_events(self):
        return self.httpd.events

    def reset_events(self):
        self.httpd.events = []

class StreamingHTTPServer:
    """multi-threaded http server class also holding list of events received into the handler
    each thread has its own server, and all servers share the same socket"""
    def __init__(self, host, port, num_workers=100, delay=0):
        addr = (host, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(addr)
        self.sock.listen(num_workers)
        self.workers = [HTTPServerThread(i, self.sock, addr, delay) for i in range(num_workers)]

    def verify_s3_events(self, keys, exact_match=False, deletions=False, expected_sizes={}):
        """verify stored s3 records agains a list of keys"""
        events = []
        for worker in self.workers:
            events += worker.get_events()
            worker.reset_events()
        verify_s3_records_by_elements(events, keys, exact_match=exact_match, deletions=deletions, expected_sizes=expected_sizes)

    def verify_events(self, keys, exact_match=False, deletions=False):
        """verify stored events agains a list of keys"""
        events = []
        for worker in self.workers:
            events += worker.get_events()
            worker.reset_events()
        verify_events_by_elements(events, keys, exact_match=exact_match, deletions=deletions)

    def get_and_reset_events(self):
        events = []
        for worker in self.workers:
            events += worker.get_events()
            worker.reset_events()
        return events

    def close(self):
        """close all workers in the http server and wait for it to finish"""
        # make sure that the shared socket is closed
        # this is needed in case that one of the threads is blocked on the socket
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()
        # wait for server threads to finish
        for worker in self.workers:
            worker.close()
            worker.join()

# AMQP endpoint functions

rabbitmq_port = 5672

class AMQPReceiver(object):
    """class for receiving and storing messages on a topic from the AMQP broker"""
    def __init__(self, exchange, topic):
        import pika
        hostname = get_ip()
        remaining_retries = 10
        while remaining_retries > 0:
            try:
                connection = pika.BlockingConnection(pika.ConnectionParameters(host=hostname, port=rabbitmq_port))
                break
            except Exception as error:
                remaining_retries -= 1
                print('failed to connect to rabbitmq (remaining retries '
                    + str(remaining_retries) + '): ' + str(error))
                time.sleep(1)

        if remaining_retries == 0:
            raise Exception('failed to connect to rabbitmq - no retries left')

        self.channel = connection.channel()
        self.channel.exchange_declare(exchange=exchange, exchange_type='topic', durable=True)
        result = self.channel.queue_declare('', exclusive=True)
        queue_name = result.method.queue
        self.channel.queue_bind(exchange=exchange, queue=queue_name, routing_key=topic)
        self.channel.basic_consume(queue=queue_name,
                                   on_message_callback=self.on_message,
                                   auto_ack=True)
        self.events = []
        self.topic = topic

    def on_message(self, ch, method, properties, body):
        """callback invoked when a new message arrive on the topic"""
        log.info('AMQP received event for topic %s:\n %s', self.topic, body)
        self.events.append(json.loads(body))

    # TODO create a base class for the AMQP and HTTP cases
    def verify_s3_events(self, keys, exact_match=False, deletions=False):
        """verify stored s3 records agains a list of keys"""
        verify_s3_records_by_elements(self.events, keys, exact_match=exact_match, deletions=deletions)
        self.events = []

    def verify_events(self, keys, exact_match=False, deletions=False):
        """verify stored events agains a list of keys"""
        verify_events_by_elements(self.events, keys, exact_match=exact_match, deletions=deletions)
        self.events = []

    def get_and_reset_events(self):
        tmp = self.events
        self.events = []
        return tmp

def amqp_receiver_thread_runner(receiver):
    """main thread function for the amqp receiver"""
    try:
        log.info('AMQP receiver started')
        receiver.channel.start_consuming()
        log.info('AMQP receiver ended')
    except Exception as error:
        log.info('AMQP receiver ended unexpectedly: %s', str(error))


def create_amqp_receiver_thread(exchange, topic):
    """create amqp receiver and thread"""
    receiver = AMQPReceiver(exchange, topic)
    task = threading.Thread(target=amqp_receiver_thread_runner, args=(receiver,))
    task.daemon = True
    return task, receiver


def stop_amqp_receiver(receiver, task):
    """stop the receiver thread and wait for it to finis"""
    try:
        receiver.channel.stop_consuming()
        log.info('stopping AMQP receiver')
    except Exception as error:
        log.info('failed to gracefuly stop AMQP receiver: %s', str(error))
    task.join(5)

def verify_events_by_elements(events, keys, exact_match=False, deletions=False):
    """ verify there is at least one event per element """
    err = ''
    for key in keys:
        key_found = False
        if type(events) is list:
            for event_list in events:
                if key_found:
                    break
                for event in event_list['events']:
                    if event['info']['bucket']['name'] == key.bucket.name and \
                        event['info']['key']['name'] == key.name:
                        if deletions and event['event'] == 'OBJECT_DELETE':
                            key_found = True
                            break
                        elif not deletions and event['event'] == 'OBJECT_CREATE':
                            key_found = True
                            break
        else:
            for event in events['events']:
                if event['info']['bucket']['name'] == key.bucket.name and \
                    event['info']['key']['name'] == key.name:
                    if deletions and event['event'] == 'OBJECT_DELETE':
                        key_found = True
                        break
                    elif not deletions and event['event'] == 'OBJECT_CREATE':
                        key_found = True
                        break

        if not key_found:
            err = 'no ' + ('deletion' if deletions else 'creation') + ' event found for key: ' + str(key)
            log.error(events)
            assert False, err

    if not len(events) == len(keys):
        err = 'superfluous events are found'
        log.debug(err)
        if exact_match:
            log.error(events)
            assert False, err

def verify_s3_records_by_elements(records, keys, exact_match=False, deletions=False, expected_sizes={}):
    """ verify there is at least one record per element """
    err = ''
    for key in keys:
        key_found = False
        object_size = 0
        if type(records) is list:
            for record_list in records:
                if key_found:
                    break
                for record in record_list['Records']:
                    if record['s3']['bucket']['name'] == key.bucket.name and \
                        record['s3']['object']['key'] == key.name:
                        if deletions and 'ObjectRemoved' in record['eventName']:
                            key_found = True
                            object_size = record['s3']['object']['size']
                            break
                        elif not deletions and 'ObjectCreated' in record['eventName']:
                            key_found = True
                            object_size = record['s3']['object']['size']
                            break
        else:
            for record in records['Records']:
                if record['s3']['bucket']['name'] == key.bucket.name and \
                    record['s3']['object']['key'] == key.name:
                    if deletions and 'ObjectRemoved' in record['eventName']:
                        key_found = True
                        object_size = record['s3']['object']['size']
                        break
                    elif not deletions and 'ObjectCreated' in record['eventName']:
                        key_found = True
                        object_size = record['s3']['object']['size']
                        break

        if not key_found:
            err = 'no ' + ('deletion' if deletions else 'creation') + ' event found for key: ' + str(key)
            assert False, err
        elif expected_sizes:
            assert_equal(object_size, expected_sizes.get(key.name))

    if not len(records) == len(keys):
        err = 'superfluous records are found'
        log.warning(err)
        if exact_match:
            for record_list in records:
                for record in record_list['Records']:
                    log.error(str(record['s3']['bucket']['name']) + ',' + str(record['s3']['object']['key']))
            assert False, err


# Kafka endpoint functions

kafka_server = 'localhost'

class KafkaReceiver(object):
    """class for receiving and storing messages on a topic from the kafka broker"""
    def __init__(self, topic, security_type):
        from kafka import KafkaConsumer
        remaining_retries = 10
        port = 9092
        if security_type != 'PLAINTEXT':
            security_type = 'SSL'
            port = 9093
        while remaining_retries > 0:
            try:
                self.consumer = KafkaConsumer(topic, bootstrap_servers = kafka_server+':'+str(port), security_protocol=security_type)
                print('Kafka consumer created on topic: '+topic)
                break
            except Exception as error:
                remaining_retries -= 1
                print('failed to connect to kafka (remaining retries '
                    + str(remaining_retries) + '): ' + str(error))
                time.sleep(1)

        if remaining_retries == 0:
            raise Exception('failed to connect to kafka - no retries left')

        self.events = []
        self.topic = topic
        self.stop = False

    def verify_s3_events(self, keys, exact_match=False, deletions=False):
        """verify stored s3 records agains a list of keys"""
        verify_s3_records_by_elements(self.events, keys, exact_match=exact_match, deletions=deletions)
        self.events = []

def kafka_receiver_thread_runner(receiver):
    """main thread function for the kafka receiver"""
    try:
        log.info('Kafka receiver started')
        print('Kafka receiver started')
        while not receiver.stop:
            for msg in receiver.consumer:
                receiver.events.append(json.loads(msg.value))
            timer.sleep(0.1)
        log.info('Kafka receiver ended')
        print('Kafka receiver ended')
    except Exception as error:
        log.info('Kafka receiver ended unexpectedly: %s', str(error))
        print('Kafka receiver ended unexpectedly: ' + str(error))


def create_kafka_receiver_thread(topic, security_type='PLAINTEXT'):
    """create kafka receiver and thread"""
    receiver = KafkaReceiver(topic, security_type)
    task = threading.Thread(target=kafka_receiver_thread_runner, args=(receiver,))
    task.daemon = True
    return task, receiver

def stop_kafka_receiver(receiver, task):
    """stop the receiver thread and wait for it to finis"""
    receiver.stop = True
    task.join(1)
    try:
        receiver.consumer.close()
    except Exception as error:
        log.info('failed to gracefuly stop Kafka receiver: %s', str(error))


def get_ip():
    return 'localhost'

def get_ip_http():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # address should not be reachable
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

def connection():
    hostname = get_config_host()
    port_no = get_config_port()
    vstart_access_key = get_access_key()
    vstart_secret_key = get_secret_key()

    conn = S3Connection(aws_access_key_id=vstart_access_key,
	    	      aws_secret_access_key=vstart_secret_key,
                      is_secure=False, port=port_no, host=hostname, 
                      calling_format='boto.s3.connection.OrdinaryCallingFormat')

    return conn

def connection2():
    vstart_access_key = '0555b35654ad1656d804'
    vstart_secret_key = 'h7GhxuBLTrlhVUyxSPUKUV8r/2EI4ngqJxD7iBdBYLhwluN30JaT3Q=='
    hostname = get_ip()

    conn = S3Connection(aws_access_key_id=vstart_access_key,
                      aws_secret_access_key=vstart_secret_key,
                      is_secure=False, port=8001, host=hostname,
                      calling_format='boto.s3.connection.OrdinaryCallingFormat')

    return conn


##############
# bucket notifications tests
##############


def test_ps_s3_topic_on_master():
    """ test s3 topics set/get/delete on master """
    return SkipTest('Get tenant function required.')

    zonegroup = 'default' 
    bucket_name = gen_bucket_name()
    conn = connection()
    topic_name = bucket_name + TOPIC_SUFFIX

    # clean all topics
    delete_all_s3_topics(conn, zonegroup)

    # create s3 topics
    endpoint_address = 'amqp://127.0.0.1:7001/vhost_1'
    endpoint_args = 'push-endpoint='+endpoint_address+'&amqp-exchange=amqp.direct&amqp-ack-level=none'
    topic_conf1 = PSTopicS3(conn, topic_name+'_1', zonegroup, endpoint_args=endpoint_args)
    topic_arn = topic_conf1.set_config()
    assert_equal(topic_arn,
                 'arn:aws:sns:' + zonegroup + ':' + get_tenant() + ':' + topic_name + '_1')

    endpoint_address = 'http://127.0.0.1:9001'
    endpoint_args = 'push-endpoint='+endpoint_address
    topic_conf2 = PSTopicS3(conn, topic_name+'_2', zonegroup, endpoint_args=endpoint_args)
    topic_arn = topic_conf2.set_config()
    assert_equal(topic_arn,
                 'arn:aws:sns:' + zonegroup + ':' + get_tenant() + ':' + topic_name + '_2')
    endpoint_address = 'http://127.0.0.1:9002'
    endpoint_args = 'push-endpoint='+endpoint_address
    topic_conf3 = PSTopicS3(conn, topic_name+'_3', zonegroup, endpoint_args=endpoint_args)
    topic_arn = topic_conf3.set_config()
    assert_equal(topic_arn,
                 'arn:aws:sns:' + zonegroup + ':' + get_tenant() + ':' + topic_name + '_3')

    # get topic 3
    result, status = topic_conf3.get_config()
    assert_equal(status, 200)
    assert_equal(topic_arn, result['GetTopicResponse']['GetTopicResult']['Topic']['TopicArn'])
    assert_equal(endpoint_address, result['GetTopicResponse']['GetTopicResult']['Topic']['EndPoint']['EndpointAddress'])

    # Note that endpoint args may be ordered differently in the result
    # delete topic 1
    result = topic_conf1.del_config()
    assert_equal(status, 200)

    # try to get a deleted topic
    _, status = topic_conf1.get_config()
    assert_equal(status, 404)

    # get the remaining 2 topics
    result, status = topic_conf1.get_list()
    assert_equal(status, 200)
    assert_equal(len(result['ListTopicsResponse']['ListTopicsResult']['Topics']['member']), 2)

    # delete topics
    result = topic_conf2.del_config()
    # TODO: should be 200OK
    # assert_equal(status, 200)
    result = topic_conf3.del_config()
    # TODO: should be 200OK
    # assert_equal(status, 200)

    # get topic list, make sure it is empty
    result, status = topic_conf1.get_list()
    assert_equal(result['ListTopicsResponse']['ListTopicsResult']['Topics'], None)

def test_ps_s3_topic_with_secret_on_master():
    """ test s3 topics with secret set/get/delete on master """
    return SkipTest('secure connection is needed to test topic with secrets')

    conn = connection1()
    if conn.secure_conn is None:
        return SkipTest('secure connection is needed to test topic with secrets')

    zonegroup = 'default' 
    bucket_name = gen_bucket_name()
    topic_name = bucket_name + TOPIC_SUFFIX

    # clean all topics
    delete_all_s3_topics(conn, zonegroup)

    # create s3 topics
    endpoint_address = 'amqp://user:password@127.0.0.1:7001'
    endpoint_args = 'push-endpoint='+endpoint_address+'&amqp-exchange=amqp.direct&amqp-ack-level=none'
    bad_topic_conf = PSTopicS3(conn, topic_name, zonegroup, endpoint_args=endpoint_args)
    try:
        result = bad_topic_conf.set_config()
    except Exception as err:
        print('Error is expected: ' + str(err))
    else:
        assert False, 'user password configuration set allowed only over HTTPS'
    topic_conf = PSTopicS3(conn.secure_conn, topic_name, zonegroup, endpoint_args=endpoint_args)
    topic_arn = topic_conf.set_config()

    assert_equal(topic_arn,
                 'arn:aws:sns:' + zonegroup + ':' + get_tenant() + ':' + topic_name)

    _, status = bad_topic_conf.get_config()
    assert_equal(status/100, 4)

    # get topic
    result, status = topic_conf.get_config()
    assert_equal(status, 200)
    assert_equal(topic_arn, result['GetTopicResponse']['GetTopicResult']['Topic']['TopicArn'])
    assert_equal(endpoint_address, result['GetTopicResponse']['GetTopicResult']['Topic']['EndPoint']['EndpointAddress'])

    _, status = bad_topic_conf.get_config()
    assert_equal(status/100, 4)

    _, status = topic_conf.get_list()
    assert_equal(status/100, 2)

    # delete topics
    result = topic_conf.del_config()


def test_ps_s3_notification_on_master():
    """ test s3 notification set/get/delete on master """
    conn = connection()
    zonegroup = 'default'
    bucket_name = gen_bucket_name()
    # create bucket
    bucket = conn.create_bucket(bucket_name)
    topic_name = bucket_name + TOPIC_SUFFIX
    # create s3 topic
    endpoint_address = 'amqp://127.0.0.1:7001'
    endpoint_args = 'push-endpoint='+endpoint_address+'&amqp-exchange=amqp.direct&amqp-ack-level=none'
    topic_conf = PSTopicS3(conn, topic_name, zonegroup, endpoint_args=endpoint_args)
    topic_arn = topic_conf.set_config()
    # create s3 notification
    notification_name = bucket_name + NOTIFICATION_SUFFIX
    topic_conf_list = [{'Id': notification_name+'_1',
                        'TopicArn': topic_arn,
                        'Events': ['s3:ObjectCreated:*']
                       },
                       {'Id': notification_name+'_2',
                        'TopicArn': topic_arn,
                        'Events': ['s3:ObjectRemoved:*']
                       },
                       {'Id': notification_name+'_3',
                        'TopicArn': topic_arn,
                        'Events': []
                       }]
    s3_notification_conf = PSNotificationS3(conn, bucket_name, topic_conf_list)
    _, status = s3_notification_conf.set_config()
    assert_equal(status/100, 2)

    # get notifications on a bucket
    response, status = s3_notification_conf.get_config(notification=notification_name+'_1')
    assert_equal(status/100, 2)
    assert_equal(response['NotificationConfiguration']['TopicConfiguration']['Topic'], topic_arn)

    # delete specific notifications
    _, status = s3_notification_conf.del_config(notification=notification_name+'_1')
    assert_equal(status/100, 2)

    # get the remaining 2 notifications on a bucket
    response, status = s3_notification_conf.get_config()
    assert_equal(status/100, 2)
    assert_equal(len(response['TopicConfigurations']), 2)
    assert_equal(response['TopicConfigurations'][0]['TopicArn'], topic_arn)
    assert_equal(response['TopicConfigurations'][1]['TopicArn'], topic_arn)

    # delete remaining notifications
    _, status = s3_notification_conf.del_config()
    assert_equal(status/100, 2)

    # make sure that the notifications are now deleted
    _, status = s3_notification_conf.get_config()

    # cleanup
    topic_conf.del_config()
    # delete the bucket
    conn.delete_bucket(bucket_name)


def test_ps_s3_notification_filter_on_master():
    """ test s3 notification filter on master """
    return SkipTest('This is an AMQP test.')

    hostname = get_ip()
    
    conn = connection()
    ps_zone = conn

    zonegroup = 'default'

    # create bucket
    bucket_name = gen_bucket_name()
    bucket = conn.create_bucket(bucket_name)
    topic_name = bucket_name + TOPIC_SUFFIX

    # start amqp receivers
    exchange = 'ex1'
    task, receiver = create_amqp_receiver_thread(exchange, topic_name)
    task.start()

    # create s3 topic
    endpoint_address = 'amqp://' + hostname
    endpoint_args = 'push-endpoint='+endpoint_address+'&amqp-exchange=' + exchange +'&amqp-ack-level=broker'
        
    topic_conf = PSTopicS3(conn, topic_name, zonegroup, endpoint_args=endpoint_args)
    topic_arn = topic_conf.set_config()

    # create s3 notification
    notification_name = bucket_name + NOTIFICATION_SUFFIX
    topic_conf_list = [{'Id': notification_name+'_1',
                        'TopicArn': topic_arn,
                        'Events': ['s3:ObjectCreated:*'],
                        'Filter': {
                          'Key': {
                            'FilterRules': [{'Name': 'prefix', 'Value': 'hello'}]
                          }
                        }
                       },
                       {'Id': notification_name+'_2',
                        'TopicArn': topic_arn,
                        'Events': ['s3:ObjectCreated:*'],
                        'Filter': {
                          'Key': {
                            'FilterRules': [{'Name': 'prefix', 'Value': 'world'},
                                            {'Name': 'suffix', 'Value': 'log'}]
                          }
                        }
                       },
                       {'Id': notification_name+'_3',
                        'TopicArn': topic_arn,
                        'Events': [],
                        'Filter': {
                          'Key': {
                            'FilterRules': [{'Name': 'regex', 'Value': '([a-z]+)\\.txt'}]
                         }
                        }
                       }]

    s3_notification_conf = PSNotificationS3(conn, bucket_name, topic_conf_list)
    result, status = s3_notification_conf.set_config()
    assert_equal(status/100, 2)

    topic_conf_list = [{'Id': notification_name+'_4',
                        'TopicArn': topic_arn,
                        'Events': ['s3:ObjectCreated:*', 's3:ObjectRemoved:*'],
                        'Filter': {
                            'Metadata': {
                                'FilterRules': [{'Name': 'x-amz-meta-foo', 'Value': 'bar'},
                                                {'Name': 'x-amz-meta-hello', 'Value': 'world'}]
                            },
                            'Key': {
                                'FilterRules': [{'Name': 'regex', 'Value': '([a-z]+)'}]
                            }
                        }
                        }]

    try:
        s3_notification_conf4 = PSNotificationS3(conn, bucket_name, topic_conf_list)
        _, status = s3_notification_conf4.set_config()
        assert_equal(status/100, 2)
        skip_notif4 = False
    except Exception as error:
        print('note: metadata filter is not supported by boto3 - skipping test')
        skip_notif4 = True


    # get all notifications
    result, status = s3_notification_conf.get_config()
    assert_equal(status/100, 2)
    for conf in result['TopicConfigurations']:
        filter_name = conf['Filter']['Key']['FilterRules'][0]['Name']
        assert filter_name == 'prefix' or filter_name == 'suffix' or filter_name == 'regex', filter_name

    if not skip_notif4:
        result, status = s3_notification_conf4.get_config(notification=notification_name+'_4')
        assert_equal(status/100, 2)
        filter_name = result['NotificationConfiguration']['TopicConfiguration']['Filter']['S3Metadata']['FilterRule'][0]['Name']
        assert filter_name == 'x-amz-meta-foo' or filter_name == 'x-amz-meta-hello'

    expected_in1 = ['hello.kaboom', 'hello.txt', 'hello123.txt', 'hello']
    expected_in2 = ['world1.log', 'world2log', 'world3.log']
    expected_in3 = ['hello.txt', 'hell.txt', 'worldlog.txt']
    expected_in4 = ['foo', 'bar', 'hello', 'world']
    filtered = ['hell.kaboom', 'world.og', 'world.logg', 'he123ll.txt', 'wo', 'log', 'h', 'txt', 'world.log.txt']
    filtered_with_attr = ['nofoo', 'nobar', 'nohello', 'noworld']
    # create objects in bucket
    for key_name in expected_in1:
        key = bucket.new_key(key_name)
        key.set_contents_from_string('bar')
    for key_name in expected_in2:
        key = bucket.new_key(key_name)
        key.set_contents_from_string('bar')
    for key_name in expected_in3:
        key = bucket.new_key(key_name)
        key.set_contents_from_string('bar')
    if not skip_notif4:
        for key_name in expected_in4:
            key = bucket.new_key(key_name)
            key.set_metadata('foo', 'bar')
            key.set_metadata('hello', 'world')
            key.set_metadata('goodbye', 'cruel world')
            key.set_contents_from_string('bar')
    for key_name in filtered:
        key = bucket.new_key(key_name)
        key.set_contents_from_string('bar')
    for key_name in filtered_with_attr:
        key.set_metadata('foo', 'nobar')
        key.set_metadata('hello', 'noworld')
        key.set_metadata('goodbye', 'cruel world')
        key = bucket.new_key(key_name)
        key.set_contents_from_string('bar')

    print('wait for 5sec for the messages...')
    time.sleep(5)

    found_in1 = []
    found_in2 = []
    found_in3 = []
    found_in4 = []

    for event in receiver.get_and_reset_events():
        notif_id = event['Records'][0]['s3']['configurationId']
        key_name = event['Records'][0]['s3']['object']['key']
        if notif_id == notification_name+'_1':
            found_in1.append(key_name)
        elif notif_id == notification_name+'_2':
            found_in2.append(key_name)
        elif notif_id == notification_name+'_3':
            found_in3.append(key_name)
        elif not skip_notif4 and notif_id == notification_name+'_4':
            found_in4.append(key_name)
        else:
            assert False, 'invalid notification: ' + notif_id

    assert_equal(set(found_in1), set(expected_in1))
    assert_equal(set(found_in2), set(expected_in2))
    assert_equal(set(found_in3), set(expected_in3))
    if not skip_notif4:
        assert_equal(set(found_in4), set(expected_in4))

    # cleanup
    s3_notification_conf.del_config()
    if not skip_notif4:
        s3_notification_conf4.del_config()
    topic_conf.del_config()
    # delete the bucket
    for key in bucket.list():
        key.delete()
    conn.delete_bucket(bucket_name)
    stop_amqp_receiver(receiver, task)

def test_ps_s3_notification_errors_on_master():
    """ test s3 notification set/get/delete on master """
    conn = connection()
    zonegroup = 'default'
    bucket_name = gen_bucket_name()
    # create bucket
    bucket = conn.create_bucket(bucket_name)
    topic_name = bucket_name + TOPIC_SUFFIX
    # create s3 topic
    endpoint_address = 'amqp://127.0.0.1:7001'
    endpoint_args = 'push-endpoint='+endpoint_address+'&amqp-exchange=amqp.direct&amqp-ack-level=none'
    topic_conf = PSTopicS3(conn, topic_name, zonegroup, endpoint_args=endpoint_args)
    topic_arn = topic_conf.set_config()

    # create s3 notification with invalid event name
    notification_name = bucket_name + NOTIFICATION_SUFFIX
    topic_conf_list = [{'Id': notification_name,
                        'TopicArn': topic_arn,
                        'Events': ['s3:ObjectCreated:Kaboom']
                       }]
    s3_notification_conf = PSNotificationS3(conn, bucket_name, topic_conf_list)
    try:
      result, status = s3_notification_conf.set_config()
    except Exception as error:
      print(str(error) + ' - is expected')
    else:
      assert False, 'invalid event name is expected to fail'

    # create s3 notification with missing name
    topic_conf_list = [{'Id': '',
                        'TopicArn': topic_arn,
                        'Events': ['s3:ObjectCreated:Put']
                       }]
    s3_notification_conf = PSNotificationS3(conn, bucket_name, topic_conf_list)
    try:
      _, _ = s3_notification_conf.set_config()
    except Exception as error:
      print(str(error) + ' - is expected')
    else:
      assert False, 'missing notification name is expected to fail'

    # create s3 notification with invalid topic ARN
    invalid_topic_arn = 'kaboom'
    topic_conf_list = [{'Id': notification_name,
                        'TopicArn': invalid_topic_arn,
                        'Events': ['s3:ObjectCreated:Put']
                       }]
    s3_notification_conf = PSNotificationS3(conn, bucket_name, topic_conf_list)
    try:
      _, _ = s3_notification_conf.set_config()
    except Exception as error:
      print(str(error) + ' - is expected')
    else:
      assert False, 'invalid ARN is expected to fail'

    # create s3 notification with unknown topic ARN
    invalid_topic_arn = 'arn:aws:sns:a::kaboom'
    topic_conf_list = [{'Id': notification_name,
                        'TopicArn': invalid_topic_arn ,
                        'Events': ['s3:ObjectCreated:Put']
                       }]
    s3_notification_conf = PSNotificationS3(conn, bucket_name, topic_conf_list)
    try:
      _, _ = s3_notification_conf.set_config()
    except Exception as error:
      print(str(error) + ' - is expected')
    else:
      assert False, 'unknown topic is expected to fail'

    # create s3 notification with wrong bucket
    topic_conf_list = [{'Id': notification_name,
                        'TopicArn': topic_arn,
                        'Events': ['s3:ObjectCreated:Put']
                       }]
    s3_notification_conf = PSNotificationS3(conn, 'kaboom', topic_conf_list)
    try:
      _, _ = s3_notification_conf.set_config()
    except Exception as error:
      print(str(error) + ' - is expected')
    else:
      assert False, 'unknown bucket is expected to fail'

    topic_conf.del_config()

    status = topic_conf.del_config()
    # deleting an unknown notification is not considered an error
    assert_equal(status, 200)

    _, status = topic_conf.get_config()
    assert_equal(status, 404)

    # cleanup
    # delete the bucket
    conn.delete_bucket(bucket_name)

def test_ps_s3_notification_push_amqp_on_master():
    """ test pushing amqp s3 notification on master """
    return SkipTest('This is an AMQP test.')

    hostname = get_ip()
    conn = connection()
    zonegroup = 'default'

    # create bucket
    bucket_name = gen_bucket_name()
    bucket = conn.create_bucket(bucket_name)
    topic_name1 = bucket_name + TOPIC_SUFFIX + '_1'
    topic_name2 = bucket_name + TOPIC_SUFFIX + '_2'

    # start amqp receivers
    exchange = 'ex1'
    task1, receiver1 = create_amqp_receiver_thread(exchange, topic_name1)
    task2, receiver2 = create_amqp_receiver_thread(exchange, topic_name2)
    task1.start()
    task2.start()

    # create two s3 topic
    endpoint_address = 'amqp://' + hostname
    # with acks from broker
    endpoint_args = 'push-endpoint='+endpoint_address+'&amqp-exchange=' + exchange +'&amqp-ack-level=broker'
    topic_conf1 = PSTopicS3(conn, topic_name1, zonegroup, endpoint_args=endpoint_args)
    topic_arn1 = topic_conf1.set_config()
    # without acks from broker
    endpoint_args = 'push-endpoint='+endpoint_address+'&amqp-exchange=' + exchange +'&amqp-ack-level=routable'
    topic_conf2 = PSTopicS3(conn, topic_name2, zonegroup, endpoint_args=endpoint_args)
    topic_arn2 = topic_conf2.set_config()
    # create s3 notification
    notification_name = bucket_name + NOTIFICATION_SUFFIX
    topic_conf_list = [{'Id': notification_name+'_1', 'TopicArn': topic_arn1,
                         'Events': []
                       },
                       {'Id': notification_name+'_2', 'TopicArn': topic_arn2,
                         'Events': ['s3:ObjectCreated:*']
                       }]

    s3_notification_conf = PSNotificationS3(conn, bucket_name, topic_conf_list)
    response, status = s3_notification_conf.set_config()
    assert_equal(status/100, 2)

    # create objects in the bucket (async)
    number_of_objects = 100
    client_threads = []
    start_time = time.time()
    for i in range(number_of_objects):
        key = bucket.new_key(str(i))
        content = str(os.urandom(1024*1024))
        thr = threading.Thread(target = set_contents_from_string, args=(key, content,))
        thr.start()
        client_threads.append(thr)
    [thr.join() for thr in client_threads]

    time_diff = time.time() - start_time
    print('average time for creation + qmqp notification is: ' + str(time_diff*1000/number_of_objects) + ' milliseconds')

    print('wait for 5sec for the messages...')
    time.sleep(5)

    # check amqp receiver
    keys = list(bucket.list())
    print('total number of objects: ' + str(len(keys)))
    receiver1.verify_s3_events(keys, exact_match=True)
    receiver2.verify_s3_events(keys, exact_match=True)

    # delete objects from the bucket
    client_threads = []
    start_time = time.time()
    for key in bucket.list():
        thr = threading.Thread(target = key.delete, args=())
        thr.start()
        client_threads.append(thr)
    [thr.join() for thr in client_threads]

    time_diff = time.time() - start_time
    print('average time for deletion + amqp notification is: ' + str(time_diff*1000/number_of_objects) + ' milliseconds')

    print('wait for 5sec for the messages...')
    time.sleep(5)

    # check amqp receiver 1 for deletions
    receiver1.verify_s3_events(keys, exact_match=True, deletions=True)
    # check amqp receiver 2 has no deletions
    try:
        receiver1.verify_s3_events(keys, exact_match=False, deletions=True)
    except:
        pass
    else:
        err = 'amqp receiver 2 should have no deletions'
        assert False, err

    # cleanup
    stop_amqp_receiver(receiver1, task1)
    stop_amqp_receiver(receiver2, task2)
    s3_notification_conf.del_config()
    topic_conf1.del_config()
    topic_conf2.del_config()
    # delete the bucket
    conn.delete_bucket(bucket_name)

def test_ps_s3_notification_push_kafka_on_master():
    """ test pushing kafka s3 notification on master """
    conn = connection()
    zonegroup = 'default'

    # create bucket
    bucket_name = gen_bucket_name()
    bucket = conn.create_bucket(bucket_name)
    # name is constant for manual testing
    topic_name = bucket_name+'_topic'
    # create consumer on the topic
    task, receiver = create_kafka_receiver_thread(topic_name+'_1')
    task.start()

    # create s3 topic
    endpoint_address = 'kafka://' + kafka_server
    # without acks from broker
    endpoint_args = 'push-endpoint='+endpoint_address+'&kafka-ack-level=broker'
    topic_conf1 = PSTopicS3(conn, topic_name+'_1', zonegroup, endpoint_args=endpoint_args)
    topic_arn1 = topic_conf1.set_config()
    endpoint_args = 'push-endpoint='+endpoint_address+'&kafka-ack-level=none'
    topic_conf2 = PSTopicS3(conn, topic_name+'_2', zonegroup, endpoint_args=endpoint_args)
    topic_arn2 = topic_conf2.set_config()
    # create s3 notification
    notification_name = bucket_name + NOTIFICATION_SUFFIX
    topic_conf_list = [{'Id': notification_name + '_1', 'TopicArn': topic_arn1,
                         'Events': []
                       },
                       {'Id': notification_name + '_2', 'TopicArn': topic_arn2,
                         'Events': []
                       }]

    s3_notification_conf = PSNotificationS3(conn, bucket_name, topic_conf_list)
    response, status = s3_notification_conf.set_config()
    assert_equal(status/100, 2)

    # create objects in the bucket (async)
    number_of_objects = 10
    client_threads = []
    start_time = time.time()
    for i in range(number_of_objects):
        key = bucket.new_key(str(i))
        content = str(os.urandom(1024*1024))
        thr = threading.Thread(target = set_contents_from_string, args=(key, content,))
        thr.start()
        client_threads.append(thr)
    [thr.join() for thr in client_threads]

    time_diff = time.time() - start_time
    print('average time for creation + kafka notification is: ' + str(time_diff*1000/number_of_objects) + ' milliseconds')

    print('wait for 5sec for the messages...')
    time.sleep(5)
    keys = list(bucket.list())
    receiver.verify_s3_events(keys, exact_match=True)

    # delete objects from the bucket
    client_threads = []
    start_time = time.time()
    for key in bucket.list():
        thr = threading.Thread(target = key.delete, args=())
        thr.start()
        client_threads.append(thr)
    [thr.join() for thr in client_threads]

    time_diff = time.time() - start_time
    print('average time for deletion + kafka notification is: ' + str(time_diff*1000/number_of_objects) + ' milliseconds')

    print('wait for 5sec for the messages...')
    time.sleep(5)
    receiver.verify_s3_events(keys, exact_match=True, deletions=True)

    # cleanup
    s3_notification_conf.del_config()
    topic_conf1.del_config()
    topic_conf2.del_config()
    # delete the bucket
    conn.delete_bucket(bucket_name)
    stop_kafka_receiver(receiver, task)


def test_ps_s3_notification_multi_delete_on_master():
    """ test deletion of multiple keys on master """
    hostname = get_ip()
    conn = connection()
    zonegroup = 'default'

    # create random port for the http server
    host = get_ip()
    port = random.randint(10000, 20000)
    # start an http server in a separate thread
    number_of_objects = 10
    http_server = StreamingHTTPServer(host, port, num_workers=number_of_objects)

    # create bucket
    bucket_name = gen_bucket_name()
    bucket = conn.create_bucket(bucket_name)
    topic_name = bucket_name + TOPIC_SUFFIX

    # create s3 topic
    endpoint_address = 'http://'+host+':'+str(port)
    endpoint_args = 'push-endpoint='+endpoint_address
    topic_conf = PSTopicS3(conn, topic_name, zonegroup, endpoint_args=endpoint_args)
    topic_arn = topic_conf.set_config()
    # create s3 notification
    notification_name = bucket_name + NOTIFICATION_SUFFIX
    topic_conf_list = [{'Id': notification_name,
                        'TopicArn': topic_arn,
                        'Events': ['s3:ObjectRemoved:*']
                       }]
    s3_notification_conf = PSNotificationS3(conn, bucket_name, topic_conf_list)
    response, status = s3_notification_conf.set_config()
    assert_equal(status/100, 2)

    # create objects in the bucket
    client_threads = []
    objects_size = {}
    for i in range(number_of_objects):
        content = str(os.urandom(randint(1, 1024)))
        object_size = len(content)
        key = bucket.new_key(str(i))
        objects_size[key.name] = object_size
        thr = threading.Thread(target = set_contents_from_string, args=(key, content,))
        thr.start()
        client_threads.append(thr)
    [thr.join() for thr in client_threads]

    keys = list(bucket.list())

    start_time = time.time()
    delete_all_objects(conn, bucket_name)
    time_diff = time.time() - start_time
    print('average time for deletion + http notification is: ' + str(time_diff*1000/number_of_objects) + ' milliseconds')

    print('wait for 5sec for the messages...')
    time.sleep(5)

    # check http receiver
    http_server.verify_s3_events(keys, exact_match=True, deletions=True, expected_sizes=objects_size)

    # cleanup
    topic_conf.del_config()
    s3_notification_conf.del_config(notification=notification_name)
    # delete the bucket
    conn.delete_bucket(bucket_name)
    http_server.close()

def test_ps_s3_notification_push_http_on_master():
    """ test pushing http s3 notification on master """
    hostname = get_ip_http()
    conn = connection()
    zonegroup = 'default'

    # create random port for the http server
    host = get_ip()
    port = random.randint(10000, 20000)
    # start an http server in a separate thread
    number_of_objects = 10
    http_server = StreamingHTTPServer(host, port, num_workers=number_of_objects)

    # create bucket
    bucket_name = gen_bucket_name()
    bucket = conn.create_bucket(bucket_name)
    topic_name = bucket_name + TOPIC_SUFFIX

    # create s3 topic
    endpoint_address = 'http://'+host+':'+str(port)
    endpoint_args = 'push-endpoint='+endpoint_address
    topic_conf = PSTopicS3(conn, topic_name, zonegroup, endpoint_args=endpoint_args)
    topic_arn = topic_conf.set_config()
    # create s3 notification
    notification_name = bucket_name + NOTIFICATION_SUFFIX
    topic_conf_list = [{'Id': notification_name,
                        'TopicArn': topic_arn,
                        'Events': []
                       }]
    s3_notification_conf = PSNotificationS3(conn, bucket_name, topic_conf_list)
    response, status = s3_notification_conf.set_config()
    assert_equal(status/100, 2)

    # create objects in the bucket
    client_threads = []
    objects_size = {}
    start_time = time.time()
    for i in range(number_of_objects):
        content = str(os.urandom(randint(1, 1024)))
        object_size = len(content)
        key = bucket.new_key(str(i))
        objects_size[key.name] = object_size
        thr = threading.Thread(target = set_contents_from_string, args=(key, content,))
        thr.start()
        client_threads.append(thr)
    [thr.join() for thr in client_threads]

    time_diff = time.time() - start_time
    print('average time for creation + http notification is: ' + str(time_diff*1000/number_of_objects) + ' milliseconds')

    print('wait for 5sec for the messages...')
    time.sleep(5)

    # check http receiver
    keys = list(bucket.list())
    http_server.verify_s3_events(keys, exact_match=True, deletions=False, expected_sizes=objects_size)

    # delete objects from the bucket
    client_threads = []
    start_time = time.time()
    for key in bucket.list():
        thr = threading.Thread(target = key.delete, args=())
        thr.start()
        client_threads.append(thr)
    [thr.join() for thr in client_threads]

    time_diff = time.time() - start_time
    print('average time for deletion + http notification is: ' + str(time_diff*1000/number_of_objects) + ' milliseconds')

    print('wait for 5sec for the messages...')
    time.sleep(5)

    # check http receiver
    http_server.verify_s3_events(keys, exact_match=True, deletions=True, expected_sizes=objects_size)

    # cleanup
    topic_conf.del_config()
    s3_notification_conf.del_config(notification=notification_name)
    # delete the bucket
    conn.delete_bucket(bucket_name)
    http_server.close()

def test_ps_s3_opaque_data_on_master():
    """ test that opaque id set in topic, is sent in notification on master """
    hostname = get_ip()
    conn = connection()
    zonegroup = 'default'

    # create random port for the http server
    host = get_ip()
    port = random.randint(10000, 20000)
    # start an http server in a separate thread
    number_of_objects = 10
    http_server = StreamingHTTPServer(host, port, num_workers=number_of_objects)

    # create bucket
    bucket_name = gen_bucket_name()
    bucket = conn.create_bucket(bucket_name)
    topic_name = bucket_name + TOPIC_SUFFIX

    # create s3 topic
    endpoint_address = 'http://'+host+':'+str(port)
    endpoint_args = 'push-endpoint='+endpoint_address
    opaque_data = 'http://1.2.3.4:8888'
    topic_conf = PSTopicS3(conn, topic_name, zonegroup, endpoint_args=endpoint_args, opaque_data=opaque_data)
    topic_arn = topic_conf.set_config()
    # create s3 notification
    notification_name = bucket_name + NOTIFICATION_SUFFIX
    topic_conf_list = [{'Id': notification_name,
                        'TopicArn': topic_arn,
                        'Events': []
                       }]
    s3_notification_conf = PSNotificationS3(conn, bucket_name, topic_conf_list)
    response, status = s3_notification_conf.set_config()
    assert_equal(status/100, 2)

    # create objects in the bucket
    client_threads = []
    start_time = time.time()
    content = 'bar'
    for i in range(number_of_objects):
        key = bucket.new_key(str(i))
        thr = threading.Thread(target = set_contents_from_string, args=(key, content,))
        thr.start()
        client_threads.append(thr)
    [thr.join() for thr in client_threads]

    time_diff = time.time() - start_time
    print('average time for creation + http notification is: ' + str(time_diff*1000/number_of_objects) + ' milliseconds')

    print('wait for 5sec for the messages...')
    time.sleep(5)

    # check http receiver
    keys = list(bucket.list())
    print('total number of objects: ' + str(len(keys)))
    events = http_server.get_and_reset_events()
    for event in events:
        assert_equal(event['Records'][0]['opaqueData'], opaque_data)

    # cleanup
    for key in keys:
        key.delete()
    [thr.join() for thr in client_threads]
    topic_conf.del_config()
    s3_notification_conf.del_config(notification=notification_name)
    # delete the bucket
    conn.delete_bucket(bucket_name)
    http_server.close()

def test_ps_s3_creation_triggers_on_master():
    """ test object creation s3 notifications in using put/copy/post on master"""
    return SkipTest('This is an AMQP test.')

    hostname = get_ip()
    conn = connection()
    zonegroup = 'default'

    # create bucket
    bucket_name = gen_bucket_name()
    bucket = conn.create_bucket(bucket_name)
    topic_name = bucket_name + TOPIC_SUFFIX

    # start amqp receiver
    exchange = 'ex1'
    task, receiver = create_amqp_receiver_thread(exchange, topic_name)
    task.start()

    # create s3 topic
    endpoint_address = 'amqp://' + hostname
    endpoint_args = 'push-endpoint='+endpoint_address+'&amqp-exchange=' + exchange +'&amqp-ack-level=broker'
    topic_conf = PSTopicS3(conn, topic_name, zonegroup, endpoint_args=endpoint_args)
    topic_arn = topic_conf.set_config()
    # create s3 notification
    notification_name = bucket_name + NOTIFICATION_SUFFIX
    topic_conf_list = [{'Id': notification_name,'TopicArn': topic_arn,
                        'Events': ['s3:ObjectCreated:Put', 's3:ObjectCreated:Copy']
                       }]

    s3_notification_conf = PSNotificationS3(conn, bucket_name, topic_conf_list)
    response, status = s3_notification_conf.set_config()
    assert_equal(status/100, 2)

    # create objects in the bucket using PUT
    key = bucket.new_key('put')
    key.set_contents_from_string('bar')
    # create objects in the bucket using COPY
    bucket.copy_key('copy', bucket.name, key.name)

    # create objects in the bucket using multi-part upload
    fp = tempfile.NamedTemporaryFile(mode='w+b')
    object_size = 10*1024*1024
    content = bytearray(os.urandom(object_size))
    fp.write(content)
    fp.flush()
    fp.seek(0)
    uploader = bucket.initiate_multipart_upload('multipart')
    uploader.upload_part_from_file(fp, 1)
    uploader.complete_upload()
    fp.close()

    print('wait for 5sec for the messages...')
    time.sleep(5)

    # check amqp receiver
    keys = list(bucket.list())
    receiver.verify_s3_events(keys, exact_match=True)

    # cleanup
    stop_amqp_receiver(receiver, task)
    s3_notification_conf.del_config()
    topic_conf.del_config()
    for key in bucket.list():
        key.delete()
    # delete the bucket
    conn.delete_bucket(bucket_name)

def test_ps_s3_multipart_on_master():
    """ test multipart object upload on master"""
    return SkipTest('This is an AMQP test.')

    hostname = get_ip()
    conn = connection()
    zonegroup = 'default'

    # create bucket
    bucket_name = gen_bucket_name()
    bucket = conn.create_bucket(bucket_name)
    topic_name = bucket_name + TOPIC_SUFFIX

    # start amqp receivers
    exchange = 'ex1'
    task1, receiver1 = create_amqp_receiver_thread(exchange, topic_name+'_1')
    task1.start()
    task2, receiver2 = create_amqp_receiver_thread(exchange, topic_name+'_2')
    task2.start()
    task3, receiver3 = create_amqp_receiver_thread(exchange, topic_name+'_3')
    task3.start()

    # create s3 topics
    endpoint_address = 'amqp://' + hostname
    endpoint_args = 'push-endpoint=' + endpoint_address + '&amqp-exchange=' + exchange + '&amqp-ack-level=broker'
    topic_conf1 = PSTopicS3(conn, topic_name+'_1', zonegroup, endpoint_args=endpoint_args)
    topic_arn1 = topic_conf1.set_config()
    topic_conf2 = PSTopicS3(conn, topic_name+'_2', zonegroup, endpoint_args=endpoint_args)
    topic_arn2 = topic_conf2.set_config()
    topic_conf3 = PSTopicS3(conn, topic_name+'_3', zonegroup, endpoint_args=endpoint_args)
    topic_arn3 = topic_conf3.set_config()

    # create s3 notifications
    notification_name = bucket_name + NOTIFICATION_SUFFIX
    topic_conf_list = [{'Id': notification_name+'_1', 'TopicArn': topic_arn1,
                        'Events': ['s3:ObjectCreated:*']
                       },
                       {'Id': notification_name+'_2', 'TopicArn': topic_arn2,
                        'Events': ['s3:ObjectCreated:Post']
                       },
                       {'Id': notification_name+'_3', 'TopicArn': topic_arn3,
                        'Events': ['s3:ObjectCreated:CompleteMultipartUpload']
                       }]
    s3_notification_conf = PSNotificationS3(conn, bucket_name, topic_conf_list)
    response, status = s3_notification_conf.set_config()
    assert_equal(status/100, 2)

    # create objects in the bucket using multi-part upload
    fp = tempfile.NamedTemporaryFile(mode='w+b')
    object_size = 1024
    content = bytearray(os.urandom(object_size))
    fp.write(content)
    fp.flush()
    fp.seek(0)
    uploader = bucket.initiate_multipart_upload('multipart')
    uploader.upload_part_from_file(fp, 1)
    uploader.complete_upload()
    fp.close()

    print('wait for 5sec for the messages...')
    time.sleep(5)

    # check amqp receiver
    events = receiver1.get_and_reset_events()
    assert_equal(len(events), 3)

    events = receiver2.get_and_reset_events()
    assert_equal(len(events), 1)
    assert_equal(events[0]['Records'][0]['eventName'], 's3:ObjectCreated:Post')
    assert_equal(events[0]['Records'][0]['s3']['configurationId'], notification_name+'_2')

    events = receiver3.get_and_reset_events()
    assert_equal(len(events), 1)
    assert_equal(events[0]['Records'][0]['eventName'], 's3:ObjectCreated:CompleteMultipartUpload')
    assert_equal(events[0]['Records'][0]['s3']['configurationId'], notification_name+'_3')
    print(events[0]['Records'][0]['s3']['object']['size'])

    # cleanup
    stop_amqp_receiver(receiver1, task1)
    stop_amqp_receiver(receiver2, task2)
    stop_amqp_receiver(receiver3, task3)
    s3_notification_conf.del_config()
    topic_conf1.del_config()
    topic_conf2.del_config()
    topic_conf3.del_config()
    for key in bucket.list():
        key.delete()
    # delete the bucket
    conn.delete_bucket(bucket_name)

def test_ps_s3_metadata_on_master():
    """ test s3 notification of metadata on master """
    return SkipTest('This is an AMQP test.')

    hostname = get_ip()
    conn = connection()
    zonegroup = 'default'

    # create bucket
    bucket_name = gen_bucket_name()
    bucket = conn.create_bucket(bucket_name)
    topic_name = bucket_name + TOPIC_SUFFIX

    # start amqp receiver
    exchange = 'ex1'
    task, receiver = create_amqp_receiver_thread(exchange, topic_name)
    task.start()

    # create s3 topic
    endpoint_address = 'amqp://' + hostname
    endpoint_args = 'push-endpoint='+endpoint_address+'&amqp-exchange=' + exchange +'&amqp-ack-level=routable'
    topic_conf = PSTopicS3(conn, topic_name, zonegroup, endpoint_args=endpoint_args)
    topic_arn = topic_conf.set_config()
    # create s3 notification
    notification_name = bucket_name + NOTIFICATION_SUFFIX
    meta_key = 'meta1'
    meta_value = 'This is my metadata value'
    meta_prefix = 'x-amz-meta-'
    topic_conf_list = [{'Id': notification_name,'TopicArn': topic_arn,
        'Events': ['s3:ObjectCreated:*', 's3:ObjectRemoved:*'],
        'Filter': {
            'Metadata': {
                'FilterRules': [{'Name': meta_prefix+meta_key, 'Value': meta_value}]
            }
        }
    }]

    s3_notification_conf = PSNotificationS3(conn, bucket_name, topic_conf_list)
    response, status = s3_notification_conf.set_config()
    assert_equal(status/100, 2)

    # create objects in the bucket
    key_name = 'foo'
    key = bucket.new_key(key_name)
    key.set_metadata(meta_key, meta_value)
    key.set_contents_from_string('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')

    # create objects in the bucket using COPY
    bucket.copy_key('copy_of_foo', bucket.name, key.name)

    # create objects in the bucket using multi-part upload
    fp = tempfile.NamedTemporaryFile(mode='w+b')
    object_size = 1024
    content = bytearray(os.urandom(object_size))
    fp.write(content)
    fp.flush()
    fp.seek(0)
    uploader = bucket.initiate_multipart_upload('multipart_foo',
            metadata={meta_key: meta_value})
    uploader.upload_part_from_file(fp, 1)
    uploader.complete_upload()
    fp.close()

    print('wait for 5sec for the messages...')
    time.sleep(5)
    # check amqp receiver
    event_count = 0
    for event in receiver.get_and_reset_events():
        s3_event = event['Records'][0]['s3']
        assert_equal(s3_event['object']['metadata'][0]['key'], meta_prefix+meta_key)
        assert_equal(s3_event['object']['metadata'][0]['val'], meta_value)
        event_count +=1

    # only PUT and POST has the metadata value
    assert_equal(event_count, 2)

    # delete objects
    for key in bucket.list():
        key.delete()
    print('wait for 5sec for the messages...')
    time.sleep(5)
    # check amqp receiver
    event_count = 0
    for event in receiver.get_and_reset_events():
        s3_event = event['Records'][0]['s3']
        assert_equal(s3_event['object']['metadata'][0]['key'], meta_prefix+meta_key)
        assert_equal(s3_event['object']['metadata'][0]['val'], meta_value)
        event_count +=1

    # all 3 object has metadata when deleted
    assert_equal(event_count, 3)

    # cleanup
    stop_amqp_receiver(receiver, task)
    s3_notification_conf.del_config()
    topic_conf.del_config()
    # delete the bucket
    conn.delete_bucket(bucket_name)

def test_ps_s3_tags_on_master():
    """ test s3 notification of tags on master """
    return SkipTest('This is an AMQP test.')

    hostname = get_ip()
    conn = connection()
    zonegroup = 'default'

    # create bucket
    bucket_name = gen_bucket_name()
    bucket = conn.create_bucket(bucket_name)
    topic_name = bucket_name + TOPIC_SUFFIX

    # start amqp receiver
    exchange = 'ex1'
    task, receiver = create_amqp_receiver_thread(exchange, topic_name)
    task.start()

    # create s3 topic
    endpoint_address = 'amqp://' + hostname
    endpoint_args = 'push-endpoint='+endpoint_address+'&amqp-exchange=' + exchange +'&amqp-ack-level=routable'
    topic_conf = PSTopicS3(conn, topic_name, zonegroup, endpoint_args=endpoint_args)
    topic_arn = topic_conf.set_config()
    # create s3 notification
    notification_name = bucket_name + NOTIFICATION_SUFFIX
    topic_conf_list = [{'Id': notification_name,'TopicArn': topic_arn,
        'Events': ['s3:ObjectCreated:*', 's3:ObjectRemoved:*'],
        'Filter': {
            'Tags': {
                'FilterRules': [{'Name': 'hello', 'Value': 'world'}]
            }
        }
    }]

    s3_notification_conf = PSNotificationS3(conn, bucket_name, topic_conf_list)
    response, status = s3_notification_conf.set_config()
    assert_equal(status/100, 2)

    # create objects in the bucket with tags
    tags = 'hello=world&ka=boom'
    key_name1 = 'key1'
    put_object_tagging(conn, bucket_name, key_name1, tags)
    tags = 'foo=bar&ka=boom'
    key_name2 = 'key2'
    put_object_tagging(conn, bucket_name, key_name2, tags)
    key_name3 = 'key3'
    key = bucket.new_key(key_name3)
    key.set_contents_from_string('bar')
    # create objects in the bucket using COPY
    bucket.copy_key('copy_of_'+key_name1, bucket.name, key_name1)
    print('wait for 5sec for the messages...')
    time.sleep(5)
    expected_tags = [{'val': 'world', 'key': 'hello'}, {'val': 'boom', 'key': 'ka'}]
    # check amqp receiver
    for event in receiver.get_and_reset_events():
        obj_tags =  event['Records'][0]['s3']['object']['tags']
        assert_equal(obj_tags[0], expected_tags[0])

    # delete the objects
    for key in bucket.list():
        key.delete()
    print('wait for 5sec for the messages...')
    time.sleep(5)
    # check amqp receiver
    for event in receiver.get_and_reset_events():
        obj_tags =  event['Records'][0]['s3']['object']['tags']
        assert_equal(obj_tags[0], expected_tags[0])

    # cleanup
    stop_amqp_receiver(receiver, task)
    s3_notification_conf.del_config()
    topic_conf.del_config()
    # delete the bucket
    conn.delete_bucket(bucket_name)

def test_ps_s3_versioning_on_master():
    """ test s3 notification of object versions """
    return SkipTest('This is an AMQP test.')

    hostname = get_ip()
    conn = connection()
    zonegroup = 'default'

    # create bucket
    bucket_name = gen_bucket_name()
    bucket = conn.create_bucket(bucket_name)
    bucket.configure_versioning(True)
    topic_name = bucket_name + TOPIC_SUFFIX

    # start amqp receiver
    exchange = 'ex1'
    task, receiver = create_amqp_receiver_thread(exchange, topic_name)
    task.start()

    # create s3 topic
    endpoint_address = 'amqp://' + hostname
    endpoint_args = 'push-endpoint='+endpoint_address+'&amqp-exchange=' + exchange +'&amqp-ack-level=broker'
    topic_conf = PSTopicS3(conn, topic_name, zonegroup, endpoint_args=endpoint_args)
    topic_arn = topic_conf.set_config()
    # create notification
    notification_name = bucket_name + NOTIFICATION_SUFFIX
    topic_conf_list = [{'Id': notification_name, 'TopicArn': topic_arn,
                        'Events': []
                       }]
    s3_notification_conf = PSNotificationS3(conn, bucket_name, topic_conf_list)
    _, status = s3_notification_conf.set_config()
    assert_equal(status/100, 2)

    # create objects in the bucket
    key_value = 'foo'
    key = bucket.new_key(key_value)
    key.set_contents_from_string('hello')
    ver1 = key.version_id
    key.set_contents_from_string('world')
    ver2 = key.version_id

    print('wait for 5sec for the messages...')
    time.sleep(5)

    # check amqp receiver
    events = receiver.get_and_reset_events()
    num_of_versions = 0
    for event_list in events:
        for event in event_list['Records']:
            assert_equal(event['s3']['object']['key'], key_value)
            version = event['s3']['object']['versionId']
            num_of_versions += 1
            if version not in (ver1, ver2):
                print('version mismatch: '+version+' not in: ('+ver1+', '+ver2+')')
                assert_equal(1, 0)
            else:
                print('version ok: '+version+' in: ('+ver1+', '+ver2+')')

    assert_equal(num_of_versions, 2)

    # cleanup
    stop_amqp_receiver(receiver, task)
    s3_notification_conf.del_config()
    topic_conf.del_config()
    # delete the bucket
    bucket.delete_key(key.name, version_id=ver2)
    bucket.delete_key(key.name, version_id=ver1)
    conn.delete_bucket(bucket_name)

def test_ps_s3_versioned_deletion_on_master():
    """ test s3 notification of deletion markers on master """
    return SkipTest('This is an AMQP test.')

    hostname = get_ip()
    conn = connection()
    zonegroup = 'default'

    # create bucket
    bucket_name = gen_bucket_name()
    bucket = conn.create_bucket(bucket_name)
    bucket.configure_versioning(True)
    topic_name = bucket_name + TOPIC_SUFFIX

    # start amqp receiver
    exchange = 'ex1'
    task, receiver = create_amqp_receiver_thread(exchange, topic_name)
    task.start()

    # create s3 topic
    endpoint_address = 'amqp://' + hostname
    endpoint_args = 'push-endpoint='+endpoint_address+'&amqp-exchange=' + exchange +'&amqp-ack-level=broker'
    topic_conf = PSTopicS3(conn, topic_name, zonegroup, endpoint_args=endpoint_args)
    topic_arn = topic_conf.set_config()
    # create s3 notification
    notification_name = bucket_name + NOTIFICATION_SUFFIX
    topic_conf_list = [{'Id': notification_name+'_1', 'TopicArn': topic_arn,
                        'Events': ['s3:ObjectRemoved:*']
                       },
                       {'Id': notification_name+'_2', 'TopicArn': topic_arn,
                        'Events': ['s3:ObjectRemoved:DeleteMarkerCreated']
                       },
                       {'Id': notification_name+'_3', 'TopicArn': topic_arn,
                         'Events': ['s3:ObjectRemoved:Delete']
                       }]
    s3_notification_conf = PSNotificationS3(conn, bucket_name, topic_conf_list)
    response, status = s3_notification_conf.set_config()
    assert_equal(status/100, 2)

    # create objects in the bucket
    key = bucket.new_key('foo')
    key.set_contents_from_string('bar')
    v1 = key.version_id
    key.set_contents_from_string('kaboom')
    v2 = key.version_id
    # create delete marker (non versioned deletion)
    delete_marker_key = bucket.delete_key(key.name)

    time.sleep(1)

    # versioned deletion
    bucket.delete_key(key.name, version_id=v2)
    bucket.delete_key(key.name, version_id=v1)
    delete_marker_key.delete()

    print('wait for 5sec for the messages...')
    time.sleep(5)

    # check amqp receiver
    events = receiver.get_and_reset_events()
    delete_events = 0
    delete_marker_create_events = 0
    for event_list in events:
        for event in event_list['Records']:
            if event['eventName'] == 's3:ObjectRemoved:Delete':
                delete_events += 1
                assert event['s3']['configurationId'] in [notification_name+'_1', notification_name+'_3']
            if event['eventName'] == 's3:ObjectRemoved:DeleteMarkerCreated':
                delete_marker_create_events += 1
                assert event['s3']['configurationId'] in [notification_name+'_1', notification_name+'_2']

    # 3 key versions were deleted (v1, v2 and the deletion marker)
    # notified over the same topic via 2 notifications (1,3)
    assert_equal(delete_events, 3*2)
    # 1 deletion marker was created
    # notified over the same topic over 2 notifications (1,2)
    assert_equal(delete_marker_create_events, 1*2)

    # cleanup
    stop_amqp_receiver(receiver, task)
    s3_notification_conf.del_config()
    topic_conf.del_config()
    # delete the bucket
    conn.delete_bucket(bucket_name)

def test_ps_s3_persistent_cleanup():
    """ test reservation cleanup after gateway crash """
    return SkipTest("only used in manual testing")
    conn = connection()
    zonegroup = 'default'

    # create random port for the http server
    host = get_ip()
    port = random.randint(10000, 20000)
    # start an http server in a separate thread
    number_of_objects = 200
    http_server = StreamingHTTPServer(host, port, num_workers=number_of_objects)

    gw = conn

    # create bucket
    bucket_name = gen_bucket_name()
    bucket = gw.create_bucket(bucket_name)
    topic_name = bucket_name + TOPIC_SUFFIX

    # create s3 topic
    endpoint_address = 'http://'+host+':'+str(port)
    endpoint_args = 'push-endpoint='+endpoint_address+'&persistent=true'
    topic_conf = PSTopicS3(gw, topic_name, zonegroup, endpoint_args=endpoint_args)
    topic_arn = topic_conf.set_config()

    # create s3 notification
    notification_name = bucket_name + NOTIFICATION_SUFFIX
    topic_conf_list = [{'Id': notification_name, 'TopicArn': topic_arn,
        'Events': ['s3:ObjectCreated:Put']
        }]
    s3_notification_conf = PSNotificationS3(gw, bucket_name, topic_conf_list)
    response, status = s3_notification_conf.set_config()
    assert_equal(status/100, 2)

    client_threads = []
    start_time = time.time()
    for i in range(number_of_objects):
        key = bucket.new_key(str(i))
        content = str(os.urandom(1024*1024))
        thr = threading.Thread(target = set_contents_from_string, args=(key, content,))
        thr.start()
        client_threads.append(thr)
    # stop gateway while clients are sending
    os.system("killall -9 radosgw");
    zonegroup.master_zone.gateways[0].stop()
    print('wait for 10 sec for before restarting the gateway')
    time.sleep(10)
    zonegroup.master_zone.gateways[0].start()
    [thr.join() for thr in client_threads]

    keys = list(bucket.list())

    # delete objects from the bucket
    client_threads = []
    start_time = time.time()
    for key in bucket.list():
        thr = threading.Thread(target = key.delete, args=())
        thr.start()
        client_threads.append(thr)
    [thr.join() for thr in client_threads]

    # check http receiver
    events = http_server.get_and_reset_events()

    print(str(len(events) ) + " events found out of " + str(number_of_objects))

    # make sure that things are working now
    client_threads = []
    start_time = time.time()
    for i in range(number_of_objects):
        key = bucket.new_key(str(i))
        content = str(os.urandom(1024*1024))
        thr = threading.Thread(target = set_contents_from_string, args=(key, content,))
        thr.start()
        client_threads.append(thr)
    [thr.join() for thr in client_threads]

    keys = list(bucket.list())

    # delete objects from the bucket
    client_threads = []
    start_time = time.time()
    for key in bucket.list():
        thr = threading.Thread(target = key.delete, args=())
        thr.start()
        client_threads.append(thr)
    [thr.join() for thr in client_threads]

    print('wait for 180 sec for reservations to be stale before queue deletion')
    time.sleep(180)

    # check http receiver
    events = http_server.get_and_reset_events()

    print(str(len(events)) + " events found out of " + str(number_of_objects))

    # cleanup
    s3_notification_conf.del_config()
    topic_conf.del_config()
    gw.delete_bucket(bucket_name)
    http_server.close()

def test_ps_s3_persistent_notification_pushback():
    """ test pushing persistent notification pushback """
    return SkipTest("only used in manual testing")
    conn = connection()
    zonegroup = 'default'

    # create random port for the http server
    host = get_ip()
    port = random.randint(10000, 20000)
    # start an http server in a separate thread
    http_server = StreamingHTTPServer(host, port, num_workers=10, delay=0.5)

    # create bucket
    bucket_name = gen_bucket_name()
    bucket = conn.create_bucket(bucket_name)
    topic_name = bucket_name + TOPIC_SUFFIX

    # create s3 topic
    endpoint_address = 'http://'+host+':'+str(port)
    endpoint_args = 'push-endpoint='+endpoint_address+'&persistent=true'
    topic_conf = PSTopicS3(conn, topic_name, zonegroup, endpoint_args=endpoint_args)
    topic_arn = topic_conf.set_config()
    # create s3 notification
    notification_name = bucket_name + NOTIFICATION_SUFFIX
    topic_conf_list = [{'Id': notification_name, 'TopicArn': topic_arn,
                         'Events': []
                       }]

    s3_notification_conf = PSNotificationS3(conn, bucket_name, topic_conf_list)
    response, status = s3_notification_conf.set_config()
    assert_equal(status/100, 2)

    # create objects in the bucket (async)
    for j in range(100):
        number_of_objects = randint(500, 1000)
        client_threads = []
        start_time = time.time()
        for i in range(number_of_objects):
            key = bucket.new_key(str(j)+'-'+str(i))
            content = str(os.urandom(1024*1024))
            thr = threading.Thread(target = set_contents_from_string, args=(key, content,))
            thr.start()
            client_threads.append(thr)
        [thr.join() for thr in client_threads]
        time_diff = time.time() - start_time
        print('average time for creation + async http notification is: ' + str(time_diff*1000/number_of_objects) + ' milliseconds')

    keys = list(bucket.list())

    delay = 30
    print('wait for '+str(delay)+'sec for the messages...')
    time.sleep(delay)

    # delete objects from the bucket
    client_threads = []
    start_time = time.time()
    count = 0
    for key in bucket.list():
        count += 1
        thr = threading.Thread(target = key.delete, args=())
        thr.start()
        client_threads.append(thr)
        if count%100 == 0:
            [thr.join() for thr in client_threads]
            time_diff = time.time() - start_time
            print('average time for deletion + async http notification is: ' + str(time_diff*1000/number_of_objects) + ' milliseconds')
            client_threads = []
            start_time = time.time()

    print('wait for '+str(delay)+'sec for the messages...')
    time.sleep(delay)

    # cleanup
    s3_notification_conf.del_config()
    topic_conf.del_config()
    # delete the bucket
    conn.delete_bucket(bucket_name)
    time.sleep(delay)
    http_server.close()

def test_ps_s3_persistent_gateways_recovery():
    """ test gateway recovery of persistent notifications """
    return SkipTest('This test requires two gateways.')

    conn = connection()
    zonegroup = 'default'
    # create random port for the http server
    host = get_ip()
    port = random.randint(10000, 20000)
    # start an http server in a separate thread
    number_of_objects = 10
    http_server = StreamingHTTPServer(host, port, num_workers=number_of_objects)
    gw1 = conn
    gw2 = connection2()
    # create bucket
    bucket_name = gen_bucket_name()
    bucket = gw1.create_bucket(bucket_name)
    topic_name = bucket_name + TOPIC_SUFFIX
    # create two s3 topics
    endpoint_address = 'http://'+host+':'+str(port)
    endpoint_args = 'push-endpoint='+endpoint_address+'&persistent=true'
    topic_conf1 = PSTopicS3(gw1, topic_name+'_1', zonegroup, endpoint_args=endpoint_args+'&OpaqueData=fromgw1')
    topic_arn1 = topic_conf1.set_config()
    topic_conf2 = PSTopicS3(gw2, topic_name+'_2', zonegroup, endpoint_args=endpoint_args+'&OpaqueData=fromgw2')
    topic_arn2 = topic_conf2.set_config()
    # create two s3 notifications
    notification_name = bucket_name + NOTIFICATION_SUFFIX+'_1'
    topic_conf_list = [{'Id': notification_name, 'TopicArn': topic_arn1,
        'Events': ['s3:ObjectCreated:Put']
        }]
    s3_notification_conf1 = PSNotificationS3(gw1, bucket_name, topic_conf_list)
    response, status = s3_notification_conf1.set_config()
    assert_equal(status/100, 2)
    notification_name = bucket_name + NOTIFICATION_SUFFIX+'_2'
    topic_conf_list = [{'Id': notification_name, 'TopicArn': topic_arn2,
        'Events': ['s3:ObjectRemoved:Delete']
        }]
    s3_notification_conf2 = PSNotificationS3(gw2, bucket_name, topic_conf_list)
    response, status = s3_notification_conf2.set_config()
    assert_equal(status/100, 2)
    # stop gateway 2
    print('stopping gateway2...')
    client_threads = []
    start_time = time.time()
    for i in range(number_of_objects):
        key = bucket.new_key(str(i))
        content = str(os.urandom(1024*1024))
        thr = threading.Thread(target = set_contents_from_string, args=(key, content,))
        thr.start()
        client_threads.append(thr)
    [thr.join() for thr in client_threads]
    keys = list(bucket.list())
    # delete objects from the bucket
    client_threads = []
    start_time = time.time()
    for key in bucket.list():
        thr = threading.Thread(target = key.delete, args=())
        thr.start()
        client_threads.append(thr)
    [thr.join() for thr in client_threads]
    print('wait for 60 sec for before restarting the gateway')
    time.sleep(60)
    # check http receiver
    events = http_server.get_and_reset_events()
    for key in keys:
        creations = 0
        deletions = 0
        for event in events:
            if event['Records'][0]['eventName'] == 's3:ObjectCreated:Put' and \
                    key.name == event['Records'][0]['s3']['object']['key']:
                creations += 1
            elif event['Records'][0]['eventName'] == 's3:ObjectRemoved:Delete' and \
                    key.name == event['Records'][0]['s3']['object']['key']:
                deletions += 1
        assert_equal(creations, 1)
        assert_equal(deletions, 1)
    # cleanup
    s3_notification_conf1.del_config()
    topic_conf1.del_config()
    gw1.delete_bucket(bucket_name)
    time.sleep(10)
    s3_notification_conf2.del_config()
    topic_conf2.del_config()
    http_server.close()

def test_ps_s3_persistent_multiple_gateways():
    """ test pushing persistent notification via two gateways """
    return SkipTest('This test requires two gateways.')

    conn = connection()
    zonegroup = 'default'
    # create random port for the http server
    host = get_ip()
    port = random.randint(10000, 20000)
    # start an http server in a separate thread
    number_of_objects = 10
    http_server = StreamingHTTPServer(host, port, num_workers=number_of_objects)
    gw1 = conn
    gw2 = connection2()
    # create bucket
    bucket_name = gen_bucket_name()
    bucket1 = gw1.create_bucket(bucket_name)
    bucket2 = gw2.get_bucket(bucket_name)
    topic_name = bucket_name + TOPIC_SUFFIX
    # create two s3 topics
    endpoint_address = 'http://'+host+':'+str(port)
    endpoint_args = 'push-endpoint='+endpoint_address+'&persistent=true'
    topic1_opaque = 'fromgw1'
    topic_conf1 = PSTopicS3(gw1, topic_name+'_1', zonegroup, endpoint_args=endpoint_args+'&OpaqueData='+topic1_opaque)
    topic_arn1 = topic_conf1.set_config()
    topic2_opaque = 'fromgw2'
    topic_conf2 = PSTopicS3(gw2, topic_name+'_2', zonegroup, endpoint_args=endpoint_args+'&OpaqueData='+topic2_opaque)
    topic_arn2 = topic_conf2.set_config()
    # create two s3 notifications
    notification_name = bucket_name + NOTIFICATION_SUFFIX+'_1'
    topic_conf_list = [{'Id': notification_name, 'TopicArn': topic_arn1,
                         'Events': []
                       }]
    s3_notification_conf1 = PSNotificationS3(gw1, bucket_name, topic_conf_list)
    response, status = s3_notification_conf1.set_config()
    assert_equal(status/100, 2)
    notification_name = bucket_name + NOTIFICATION_SUFFIX+'_2'
    topic_conf_list = [{'Id': notification_name, 'TopicArn': topic_arn2,
                         'Events': []
                       }]
    s3_notification_conf2 = PSNotificationS3(gw2, bucket_name, topic_conf_list)
    response, status = s3_notification_conf2.set_config()
    assert_equal(status/100, 2)
    client_threads = []
    start_time = time.time()
    for i in range(number_of_objects):
        key = bucket1.new_key('gw1_'+str(i))
        content = str(os.urandom(1024*1024))
        thr = threading.Thread(target = set_contents_from_string, args=(key, content,))
        thr.start()
        client_threads.append(thr)
        key = bucket2.new_key('gw2_'+str(i))
        content = str(os.urandom(1024*1024))
        thr = threading.Thread(target = set_contents_from_string, args=(key, content,))
        thr.start()
        client_threads.append(thr)
    [thr.join() for thr in client_threads]
    keys = list(bucket1.list())
    delay = 30
    print('wait for '+str(delay)+'sec for the messages...')
    time.sleep(delay)
    events = http_server.get_and_reset_events()
    for key in keys:
        topic1_count = 0
        topic2_count = 0
        for event in events:
            if event['Records'][0]['eventName'] == 's3:ObjectCreated:Put' and \
                    key.name == event['Records'][0]['s3']['object']['key'] and \
                    topic1_opaque == event['Records'][0]['opaqueData']:
                topic1_count += 1
            elif event['Records'][0]['eventName'] == 's3:ObjectCreated:Put' and \
                    key.name == event['Records'][0]['s3']['object']['key'] and \
                    topic2_opaque == event['Records'][0]['opaqueData']:
                topic2_count += 1
        assert_equal(topic1_count, 1)
        assert_equal(topic2_count, 1)
    # delete objects from the bucket
    client_threads = []
    start_time = time.time()
    for key in bucket1.list():
        thr = threading.Thread(target = key.delete, args=())
        thr.start()
        client_threads.append(thr)
    [thr.join() for thr in client_threads]
    print('wait for '+str(delay)+'sec for the messages...')
    time.sleep(delay)
    events = http_server.get_and_reset_events()
    for key in keys:
        topic1_count = 0
        topic2_count = 0
        for event in events:
            if event['Records'][0]['eventName'] == 's3:ObjectRemoved:Delete' and \
                    key.name == event['Records'][0]['s3']['object']['key'] and \
                    topic1_opaque == event['Records'][0]['opaqueData']:
                topic1_count += 1
            elif event['Records'][0]['eventName'] == 's3:ObjectRemoved:Delete' and \
                    key.name == event['Records'][0]['s3']['object']['key'] and \
                    topic2_opaque == event['Records'][0]['opaqueData']:
                topic2_count += 1
        assert_equal(topic1_count, 1)
        assert_equal(topic2_count, 1)
    # cleanup
    s3_notification_conf1.del_config()
    topic_conf1.del_config()
    s3_notification_conf2.del_config()
    topic_conf2.del_config()
    gw1.delete_bucket(bucket_name)
    http_server.close()

def test_ps_s3_persistent_multiple_endpoints():
    """ test pushing persistent notification when one of the endpoints has error """
    conn = connection()
    zonegroup = 'default'

    # create random port for the http server
    host = get_ip()
    port = random.randint(10000, 20000)
    # start an http server in a separate thread
    number_of_objects = 10
    http_server = StreamingHTTPServer(host, port, num_workers=number_of_objects)

    # create bucket
    bucket_name = gen_bucket_name()
    bucket = conn.create_bucket(bucket_name)
    topic_name = bucket_name + TOPIC_SUFFIX

    # create two s3 topics
    endpoint_address = 'http://'+host+':'+str(port)
    endpoint_args = 'push-endpoint='+endpoint_address+'&persistent=true'
    topic_conf1 = PSTopicS3(conn, topic_name+'_1', zonegroup, endpoint_args=endpoint_args)
    topic_arn1 = topic_conf1.set_config()
    endpoint_address = 'http://kaboom:9999'
    endpoint_args = 'push-endpoint='+endpoint_address+'&persistent=true'
    topic_conf2 = PSTopicS3(conn, topic_name+'_2', zonegroup, endpoint_args=endpoint_args)
    topic_arn2 = topic_conf2.set_config()

    # create two s3 notifications
    notification_name = bucket_name + NOTIFICATION_SUFFIX+'_1'
    topic_conf_list = [{'Id': notification_name, 'TopicArn': topic_arn1,
                         'Events': []
                       }]
    s3_notification_conf1 = PSNotificationS3(conn, bucket_name, topic_conf_list)
    response, status = s3_notification_conf1.set_config()
    assert_equal(status/100, 2)
    notification_name = bucket_name + NOTIFICATION_SUFFIX+'_2'
    topic_conf_list = [{'Id': notification_name, 'TopicArn': topic_arn2,
                         'Events': []
                       }]
    s3_notification_conf2 = PSNotificationS3(conn, bucket_name, topic_conf_list)
    response, status = s3_notification_conf2.set_config()
    assert_equal(status/100, 2)

    client_threads = []
    start_time = time.time()
    for i in range(number_of_objects):
        key = bucket.new_key(str(i))
        content = str(os.urandom(1024*1024))
        thr = threading.Thread(target = set_contents_from_string, args=(key, content,))
        thr.start()
        client_threads.append(thr)
    [thr.join() for thr in client_threads]

    keys = list(bucket.list())

    delay = 30
    print('wait for '+str(delay)+'sec for the messages...')
    time.sleep(delay)

    http_server.verify_s3_events(keys, exact_match=False, deletions=False)

    # delete objects from the bucket
    client_threads = []
    start_time = time.time()
    for key in bucket.list():
        thr = threading.Thread(target = key.delete, args=())
        thr.start()
        client_threads.append(thr)
    [thr.join() for thr in client_threads]

    print('wait for '+str(delay)+'sec for the messages...')
    time.sleep(delay)

    http_server.verify_s3_events(keys, exact_match=False, deletions=True)

    # cleanup
    s3_notification_conf1.del_config()
    topic_conf1.del_config()
    s3_notification_conf2.del_config()
    topic_conf2.del_config()
    conn.delete_bucket(bucket_name)
    http_server.close()

def persistent_notification(endpoint_type):
    """ test pushing persistent notification """
    conn = connection()
    zonegroup = 'default'

    # create bucket
    bucket_name = gen_bucket_name()
    bucket = conn.create_bucket(bucket_name)
    topic_name = bucket_name + TOPIC_SUFFIX

    receiver = {}
    host = get_ip()
    if endpoint_type == 'http':
        # create random port for the http server
        host = get_ip_http()
        port = random.randint(10000, 20000)
        # start an http server in a separate thread
        receiver = StreamingHTTPServer(host, port, num_workers=10)
        endpoint_address = 'http://'+host+':'+str(port)
        endpoint_args = 'push-endpoint='+endpoint_address+'&persistent=true'
        # the http server does not guarantee order, so duplicates are expected
        exact_match = False
    elif endpoint_type == 'amqp':
        # start amqp receiver
        exchange = 'ex1'
        task, receiver = create_amqp_receiver_thread(exchange, topic_name)
        task.start()
        endpoint_address = 'amqp://' + host
        endpoint_args = 'push-endpoint='+endpoint_address+'&amqp-exchange='+exchange+'&amqp-ack-level=broker'+'&persistent=true'
        # amqp broker guarantee ordering
        exact_match = True
    else:
        return SkipTest('Unknown endpoint type: ' + endpoint_type)


    # create s3 topic
    topic_conf = PSTopicS3(conn, topic_name, zonegroup, endpoint_args=endpoint_args)
    topic_arn = topic_conf.set_config()
    # create s3 notification
    notification_name = bucket_name + NOTIFICATION_SUFFIX
    topic_conf_list = [{'Id': notification_name, 'TopicArn': topic_arn,
                         'Events': []
                       }]

    s3_notification_conf = PSNotificationS3(conn, bucket_name, topic_conf_list)
    response, status = s3_notification_conf.set_config()
    assert_equal(status/100, 2)

    # create objects in the bucket (async)
    number_of_objects = 100
    client_threads = []
    start_time = time.time()
    for i in range(number_of_objects):
        key = bucket.new_key(str(i))
        content = str(os.urandom(1024*1024))
        thr = threading.Thread(target = set_contents_from_string, args=(key, content,))
        thr.start()
        client_threads.append(thr)
    [thr.join() for thr in client_threads]

    time_diff = time.time() - start_time
    print('average time for creation + async http notification is: ' + str(time_diff*1000/number_of_objects) + ' milliseconds')

    keys = list(bucket.list())

    delay = 40
    print('wait for '+str(delay)+'sec for the messages...')
    time.sleep(delay)

    receiver.verify_s3_events(keys, exact_match=exact_match, deletions=False)

    # delete objects from the bucket
    client_threads = []
    start_time = time.time()
    for key in bucket.list():
        thr = threading.Thread(target = key.delete, args=())
        thr.start()
        client_threads.append(thr)
    [thr.join() for thr in client_threads]

    time_diff = time.time() - start_time
    print('average time for deletion + async http notification is: ' + str(time_diff*1000/number_of_objects) + ' milliseconds')

    print('wait for '+str(delay)+'sec for the messages...')
    time.sleep(delay)

    receiver.verify_s3_events(keys, exact_match=exact_match, deletions=True)

    # cleanup
    s3_notification_conf.del_config()
    topic_conf.del_config()
    # delete the bucket
    conn.delete_bucket(bucket_name)
    if endpoint_type == 'http':
        receiver.close()
    else:
        stop_amqp_receiver(receiver, task)


def test_ps_s3_persistent_notification_http():
    """ test pushing persistent notification http """
    persistent_notification('http')


def test_ps_s3_persistent_notification_amqp():
    """ test pushing persistent notification amqp """
    return SkipTest('This is an AMQP test.')
    persistent_notification('amqp')

'''
def test_ps_s3_persistent_notification_kafka():
    """ test pushing persistent notification http """
    persistent_notification('kafka')
'''

def random_string(length):
    import string
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for i in range(length))

def test_ps_s3_persistent_notification_large():
    """ test pushing persistent notification of large notifications """
    return SkipTest('This is an AMQP test.')

    conn = connection()
    zonegroup = 'default'

    # create bucket
    bucket_name = gen_bucket_name()
    bucket = conn.create_bucket(bucket_name)
    topic_name = bucket_name + TOPIC_SUFFIX

    receiver = {}
    host = get_ip()
    # start amqp receiver
    exchange = 'ex1'
    task, receiver = create_amqp_receiver_thread(exchange, topic_name)
    task.start()
    endpoint_address = 'amqp://' + host
    opaque_data = random_string(1024*2)
    endpoint_args = 'push-endpoint='+endpoint_address+'&OpaqueData='+opaque_data+'&amqp-exchange='+exchange+'&amqp-ack-level=broker'+'&persistent=true'
    # amqp broker guarantee ordering
    exact_match = True

    # create s3 topic
    topic_conf = PSTopicS3(conn, topic_name, zonegroup, endpoint_args=endpoint_args)
    topic_arn = topic_conf.set_config()
    # create s3 notification
    notification_name = bucket_name + NOTIFICATION_SUFFIX
    topic_conf_list = [{'Id': notification_name, 'TopicArn': topic_arn,
                         'Events': []
                       }]

    s3_notification_conf = PSNotificationS3(conn, bucket_name, topic_conf_list)
    response, status = s3_notification_conf.set_config()
    assert_equal(status/100, 2)

    # create objects in the bucket (async)
    number_of_objects = 100
    client_threads = []
    start_time = time.time()
    for i in range(number_of_objects):
        key_value = random_string(63)
        key = bucket.new_key(key_value)
        content = str(os.urandom(1024*1024))
        thr = threading.Thread(target = set_contents_from_string, args=(key, content,))
        thr.start()
        client_threads.append(thr)
    [thr.join() for thr in client_threads]

    time_diff = time.time() - start_time
    print('average time for creation + async http notification is: ' + str(time_diff*1000/number_of_objects) + ' milliseconds')

    keys = list(bucket.list())

    delay = 40
    print('wait for '+str(delay)+'sec for the messages...')
    time.sleep(delay)

    receiver.verify_s3_events(keys, exact_match=exact_match, deletions=False)

    # delete objects from the bucket
    client_threads = []
    start_time = time.time()
    for key in bucket.list():
        thr = threading.Thread(target = key.delete, args=())
        thr.start()
        client_threads.append(thr)
    [thr.join() for thr in client_threads]

    time_diff = time.time() - start_time
    print('average time for deletion + async http notification is: ' + str(time_diff*1000/number_of_objects) + ' milliseconds')

    print('wait for '+str(delay)+'sec for the messages...')
    time.sleep(delay)

    receiver.verify_s3_events(keys, exact_match=exact_match, deletions=True)

    # cleanup
    s3_notification_conf.del_config()
    topic_conf.del_config()
    # delete the bucket
    conn.delete_bucket(bucket_name)
    stop_amqp_receiver(receiver, task)



def test_ps_s3_topic_update():
    """ test updating topic associated with a notification"""
    return SkipTest('This test is yet to be modified.')

    conn = connection()
    ps_zone = None
    bucket_name = gen_bucket_name()
    topic_name = bucket_name+TOPIC_SUFFIX
    # create amqp topic
    hostname = get_ip()
    exchange = 'ex1'
    amqp_task, receiver = create_amqp_receiver_thread(exchange, topic_name)
    amqp_task.start()
    #topic_conf = PSTopic(ps_zone.conn, topic_name,endpoint='amqp://' + hostname,endpoint_args='amqp-exchange=' + exchange + '&amqp-ack-level=none')
    topic_conf = PSTopicS3(conn, topic_name, zonegroup, endpoint_args='amqp-exchange=' + exchange + '&amqp-ack-level=none')
    
    topic_arn = topic_conf.set_config()
    #result, status = topic_conf.set_config()
    #assert_equal(status/100, 2)
    parsed_result = json.loads(result)
    topic_arn = parsed_result['arn']
    # get topic
    result, _ = topic_conf.get_config()
    # verify topic content
    parsed_result = json.loads(result)
    assert_equal(parsed_result['topic']['name'], topic_name)
    assert_equal(parsed_result['topic']['dest']['push_endpoint'], topic_conf.parameters['push-endpoint'])
    # create http server
    port = random.randint(10000, 20000)
    # start an http server in a separate thread
    http_server = StreamingHTTPServer(hostname, port)
    # create bucket on the first of the rados zones
    bucket = conn.create_bucket(bucket_name)
    # create s3 notification
    notification_name = bucket_name + NOTIFICATION_SUFFIX
    topic_conf_list = [{'Id': notification_name,
                        'TopicArn': topic_arn,
                        'Events': ['s3:ObjectCreated:*']
                       }]
    s3_notification_conf = PSNotificationS3(ps_zone.conn, bucket_name, topic_conf_list)
    _, status = s3_notification_conf.set_config()
    assert_equal(status/100, 2)
    # create objects in the bucket
    number_of_objects = 10
    for i in range(number_of_objects):
        key = bucket.new_key(str(i))
        key.set_contents_from_string('bar')
    # wait for sync
    #zone_bucket_checkpoint(ps_zone.zone, master_zone.zone, bucket_name)
    keys = list(bucket.list())
    # TODO: use exact match
    receiver.verify_s3_events(keys, exact_match=False)
    # update the same topic with new endpoint
    #topic_conf = PSTopic(ps_zone.conn, topic_name,endpoint='http://'+ hostname + ':' + str(port))
    topic_conf = PSTopicS3(conn, topic_name, endpoint_args='http://'+ hostname + ':' + str(port))
    _, status = topic_conf.set_config()
    assert_equal(status/100, 2)
    # get topic
    result, _ = topic_conf.get_config()
    # verify topic content
    parsed_result = json.loads(result)
    assert_equal(parsed_result['topic']['name'], topic_name)
    assert_equal(parsed_result['topic']['dest']['push_endpoint'], topic_conf.parameters['push-endpoint'])
    # delete current objects and create new objects in the bucket
    for key in bucket.list():
        key.delete()
    for i in range(number_of_objects):
        key = bucket.new_key(str(i+100))
        key.set_contents_from_string('bar')
    # wait for sync
    #zone_meta_checkpoint(ps_zone.zone)
    #zone_bucket_checkpoint(ps_zone.zone, master_zone.zone, bucket_name)
    keys = list(bucket.list())
    # verify that notifications are still sent to amqp
    # TODO: use exact match
    receiver.verify_s3_events(keys, exact_match=False)
    # update notification to update the endpoint from the topic
    topic_conf_list = [{'Id': notification_name,
                        'TopicArn': topic_arn,
                        'Events': ['s3:ObjectCreated:*']
                       }]
    s3_notification_conf = PSNotificationS3(ps_zone.conn, bucket_name, topic_conf_list)
    _, status = s3_notification_conf.set_config()
    assert_equal(status/100, 2)
    # delete current objects and create new objects in the bucket
    for key in bucket.list():
        key.delete()
    for i in range(number_of_objects):
        key = bucket.new_key(str(i+200))
        key.set_contents_from_string('bar')
    # wait for sync
    #zone_meta_checkpoint(ps_zone.zone)
    #zone_bucket_checkpoint(ps_zone.zone, master_zone.zone, bucket_name)
    keys = list(bucket.list())
    # check that updates switched to http
    # TODO: use exact match
    http_server.verify_s3_events(keys, exact_match=False)
    # cleanup
    # delete objects from the bucket
    stop_amqp_receiver(receiver, amqp_task)
    for key in bucket.list():
        key.delete()
    s3_notification_conf.del_config()
    topic_conf.del_config()
    conn.delete_bucket(bucket_name)
    http_server.close()


def test_ps_s3_notification_update():
    """ test updating the topic of a notification"""
    return SkipTest('This test is yet to be modified.')

    hostname = get_ip()
    conn = connection()
    ps_zone = None
    bucket_name = gen_bucket_name()
    topic_name1 = bucket_name+'amqp'+TOPIC_SUFFIX
    topic_name2 = bucket_name+'http'+TOPIC_SUFFIX
    zonegroup = 'default'
    # create topics
    # start amqp receiver in a separate thread
    exchange = 'ex1'
    amqp_task, receiver = create_amqp_receiver_thread(exchange, topic_name1)
    amqp_task.start()
    # create random port for the http server
    http_port = random.randint(10000, 20000)
    # start an http server in a separate thread
    http_server = StreamingHTTPServer(hostname, http_port)
    #topic_conf1 = PSTopic(ps_zone.conn, topic_name1,endpoint='amqp://' + hostname,endpoint_args='amqp-exchange=' + exchange + '&amqp-ack-level=none')
    topic_conf1 = PSTopicS3(conn, topic_name1, zonegroup, endpoint_args='amqp-exchange=' + exchange + '&amqp-ack-level=none')
    result, status = topic_conf1.set_config()
    parsed_result = json.loads(result)
    topic_arn1 = parsed_result['arn']
    assert_equal(status/100, 2)
    #topic_conf2 = PSTopic(ps_zone.conn, topic_name2,endpoint='http://'+hostname+':'+str(http_port))
    topic_conf2 = PSTopicS3(conn, topic_name2, endpoint_args='http://'+hostname+':'+str(http_port))
    result, status = topic_conf2.set_config()
    parsed_result = json.loads(result)
    topic_arn2 = parsed_result['arn']
    assert_equal(status/100, 2)
    # create bucket on the first of the rados zones
    bucket = conn.create_bucket(bucket_name)
    # wait for sync
    #zone_meta_checkpoint(ps_zone.zone)
    # create s3 notification with topic1
    notification_name = bucket_name + NOTIFICATION_SUFFIX
    topic_conf_list = [{'Id': notification_name,
                        'TopicArn': topic_arn1,
                        'Events': ['s3:ObjectCreated:*']
                       }]
    s3_notification_conf = PSNotificationS3(ps_zone.conn, bucket_name, topic_conf_list)
    _, status = s3_notification_conf.set_config()
    assert_equal(status/100, 2)
    # create objects in the bucket
    number_of_objects = 10
    for i in range(number_of_objects):
        key = bucket.new_key(str(i))
        key.set_contents_from_string('bar')
    # wait for sync
    #zone_bucket_checkpoint(ps_zone.zone, master_zone.zone, bucket_name)
    keys = list(bucket.list())
    # TODO: use exact match
    receiver.verify_s3_events(keys, exact_match=False);
    # update notification to use topic2
    topic_conf_list = [{'Id': notification_name,
                        'TopicArn': topic_arn2,
                        'Events': ['s3:ObjectCreated:*']
                       }]
    s3_notification_conf = PSNotificationS3(ps_zone.conn, bucket_name, topic_conf_list)
    _, status = s3_notification_conf.set_config()
    assert_equal(status/100, 2)
    # delete current objects and create new objects in the bucket
    for key in bucket.list():
        key.delete()
    for i in range(number_of_objects):
        key = bucket.new_key(str(i+100))
        key.set_contents_from_string('bar')
    # wait for sync
    #zone_meta_checkpoint(ps_zone.zone)
    #zone_bucket_checkpoint(ps_zone.zone, master_zone.zone, bucket_name)
    keys = list(bucket.list())
    # check that updates switched to http
    # TODO: use exact match
    http_server.verify_s3_events(keys, exact_match=False)
    # cleanup
    # delete objects from the bucket
    stop_amqp_receiver(receiver, amqp_task)
    for key in bucket.list():
        key.delete()
    s3_notification_conf.del_config()
    topic_conf1.del_config()
    topic_conf2.del_config()
    conn.delete_bucket(bucket_name)
    http_server.close()


def test_ps_s3_multiple_topics_notification():
    """ test notification creation with multiple topics"""
    return SkipTest('This test is yet to be modified.')

    hostname = get_ip()
    zonegroup = 'default'
    conn = connection()
    ps_zone = None
    bucket_name = gen_bucket_name()
    topic_name1 = bucket_name+'amqp'+TOPIC_SUFFIX
    topic_name2 = bucket_name+'http'+TOPIC_SUFFIX
    # create topics
    # start amqp receiver in a separate thread
    exchange = 'ex1'
    amqp_task, receiver = create_amqp_receiver_thread(exchange, topic_name1)
    amqp_task.start()
    # create random port for the http server
    http_port = random.randint(10000, 20000)
    # start an http server in a separate thread
    http_server = StreamingHTTPServer(hostname, http_port)
    #topic_conf1 = PSTopic(ps_zone.conn, topic_name1,endpoint='amqp://' + hostname,endpoint_args='amqp-exchange=' + exchange + '&amqp-ack-level=none')
    topic_conf1 = PSTopicS3(conn, topic_name1, zonegroup, endpoint_args='amqp-exchange=' + exchange + '&amqp-ack-level=none')
    result, status = topic_conf1.set_config()
    parsed_result = json.loads(result)
    topic_arn1 = parsed_result['arn']
    assert_equal(status/100, 2)
    #topic_conf2 = PSTopic(ps_zone.conn, topic_name2,endpoint='http://'+hostname+':'+str(http_port))
    topic_conf2 = PSTopicS3(conn, topic_name2, zonegroup, endpoint_args='http://'+hostname+':'+str(http_port))
    result, status = topic_conf2.set_config()
    parsed_result = json.loads(result)
    topic_arn2 = parsed_result['arn']
    assert_equal(status/100, 2)
    # create bucket on the first of the rados zones
    bucket = conn.create_bucket(bucket_name)
    # wait for sync
    #zone_meta_checkpoint(ps_zone.zone)
    # create s3 notification
    notification_name1 = bucket_name + NOTIFICATION_SUFFIX + '_1'
    notification_name2 = bucket_name + NOTIFICATION_SUFFIX + '_2'
    topic_conf_list = [
        {
            'Id': notification_name1,
            'TopicArn': topic_arn1,
            'Events': ['s3:ObjectCreated:*']
        },
        {
            'Id': notification_name2,
            'TopicArn': topic_arn2,
            'Events': ['s3:ObjectCreated:*']
        }]
    s3_notification_conf = PSNotificationS3(ps_zone.conn, bucket_name, topic_conf_list)
    _, status = s3_notification_conf.set_config()
    assert_equal(status/100, 2)
    result, _ = s3_notification_conf.get_config()
    assert_equal(len(result['TopicConfigurations']), 2)
    assert_equal(result['TopicConfigurations'][0]['Id'], notification_name1)
    assert_equal(result['TopicConfigurations'][1]['Id'], notification_name2)
    # get auto-generated subscriptions
    sub_conf1 = PSSubscription(ps_zone.conn, notification_name1,
                               topic_name1)
    _, status = sub_conf1.get_config()
    assert_equal(status/100, 2)
    sub_conf2 = PSSubscription(ps_zone.conn, notification_name2,
                               topic_name2)
    _, status = sub_conf2.get_config()
    assert_equal(status/100, 2)
    # create objects in the bucket
    number_of_objects = 10
    for i in range(number_of_objects):
        key = bucket.new_key(str(i))
        key.set_contents_from_string('bar')
    # wait for sync
    #zone_bucket_checkpoint(ps_zone.zone, master_zone.zone, bucket_name)
    # get the events from both of the subscription
    result, _ = sub_conf1.get_events()
    records = json.loads(result)
    for record in records['Records']:
        log.debug(record)
    keys = list(bucket.list())
    # TODO: use exact match
    verify_s3_records_by_elements(records, keys, exact_match=False)
    receiver.verify_s3_events(keys, exact_match=False)  
    result, _ = sub_conf2.get_events()
    parsed_result = json.loads(result)
    for record in parsed_result['Records']:
        log.debug(record)
    keys = list(bucket.list())
    # TODO: use exact match
    verify_s3_records_by_elements(records, keys, exact_match=False)
    http_server.verify_s3_events(keys, exact_match=False)
    # cleanup
    stop_amqp_receiver(receiver, amqp_task)
    s3_notification_conf.del_config()
    topic_conf1.del_config()
    topic_conf2.del_config()
    # delete objects from the bucket
    for key in bucket.list():
        key.delete()
    conn.delete_bucket(bucket_name)
    http_server.close()


def kafka_security(security_type):
    """ test pushing kafka s3 notification on master """
    return SkipTest('This test is yet to be modified.')

    conn = connection()
    if security_type == 'SSL_SASL' and master_zone.secure_conn is None:
        return SkipTest("secure connection is needed to test SASL_SSL security")
    zonegroup = 'default'
    # create bucket
    bucket_name = gen_bucket_name()
    bucket = conn.create_bucket(bucket_name)
    # name is constant for manual testing
    topic_name = bucket_name+'_topic'
    # create consumer on the topic
    task, receiver = create_kafka_receiver_thread(topic_name)
    task.start()
    # create s3 topic
    if security_type == 'SSL_SASL':
        endpoint_address = 'kafka://alice:alice-secret@' + kafka_server + ':9094'
    else:
        # ssl only
        endpoint_address = 'kafka://' + kafka_server + ':9093'
    KAFKA_DIR = os.environ['KAFKA_DIR']
    # without acks from broker, with root CA
    endpoint_args = 'push-endpoint='+endpoint_address+'&kafka-ack-level=none&use-ssl=true&ca-location='+KAFKA_DIR+'rootCA.crt'
    if security_type == 'SSL_SASL':
        topic_conf = PSTopicS3(master_zone.secure_conn, topic_name, zonegroup, endpoint_args=endpoint_args)
    else:
        topic_conf = PSTopicS3(conn, topic_name, zonegroup, endpoint_args=endpoint_args)
    topic_arn = topic_conf.set_config()
    # create s3 notification
    notification_name = bucket_name + NOTIFICATION_SUFFIX
    topic_conf_list = [{'Id': notification_name, 'TopicArn': topic_arn,
                         'Events': []
                       }]
    s3_notification_conf = PSNotificationS3(conn, bucket_name, topic_conf_list)
    s3_notification_conf.set_config()
    # create objects in the bucket (async)
    number_of_objects = 10
    client_threads = []
    start_time = time.time()
    for i in range(number_of_objects):
        key = bucket.new_key(str(i))
        content = str(os.urandom(1024*1024))
        thr = threading.Thread(target = set_contents_from_string, args=(key, content,))
        thr.start()
        client_threads.append(thr)
    [thr.join() for thr in client_threads]
    time_diff = time.time() - start_time
    print('average time for creation + kafka notification is: ' + str(time_diff*1000/number_of_objects) + ' milliseconds')
    try:
        print('wait for 5sec for the messages...')
        time.sleep(5)
        keys = list(bucket.list())
        receiver.verify_s3_events(keys, exact_match=True)
        # delete objects from the bucket
        client_threads = []
        start_time = time.time()
        for key in bucket.list():
            thr = threading.Thread(target = key.delete, args=())
            thr.start()
            client_threads.append(thr)
        [thr.join() for thr in client_threads]
        time_diff = time.time() - start_time
        print('average time for deletion + kafka notification is: ' + str(time_diff*1000/number_of_objects) + ' milliseconds')
        print('wait for 5sec for the messages...')
        time.sleep(5)
        receiver.verify_s3_events(keys, exact_match=True, deletions=True)
    except Exception as err:
        assert False, str(err)
    finally:
        # cleanup
        s3_notification_conf.del_config()
        topic_conf.del_config()
        # delete the bucket
        for key in bucket.list():
            key.delete()
        conn.delete_bucket(bucket_name)
        stop_kafka_receiver(receiver, task)


def test_ps_s3_notification_push_kafka_security_ssl():
    return SkipTest('This test is yet to be modified.')
    kafka_security('SSL')

def test_ps_s3_notification_push_kafka_security_ssl_sasl():
    return SkipTest('This test is yet to be modified.')
    kafka_security('SSL_SASL')

