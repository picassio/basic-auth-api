import logging
import json
import os
import pika
from dotenv import load_dotenv
from skpy import Skype

load_dotenv()

sk = None

def get_skype_session():
    global sk
    if sk is None:
        skype_username = os.getenv("SKYPE_USERNAME")
        skype_password = os.getenv("SKYPE_PASSWORD")
        sk = Skype(connect=False)
        sk.conn.setTokenFile('./token/.skype_token')  # Token will be stored in this file
        sk.conn.setUserPwd(skype_username, skype_password)
        sk.conn.getSkypeToken()
    return sk

def send_skype_message(chat_id, msg):
    sk = get_skype_session()
    ch = sk.chats[chat_id]
    ch.sendMsg(msg)
    logging.info("Sent message: %s", msg)

def consume_message(ch, method, properties, body):
    message = body.decode()
    logging.info("Received message: %s", message)

    try:
        data = json.loads(message)
        if 'body' in data and 'id' in data['body'] and 'msg' in data['body']:
            chat_id = data['body']['id']
            msg = data['body']['msg']
            send_skype_message(chat_id, msg)
            ch.basic_ack(delivery_tag=method.delivery_tag)  # Acknowledge the message
        else:
            logging.error("Error: Invalid message format. 'id' and 'msg' keys are required.")
            ch.basic_reject(delivery_tag=method.delivery_tag, requeue=False)  # Reject and discard the message
    except Exception as e:
        logging.error("Error: %s", str(e))
        ch.basic_reject(delivery_tag=method.delivery_tag, requeue=False)  # Reject and discard the message

def start_consumer():
    rabbitmq_host = os.getenv("RABBITMQ_HOST")
    rabbitmq_port = int(os.getenv("RABBITMQ_PORT"))
    rabbitmq_username = os.getenv("RABBITMQ_USERNAME")
    rabbitmq_password = os.getenv("RABBITMQ_PASSWORD")
    rabbitmq_exchange = os.getenv("RABBITMQ_EXCHANGE")
    rabbitmq_topic = os.getenv("RABBITMQ_TOPIC")
    rabbitmq_queue = os.getenv("RABBITMQ_QUEUE")

    connection = pika.BlockingConnection(pika.ConnectionParameters(host=rabbitmq_host,
                                                                   port=rabbitmq_port,
                                                                   credentials=pika.PlainCredentials(rabbitmq_username, rabbitmq_password)))
    channel = connection.channel()
    channel.exchange_declare(exchange=rabbitmq_exchange, exchange_type='direct', durable=True)
    channel.queue_declare(queue=rabbitmq_queue, durable=True)
    channel.queue_bind(exchange=rabbitmq_exchange, queue=rabbitmq_queue, routing_key=rabbitmq_topic)
    channel.basic_qos(prefetch_count=1)  # Set prefetch_count to 1 for FIFO processing
    channel.basic_consume(queue=rabbitmq_queue, on_message_callback=consume_message)

    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

    logging.info('Consumer started.')
    print('Waiting for messages...')

    channel.start_consuming()

if __name__ == '__main__':
    start_consumer()
