from flask import Flask, request, jsonify
from skpy import Skype, SkypeGroupChat
import pika
import os
from dotenv import load_dotenv
import json
from flask_swagger_ui import get_swaggerui_blueprint
from functools import wraps
import jwt
import requests

load_dotenv()

app = Flask(__name__)

app.config['ENV'] = os.getenv('ENV')
# JWT secret key
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# Define Swagger UI blueprint
if app.config['ENV'] == 'development':
    # Swagger configuration
    SWAGGER_URL = '/api/docs'
    API_URL = '/api/swagger.json'
    swaggerui_blueprint = get_swaggerui_blueprint(
        SWAGGER_URL,
        API_URL,
        config={
            'app_name': "Skype API"
        }
    )

    app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

sk = None

def token_required(roles=None):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = None
            current_user = None

            if 'Authorization' in request.headers:
                token = request.headers['Authorization'].split()[1]

            if not token:
                return jsonify({'message': 'Token is missing'}), 401

            # Make a request to the auth service to validate the token
            auth_service_url = os.getenv('AUTH_SERVICE_URL')
            headers = {'Content-Type': 'application/json'}
            data = {'token': token}
            response = requests.post(auth_service_url, headers=headers, json=data)

            print(response.status_code)

            if response.status_code == 200:
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                current_user = data['username']
                current_user_role = data['role']
            else:
                return jsonify({'message': 'Invalid Token'}), 401

            if roles is not None and current_user_role not in roles:
                return jsonify({'message': 'Unauthorized'}), 401

            return f(current_user, *args, **kwargs)

        return decorated

    return decorator

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

def get_group_chat_info():
    sk = get_skype_session()
    # Fetch recent conversations to populate the cache
    while sk.chats.recent():
        pass

    group_chat_info = [
        {
            'group_chat_id': chat.id,
            'topic': chat.topic
        }
        for chat in sk.chats
        if isinstance(chat, SkypeGroupChat)
    ]
    return group_chat_info

@app.route('/api/swagger.json', methods=['GET'])
def swagger_json():
    """
    Get Swagger JSON
    ---
    responses:
      200:
        description: Swagger JSON specification
    """
    return app.send_static_file('swagger.json')


@app.route('/api/v1/skype/groupId', methods=['GET'])
@token_required(roles=['admin'])
def skype_info(current_user):
    """
    Get Skype Group IDs and Topics
    ---
    responses:
      200:
        description: List of Skype group chat IDs and topics
    """
    group_chat_info = get_group_chat_info()
    return jsonify(group_chat_info)

@app.route('/api/v1/skype/send_group_message', methods=['POST'])
def send_message():
    """
    Send Message to Skype Groups
    ---
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            groups:
              type: array
              items:
                type: object
                properties:
                  id:
                    type: string
                    description: Skype Group ID
                  msg:
                    type: string
                    description: Message to send
    responses:
      200:
        description: Messages sent successfully
      400:
        description: Invalid message format
    """
    data = request.get_json()
    if 'groups' in data and isinstance(data['groups'], list):
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

        for group in data['groups']:
            if 'id' in group and 'msg' in group:
                message = {
                    'body': {
                        'id': group['id'],
                        'msg': group['msg']
                    }
                }
                channel.basic_publish(
                    exchange=rabbitmq_exchange,
                    routing_key=rabbitmq_topic,
                    body=json.dumps(message),
                    properties=pika.BasicProperties(delivery_mode=2)  # Set delivery mode to 2 for persistent messages
                )
            else:
                connection.close()
                return jsonify({'error': 'Invalid message format. Each group object should contain "id" and "msg"'})

        connection.close()

        return jsonify({'message': 'Messages sent successfully'})
    else:
        return jsonify({'error': 'Invalid message format. Please provide a list of groups'})

if __name__ == '__main__':
    app.run()
