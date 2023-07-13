import os
from flask import Flask, request, jsonify
from flask_mysqldb import MySQL
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import BadRequest
import jwt
import redis
from functools import wraps
# import secrets
from datetime import datetime, timedelta
from flask_swagger_ui import get_swaggerui_blueprint

# Load environment variables from .env file
load_dotenv('.env')

app = Flask(__name__)


app.config['ENV'] = os.getenv('ENV')


# MySQL configuration
app.config['MYSQL_HOST'] = os.getenv('DB_IP')
app.config['MYSQL_PORT'] = int(os.getenv('DB_PORT'))
app.config['MYSQL_USER'] = os.getenv('DB_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('DB_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('DATABASE')

# JWT secret key
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# Redis configuration
redis_host = os.getenv('REDIS_HOST')
redis_port = os.getenv('REDIS_PORT')
redis_password = os.getenv('REDIS_PASSWORD')

# Token settings
token_expire = int(os.getenv('TOKEN_EXPIRATION_TIME'))

# Login services URL
login_services_validate_api = os.getenv('LOGIN_SERVICE_URL')

# Define Swagger UI blueprint
if app.config['ENV'] == 'development':
    # Swagger configuration
    SWAGGER_URL = '/api/docs'  # URL for accessing the Swagger UI
    API_URL = '/api/swagger.json'  # URL for accessing the Swagger JSON

    # Create a Swagger UI blueprint
    swagger_ui_blueprint = get_swaggerui_blueprint(
        SWAGGER_URL,
        API_URL,
        config={
            'app_name': "Auth API"  # Customize the Swagger UI app name
        }
    )

    # Register the Swagger UI blueprint
    app.register_blueprint(swagger_ui_blueprint, url_prefix=SWAGGER_URL)

# Initialize MySQL
mysql = MySQL(app)

# Initialize Redis
redis_client = redis.Redis(host=redis_host, port=redis_port, password=redis_password)


def create_tables():
    with app.app_context():
        try:
            print("Creating tables...")

            conn = mysql.connect
            cur = conn.cursor()

            # Create 'roles' table if it doesn't exist
            cur.execute("""
                CREATE TABLE IF NOT EXISTS roles (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    role_name VARCHAR(255) NOT NULL
                )
            """)

            # Create 'users' table if it doesn't exist
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) NOT NULL,
                    hashed_password VARCHAR(255) NOT NULL,
                    role_id INT,
                    FOREIGN KEY (role_id) REFERENCES roles (id)
                )
            """)

            # Create 'admin' role if it doesn't exist
            cur.execute("SELECT id FROM roles WHERE role_name = 'admin'")
            admin_role = cur.fetchone()
            if not admin_role:
                cur.execute("INSERT INTO roles (role_name) VALUES ('admin')")

            # Create 'guest' role if it doesn't exist
            cur.execute("SELECT id FROM roles WHERE role_name = 'guest'")
            guest_role = cur.fetchone()
            if not guest_role:
                cur.execute("INSERT INTO roles (role_name) VALUES ('guest')")

            # Check if admin user exists
            cur.execute("SELECT id FROM roles WHERE role_name = 'admin'")
            admin_role = cur.fetchone()

            cur.execute("SELECT id FROM users WHERE role_id = %s", (admin_role,))
            admin_user = cur.fetchone()

            if not admin_user:
                # Read admin password from environment variables
                admin_password = os.getenv('ADMIN_PASSWORD')

                # Create admin user
                hashed_password = generate_password_hash(admin_password)
                cur.execute("INSERT INTO users (username, hashed_password, role_id) VALUES (%s, %s, %s)",
                            ("admin", hashed_password, admin_role[0]))
                conn.commit()
                print("Admin user created successfully.")


            conn.commit()
            cur.close()
            print("Tables created successfully.")
        except Exception as e:
            print("An error occurred while creating the tables:", str(e))

create_tables()

# JWT Token Required Decorator
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
                
            try:
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                current_user = data['username']
                current_user_role = data['role']
            except jwt.ExpiredSignatureError:
                return jsonify({'message': 'Token has expired'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'message': 'Invalid Token'}), 401

            if not redis_client.get(current_user) or redis_client.get(current_user).decode() != token:
                return jsonify({'message': 'Invalid Token'}), 401

            if roles is not None and current_user_role not in roles:
                return jsonify({'message': 'Unauthorized'}), 401

            return f(current_user, *args, **kwargs)

        return decorated

    return decorator

def is_admin(username):
    # Fetch the role ID for the 'admin' role from the database
    cur = mysql.connection.cursor()
    cur.execute("SELECT id FROM roles WHERE role_name = 'admin'")
    admin_role = cur.fetchone()

    if not admin_role:
        return False

    admin_role_id = admin_role[0]

    # Fetch the user's role ID from the database or any other data source
    cur.execute("SELECT role_id FROM users WHERE username = %s", (username,))
    user = cur.fetchone()

    if not user:
        return False
    user_role_id = user[0]

    return user_role_id == admin_role_id

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

@app.route('/v1/user/register', methods=['POST'])
@token_required(roles=['admin'])
def register(current_user):
    """
    User Registration
    ---
    tags:
      - User
    parameters:
      - name: body
        in: body
        required: true
        description: User registration details
        schema:
          type: object
          properties:
            username:
              type: string
              example: john
            password:
              type: string
              example: secret
    responses:
      "200":
        description: User registered successfully
      "400":
        description: Bad request
    """
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        raise BadRequest("Username and password are required")

    hashed_password = generate_password_hash(password)

    cur = mysql.connection.cursor()
    
    # Check 'guest' role ID
    cur.execute("SELECT id FROM roles WHERE role_name = 'guest'")
    guest_role_id = cur.fetchone()
    
    if not guest_role_id:
        raise BadRequest("Guest role ID not found")
    
    cur.execute("INSERT INTO users (username, hashed_password, role_id) VALUES (%s, %s, %s)",
                (username, hashed_password, guest_role_id[0]))
    
    mysql.connection.commit()
    cur.close()

    return jsonify({'message': 'User registered successfully'})


@app.route('/v1/user/login', methods=['POST'])
def login():
    """
    User Login
    ---
    tags:
      - User
    parameters:
      - name: body
        in: body
        required: true
        description: User login details
        schema:
          type: object
          properties:
            username:
              type: string
              example: john
            password:
              type: string
              example: secret
    responses:
      "200":
        description: User logged in successfully
      "400":
        description: Bad request
      "401":
        description: Unauthorized
    """
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    cur = mysql.connection.cursor()
    cur.execute("SELECT users.username, users.hashed_password, roles.role_name "
                "FROM users "
                "LEFT JOIN roles ON users.role_id = roles.id "
                "WHERE users.username = %s", (username,))
    
    # cur.execute("SELECT username, hashed_password FROM users WHERE username = %s", (username,))
    user = cur.fetchone()

    if not user or not check_password_hash(user[1], password):
        return jsonify({'message': 'Invalid username or password'}), 401


    payload = {
        'username': username,
        'role': user[2],
        'nbf': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(seconds=token_expire)
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

    # Delete the previous token from Redis if exists
    redis_client.delete(username)
    # Update token in Redis
    redis_client.set(username, token)
    redis_client.expire(username, token_expire)

    return jsonify({'token': token})


@app.route('/v1/user/info/<username>', methods=['GET'])
@token_required(roles=['admin'])
def get_user_info(current_user, username):
    """
    Get User Information
    ---
    tags:
      - User
    parameters:
      - name: username
        in: path
        required: true
        description: Username of the user
        type: string
    responses:
      "200":
        description: User information retrieved successfully
      "404":
        description: User not found
    """
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, username FROM users WHERE username = %s", (username,))
    user = cur.fetchone()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    user_info = {'userId': user[0], 'username': user[1], 'token': redis_client.get(username).decode()}

    return jsonify(user_info), 200

@app.route('/v1/user/getAll', methods=['GET'])
@token_required(roles=['admin','guest'])
def list_users(current_user):
    """
    List Users
    ---
    tags:
      - User
    responses:
      "200":
        description: List of users retrieved successfully
    """
    cur = mysql.connection.cursor()
    cur.execute("SELECT users.id, users.username, roles.role_name "
                "FROM users "
                "LEFT JOIN roles ON users.role_id = roles.id")
    users = cur.fetchall()

    user_list = []
    for user in users:
        user_info = {'userId': user[0], 'username': user[1], 'role': user[2]}
        user_list.append(user_info)

    return jsonify(user_list), 200


@app.route('/v1/roles/getAll', methods=['GET'])
@token_required(roles=['admin'])
def get_roles(current_user):
    """
    Get All Roles
    ---
    tags:
      - Role
    responses:
      "200":
        description: List of roles retrieved successfully
    """
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, role_name FROM roles")
    roles = cur.fetchall()
    cur.close()

    role_list = [{'roleId': role[0], 'roleName': role[1]} for role in roles]

    return jsonify(role_list), 200


@app.route('/v1/roles/create', methods=['POST'])
@token_required(roles=['admin'])
def create_role(current_user):
    """
    Create Role
    ---
    tags:
      - Role
    parameters:
      - in: body
        name: role
        description: Role object
        required: true
        schema:
          type: object
          properties:
            roleName:
              type: string
              description: Name of the role
    responses:
      "201":
        description: Role created successfully
    """
    role_name = request.json.get('roleName')

    if not role_name:
        raise BadRequest("Role name is required")

    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO roles (role_name) VALUES (%s)", (role_name,))
    mysql.connection.commit()
    cur.close()

    return jsonify({'message': 'Role created successfully'}), 201

@app.route('/v1/user/password/change', methods=['POST'])
@token_required(roles=['admin','guest'])
def change_user_password(current_user):
    """
    Change User Password
    ---
    tags:
      - User
    parameters:
      - in: body
        name: password
        description: Password object
        required: true
        schema:
          type: object
          properties:
            old_password:
              type: string
              description: Current password of the user
            new_password:
              type: string
              description: New password to be set for the user
    responses:
      "200":
        description: Password changed successfully
      "401":
        description: Invalid old password
    """
    username = current_user
    old_password = request.json.get('old_password')
    new_password = request.json.get('new_password')

    if not old_password or not new_password:
        raise BadRequest("Old password and new password are required")

    cur = mysql.connection.cursor()
    cur.execute("SELECT hashed_password FROM users WHERE username = %s", (username,))
    user = cur.fetchone()

    if not user or not check_password_hash(user[0], old_password):
        return jsonify({'message': 'Invalid old password'}), 401

    new_hashed_password = generate_password_hash(new_password)
    cur.execute("UPDATE users SET hashed_password = %s WHERE username = %s", (new_hashed_password, username))
    mysql.connection.commit()
    cur.close()

    return jsonify({'message': 'Password changed successfully'})

@app.route('/v1/admin/password/change/<username>', methods=['PUT'])
@token_required(roles=['admin'])
def admin_change_password(current_user, username):
    """
    Admin Change User Password
    ---
    tags:
      - Admin
    parameters:
      - in: path
        name: username
        description: Username of the user whose password needs to be changed
        required: true
        type: string
      - in: body
        name: password
        description: Password object
        required: true
        schema:
          type: object
          properties:
            new_password:
              type: string
              description: New password to be set for the user
    responses:
      "200":
        description: Password updated successfully
      "400":
        description: Username is required or New password is required
      "404":
        description: User not found
    """
    if not username:
        return jsonify({'message': 'Username is required'}), 400

    new_password = request.json.get('new_password')

    if not new_password:
        return jsonify({'message': 'New password is required'}), 400

    cur = mysql.connection.cursor()
    cur.execute("SELECT id FROM users WHERE username = %s", (username,))
    user = cur.fetchone()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    hashed_password = generate_password_hash(new_password)

    cur.execute("UPDATE users SET hashed_password = %s WHERE id = %s", (hashed_password, user[0]))
    mysql.connection.commit()

    return jsonify({'message': 'Password updated successfully'}), 200

@app.route('/v1/admin/role/change/<username>', methods=['PUT'])
@token_required(roles=['admin'])
def change_user_role(current_user, username):
    """
    Admin Change User Role
    ---
    tags:
      - Admin
    parameters:
      - in: path
        name: username
        description: Username of the user whose role needs to be changed
        required: true
        type: string
      - in: body
        name: role
        description: Role object
        required: true
        schema:
          type: object
          properties:
            role_name:
              type: string
              description: New role name to be assigned to the user
    responses:
      "200":
        description: User role updated successfully
      "400":
        description: Role name is required or Invalid role name
    """
    role_name = request.json.get('role_name')

    if not role_name:
        return jsonify({'message': 'Role name is required'}), 400

    # Get the role ID based on the role name
    cur = mysql.connection.cursor()
    cur.execute("SELECT id FROM roles WHERE role_name = %s", (role_name,))
    role = cur.fetchone()

    if not role:
        return jsonify({'message': 'Invalid role name'}), 400

    role_id = role[0]

    # Update the user's role ID
    cur.execute("UPDATE users SET role_id = %s WHERE username = %s", (role_id, username))
    mysql.connection.commit()
    cur.close()

    return jsonify({'message': 'User role updated successfully'}), 200

@app.route('/v1/user/logout', methods=['POST'])
def logout():
    """
    User Logout
    ---
    tags:
      - User
    parameters:
      - in: header
        name: Authorization
        description: Bearer token
        required: false
        type: string
      - in: body
        name: credentials
        description: Username and password for manual logout
        required: false
        schema:
          type: object
          properties:
            username:
              type: string
              description: User's username
            password:
              type: string
              description: User's password
    responses:
      "200":
        description: Logged out successfully
      "400":
        description: Username and password are required
      "401":
        description: Invalid Token or Invalid username or password
    """
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ', 1)[1]

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = data['username']

            if not redis_client.get(current_user) or redis_client.get(current_user).decode() != token:
                return jsonify({'message': 'Invalid Token'}), 401   
            print(redis_client.get(current_user))

            # Delete token from Redis
            redis_client.delete(current_user)
            return jsonify({'message': 'Logged out successfully (token)'}), 200
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid Token'}), 401
    else:
        username = request.json.get('username')
        password = request.json.get('password')
        if not username or not password:
            return jsonify({'message': 'Username and password are required'}), 400

        cur = mysql.connection.cursor()
        cur.execute("SELECT username, hashed_password FROM users WHERE username = %s", (username,))
        user = cur.fetchone()

        if not user or not check_password_hash(user[1], password):
            return jsonify({'message': 'Invalid username or password'}), 401

        # Delete token from Redis
        redis_client.delete(username)
        return jsonify({'message': 'Logged out successfully (username/password)'}), 200
    
@app.route('/v1/user/delete/<username>', methods=['DELETE'])
@token_required(roles=['admin'])
def delete_user(current_user, username):
    """
    Delete User
    ---
    tags:
      - User
    parameters:
      - in: path
        name: username
        description: Username of the user to be deleted
        required: true
        type: string
    responses:
      "200":
        description: User deleted successfully
      "401":
        description: Unauthorized
      "404":
        description: User not found
    """
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM users WHERE username = %s", (username,))
    mysql.connection.commit()
    cur.close()

    # Clear user's token from Redis
    redis_client.delete(username)

    return jsonify({'message': 'User deleted successfully'})


@app.route('/v1/token/validate', methods=['POST'])
def validate_token():
    """
    Validate Token
    ---
    tags:
      - Token
    parameters:
      - in: body
        name: body
        description: Token object
        required: true
        schema:
          type: object
          properties:
            token:
              type: string
    responses:
      "200":
        description: Token is valid
      "401":
        description: Invalid Token or Token has expired
    """
    token = request.json.get('token')

    if not token:
        return jsonify({'message': 'Token is missing'}), 401
    
    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        username = decoded_token.get('username')
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid Token'}), 401

    if not redis_client.get(username) or redis_client.get(username).decode() != token:
        return jsonify({'message': 'Invalid Token'}), 401

    return jsonify({'message': 'Token is valid'}), 200

@app.route('/v1/token/<username>/revoke', methods=['DELETE'])
@token_required(roles=['admin'])
def revoke_user_tokens(current_user, username):
    """
    Revoke User Tokens
    ---
    tags:
      - Token
    parameters:
      - in: path
        name: username
        description: Username of the user
        required: true
        type: string
    responses:
      "200":
        description: User tokens revoked
      "404":
        description: User not found
    """
    # Check if the user exists
    cur = mysql.connection.cursor()
    cur.execute("SELECT id FROM users WHERE username = %s", (username,))
    user = cur.fetchone()
    cur.close()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Delete the user's token from Redis
    redis_client.delete(username)

    return jsonify({'message': 'User tokens revoked'}), 200

if __name__ == '__main__':
    app.run(debug=True)
