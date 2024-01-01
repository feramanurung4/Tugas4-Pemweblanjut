from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
bcrypt = Bcrypt()

# Dummy database to store user information
users = {
    'user1': {
        'username': 'user1',
        'password': bcrypt.generate_password_hash('password1').decode('utf-8')
    }
}

# Function to generate JWT token
def generate_token(username):
    expiration_date = datetime.datetime.utcnow() + datetime.timedelta(days=1)
    token = jwt.encode({'username': username, 'exp': expiration_date}, app.config['SECRET_KEY'], algorithm='HS256')
    return token

# Function to check if user is logged in
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return jsonify({'message': 'Token is invalid'}), 401

        return f(*args, **kwargs)

    return decorated

# Registration endpoint
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    username = data.get('username')
    password = data.get('password')

    if username in users:
        return jsonify({'message': 'Username already exists'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    users[username] = {'username': username, 'password': hashed_password}

    return jsonify({'message': 'Registration successful'}), 201

# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    username = data.get('username')
    password = data.get('password')

    if username not in users or not bcrypt.check_password_hash(users[username]['password'], password):
        return jsonify({'message': 'Invalid credentials'}), 401

    token = generate_token(username)

    return jsonify({'token': token.decode('utf-8')})

# Protected endpoint (requires JWT token)
@app.route('/protected', methods=['GET'])
@token_required
def protected():
    return jsonify({'message': 'This is a protected endpoint'})

if __name__ == '__main__':
    app.run(debug=True)
