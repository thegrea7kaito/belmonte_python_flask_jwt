from flask import Flask, request, jsonify
import jwt
import datetime
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Secret key for JWT encoding/decoding
app.config['SECRET_KEY'] = 'your_secret_key'

# Mock database for users
users_db = {}

# POST /register: Register a new user
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    if username in users_db:
        return jsonify({"message": "User already exists"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    users_db[username] = hashed_password

    return jsonify({"message": "User registered successfully"}), 201

# POST /login: Authenticate user and return a JWT
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    hashed_password = users_db.get(username)
    if not hashed_password or not bcrypt.check_password_hash(hashed_password, password):
        return jsonify({"message": "Invalid credentials"}), 401

    token = jwt.encode(
        {'username': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
        app.config['SECRET_KEY'],
        algorithm='HS256'
    )

    return jsonify({"message": "Login successful", "token": token}), 200

# POST /set-jwt: Set a custom JWT
@app.route('/set-jwt', methods=['POST'])
def set_jwt():
    data = request.get_json()
    payload = data.get('payload')

    if not payload:
        return jsonify({"message": "Payload is required"}), 400

    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return jsonify({"message": "JWT generated successfully", "token": token}), 201

# GET /get-jwt: Decode and return the JWT payload
@app.route('/get-jwt', methods=['GET'])
def get_jwt():
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({"message": "JWT is required"}), 400

    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return jsonify({"message": "JWT decoded successfully", "payload": payload}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "JWT has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid JWT"}), 401

if __name__ == '__main__':
    app.run(debug=True)
