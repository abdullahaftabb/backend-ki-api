from flask import Flask, request, jsonify, flash
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import time


app=Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['MONGO_URI'] = 'mongodb://localhost:27017/testdatabase'
mongo = PyMongo(app)

@app.route('/')
def home():
    return login()

def generate_token(user):
    payload = {
        'email': user['email'],
        'time': time.time()
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

MAX_Login = 150
current_login = 0

@app.route('/login', methods=['GET', 'POST'])
def login():
    global current_login
    email = request.args.get('email')
    password = request.args.get('password')
    user = mongo.db.users.find_one({'email': email})
    if user and check_password_hash(user['password'], password):
        token = generate_token(user)
        print(token)
        current_login = current_login + 1
        print('current_login is ',current_login)
        if current_login > MAX_Login:
            return jsonify({'message': 'Login failed! bcz max limit reached'})
        return jsonify({'message': 'token generated!', 'token': token})
    else:
        return jsonify({'message': 'Login failed!'})

@app.route('/register', methods=['GET', 'POST'])
def register():
    email = request.args.get('email')
    password = request.args.get('password')
    existing_user = mongo.db.users.find_one({'email': email})
    print(email)
    print(password)
    if existing_user:
        return jsonify({'message': 'User already exists!'})
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    mongo.db.users.insert_one({'email': email, 'password': hashed_password})
    return jsonify({'message': 'signup successful!'})

@app.route('/protected', methods=['GET'])
def protected():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'message': 'Missing Authorization Header'}), 401
    try:
        token = auth_header.split(" ")[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return jsonify({'message': 'protected route!', 'user': payload['email']})
    except IndexError:
        return jsonify({'message': 'Invalid Authorization header format!'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token!'}), 401

if __name__ == '__main__':
    app.run(debug=True, port=8006)