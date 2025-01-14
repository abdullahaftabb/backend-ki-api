from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import time
import pytest

def create_app(testing=False):
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your_secret_key'
    app.config['MONGO_URI'] = 'mongodb://localhost:27017/testdatabase'
    if testing:
        app.config['TESTING'] = True
    
    mongo = PyMongo(app)
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        email = request.args.get('email')
        password = request.args.get('password')
        
        if not email or not password:
            return jsonify({'message': 'Email and password are required!'}), 400
            
        user = mongo.db.users.find_one({'email': email})
        
        if user and check_password_hash(user['password'], password):
            token = generate_token(user)
            return jsonify({
                'message': 'Token generated!',
                'token': token
            }), 200
        return jsonify({'message': 'Login failed! Invalid credentials'}), 401

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        email = request.args.get('email')
        password = request.args.get('password')
        
        if not email or not password:
            return jsonify({'message': 'Email and password are required!'}), 400
            
        existing_user = mongo.db.users.find_one({'email': email})
        
        if existing_user:
            return jsonify({'message': 'User already exists!'}), 400
            
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        mongo.db.users.insert_one({'email': email, 'password': hashed_password})
        return jsonify({'message': 'Signup successful!'}), 201

    @app.route('/protected', methods=['GET'])
    def protected():
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'message': 'Missing Authorization Header'}), 401
        
        try:
            token = auth_header.split(" ")[1]
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            return jsonify({
                'message': 'Protected route!',
                'user': payload['email']
            }), 200
        except IndexError:
            return jsonify({'message': 'Invalid Authorization header format!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401
    
    def generate_token(user):
        payload = {
            'email': user['email'],
            'time': time.time()
        }
        return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return app

@pytest.fixture
def app():
    app = create_app(testing=True)
    return app

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def mongo_client(app):
    with app.app_context():
        mongo = PyMongo(app)
        mongo.db.users.delete_many({})
        yield mongo

def test_register(client, mongo_client):
    print('I am in test_register')
    response = client.post('/register', query_string={
        'email': 'test@example.com',
        'password': 'password123'
    })
    assert response.status_code == 201
    data = response.get_json()
    assert data['message'] == 'Signup successful!'

    response = client.post('/register', query_string={
        'email': 'test@example.com',
        'password': 'password123'
    })
    assert response.status_code == 400
    data = response.get_json()
    assert data['message'] == 'User already exists!'
    print('Success test_register')

def test_login(client, mongo_client):
    print('I am in test_login')
    
    register_response = client.post('/register', query_string={
        'email': 'test@example.com',
        'password': 'password123'
    })
    assert register_response.status_code == 201
    
    response = client.post('/login', query_string={
        'email': 'test@example.com',
        'password': 'password123'
    })
    
    assert response.status_code == 200
    data = response.get_json()
    print('The data is ', data)
    assert 'token' in data
    assert data['message'] == 'Token generated!'
    
    print('Success test_login')

    response = client.post('/login', query_string={
        'email': 'test@example.com',
        'password': 'wrongpassword'
    })
    assert response.status_code == 401
    data = response.get_json()
    assert data['message'] == 'Login failed! Invalid credentials'
    print('login failed with wrong password')

    response = client.post('/login', query_string={
        'email': 'test@example.com'
    })
    assert response.status_code == 400
    data = response.get_json()
    assert data['message'] == 'Email and password are required!'
    print('login failed with missing password')
    
    print('Success test_login')

def test_protected_route(client, mongo_client):
    print('I am in test_protected_route')
    register_response = client.post('/register', query_string={
        'email': 'test@example.com',
        'password': 'password123'
    })
    assert register_response.status_code == 201

    login_response = client.post('/login', query_string={
        'email': 'test@example.com',
        'password': 'password123'
    })
    assert login_response.status_code == 200
    token = login_response.get_json()['token']

    response = client.get('/protected', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    data = response.get_json()
    assert data['message'] == 'Protected route!'
    assert data['user'] == 'test@example.com'

    response = client.get('/protected')
    assert response.status_code == 401
    data = response.get_json()
    assert data['message'] == 'Missing Authorization Header'
    print('Missing Authorization Header')

    response = client.get('/protected', headers={'Authorization': 'Bearer invalidtoken'})
    assert response.status_code == 401
    data = response.get_json()
    assert data['message'] == 'Invalid token!'
    print('Invalid token!')