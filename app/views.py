from flask import request, jsonify, make_response
import requests
from app import app

import jwt, datetime, uuid, zmq, json
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

from flask_cors import cross_origin

# Models
from app.models import User

# DB
from app import db

# ZMQ setup
context = zmq.Context()
socket = context.socket(zmq.PUSH)
socket.connect("tcp://127.0.0.1:2000")

@app.route('/update', methods=['POST'])
@cross_origin(expose_headers='Access-Control-Allow-Origin')
def update_config():
    token = None
    if 'x-access-token' in request.headers:
        token = request.headers['x-access-token']
    if not token:
        return jsonify({'message' : 'Token not found!'}), 401
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'])
        current_user = User.query.filter_by(username = data['public']).first
    except:
        return jsonify({'message' : 'Token is invalid!'}), 401

    conf_update = {
	    "mode": "off",
	    "temp": 26,
	    "humidity": 40,
	    "interval_start": "11:00",
	    "interval_stop": "23:00",
	    "fan_state": "off",
	    "light_state": "off",
	    "pump_state": "off"
    }
    conf_update["mode"] = request.form.get('mode')
    conf_update["temp"] = request.form.get('temp')
    conf_update["humidity"] = request.form.get('temp')
    conf_update["interval_start"] = request.form.get('temp')
    conf_update["interval_stop"] = request.form.get('temp')
    conf_update["fan_state"] = request.form.get('temp')
    conf_update["light_state"] = request.form.get('temp')
    conf_update["pump_state"] = request.form.get('pump_state')
    #socket.send_json(json.dumps(conf_update))
    return jsonify({'message' : 'Config updated!'}), 200


# Token creation
@app.route('/login', methods=['GET'])
@cross_origin(supports_credentials=True)
def login():

    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Error', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(username = auth.username).first()

    if not user:
       return make_response('Error, user not found', 401, {'WWW-Authenticate' : 'Basic realm="User not found!"'}) 

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public' : user.username, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes = 30)}, app.config['SECRET_KEY'])
        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Error, user not found', 401, {'WWW-Authenticate' : 'Basic realm="Login failed!"'})

# Fetching entries
@app.route('/fetch', methods=['GET'])
@cross_origin(supports_credentials=True)
def fetch_data():
    token = None
    if 'x-access-token' in request.headers:
        token = request.headers['x-access-token']
    if not token:
        return jsonify({'message' : 'Token not found!'}), 401
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'])
        current_user = User.query.filter_by(username = data['public']).first
    except:
        return jsonify({'message' : 'Token is invalid!'}), 401

    response = requests.get("http://127.0.0.1:5001/")
    return response.text

# Fetching entry
@app.route('/fetch_month', methods=['GET'])
@cross_origin(supports_credentials=True)
def fetch_data_month():
    token = None
    if 'x-access-token' in request.headers:
        token = request.headers['x-access-token']
    if not token:
        return jsonify({'message' : 'Token not found!'}), 401
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'])
        current_user = User.query.filter_by(username = data['public']).first
    except:
        return jsonify({'message' : 'Token is invalid!'}), 401

    response = requests.get("http://127.0.0.1:5001/month")
    return response.text

# Fetching entry
@app.route('/fetch_screenshot', methods=['GET'])
@cross_origin(supports_credentials=True)
def fetch_screenshot():
    token = None
    if 'x-access-token' in request.headers:
        token = request.headers['x-access-token']
    if not token:
        return jsonify({'message' : 'Token not found!'}), 401
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'])
        current_user = User.query.filter_by(username = data['public']).first
    except:
        return jsonify({'message' : 'Token is invalid!'}), 401

    response = requests.get("http://127.0.0.1:5002/")
    return jsonify(response)

@app.route('/user', methods=['POST'])
def create_user():
    token = None
    if 'x-access-token' in request.headers:
        token = request.headers['x-access-token']
    if not token:
        return jsonify({'message' : 'Token not found!'}), 401
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'])
        current_user = User.query.filter_by(username = data['public']).first
    except:
        return jsonify({'message' : 'Token is invalid!'}), 401
        
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(username=data['username'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'New user created!'}), 201
