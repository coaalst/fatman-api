from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from app.config import Config
from flask_cors import CORS

# Init app
app = Flask(__name__)
app.config.from_object(Config)

cors = CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})
app.config['CORS_HEADERS'] = 'Content-Type'

db = SQLAlchemy(app)


from app import views