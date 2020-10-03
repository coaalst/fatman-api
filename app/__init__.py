from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from app.config import Config
from flask_cors import CORS

# Init app
app = Flask(__name__)
CORS(app, support_credentials=True)
app.config.from_object(Config)
db = SQLAlchemy(app)

from app import views