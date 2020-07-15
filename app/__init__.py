from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy

from app.config import Config

# Init app
app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)


from app import views