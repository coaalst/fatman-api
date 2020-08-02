import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    # DB
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'fatman.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = 'fatcat'

    # ZMQ Connection stuff
    web_controller_conn_str = "tcp://127.0.0.1:2000"