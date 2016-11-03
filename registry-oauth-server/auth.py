import jose
import logging
from functools import wraps
from flask import request, jsonify
from tokens import Token


def check_auth(username, password):
    """This function is called to check if a username /
    password combination is valid.
    """
    if username == 'demouser':
        if password == 'demopass':
            request.user = username
            logging.info('Authenticated demouser with password {}'.format(password))
            return True
        logging.info('Failed to authenticate demouser with password {}'.format(password))
    elif username == 'PASSTOKEN':
        try:
            token = Token('password')
            decoded_token = token.decode_token(password)
            request.user = decoded_token['sub']
            logging.info('Valid password token from {}'.format(request.user))
            return True
        except jose.exceptions.JOSEError as e:
            logging.info('Password token error {}'.format(repr(e)))
    elif username == 'NOTIFICATION':
        if password == 'notipass':
        # if password == 'notipassword':
            request.user = username
            logging.info('Authenticated NOTIFICATION with password {}'.format(password))
            return True
        logging.info('Failed to authenticate NOTIFICATION with password {}'.format(password))
    return False


def authenticate():
    """Sends a 401 response that enables basic auth"""
    return jsonify(error='Authentication required'), 401, \
        {'WWW-Authenticate': 'Basic realm="Login Required"'}


def basic_auth_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return func(*args, **kwargs)
    return decorated
