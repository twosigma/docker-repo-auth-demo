import dateutil.parser
import json
import logging
import os
from flask import Flask, request, jsonify
from tokens import Token
from auth import basic_auth_required


app = Flask(__name__)
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


def get_allowed_actions(user, actions):
    # determine what actions are allowed here
    logging.debug('Requested actions: {}'.format(actions))
    # The three actions used by the registry are 'push', 'pull', and '*':
    # https://github.com/docker/distribution/blob/master/registry/handlers/app.go#L875
    allowed_actions = actions
    # allowed_actions = []
    # if 'pull' in actions:
    #     actions.remove('pull')
    logging.debug('Allowed actions: {}'.format(allowed_actions))
    return allowed_actions


@app.route('/getpassword')
# Could use Kerberos or whatever else is needed in your environment
@basic_auth_required
def getpassword():
    user = request.user
    token = Token('password', subject=user)
    encoded_token = token.encode_token()
    logging.info('Issued registry password to {}'.format(user))
    return jsonify(username='PASSTOKEN', password=encoded_token)


@app.route('/tokens')
@basic_auth_required
def tokens():
    service = request.args.get('service')
    scope = request.args.get('scope')
    if not scope:
        typ = ''
        name = ''
        actions = []
    else:
        params = scope.split(':')
        if len(params) != 3:
            return jsonify(error='Invalid scope parameter'), 400
        typ = params[0]
        name = params[1]
        actions = params[2].split(',')

    logging.debug("Registry request from {}: {}, {}, {}, {}".format(request.user, service, typ, name, actions))

    authorized_actions = get_allowed_actions(request.user, actions)

    token = Token(service, typ, name, authorized_actions, subject=request.user)
    encoded_token = token.encode_token()

    return jsonify(token=encoded_token)

# We configure the docker registry to send notifications here via the
# notifications->endpoints section of the registry config.
# https://docs.docker.com/registry/notifications/
@app.route('/notifications', methods=['POST'])
@basic_auth_required
def notifications():
    if request.user != 'NOTIFICATION':
        return ('', 403)
    data = json.loads(request.data)
    if not 'events' in data:
        return ('', 204)
    for event in data['events']:
        logging.debug(event)
        # At this time the possible values for action seem to be
        # push, pull, delete, and mount:
        # https://github.com/docker/distribution/blob/master/notifications/event.go#L10
        action = event['action']
        repo = event['target']['repository']
        digest = event['target']['digest']
        # tag may not be present
        tag = event['target'].get('tag')
        timestamp = dateutil.parser.parse(event['timestamp'])
        user = event['actor']['name']
        logging.info("action '{}' repo '{}' digest '{}' tag '{}' timestamp '{}' user '{}'".format(action, repo, digest, tag, timestamp, user))
        # Save to database, etc. here
    return ('', 204)

if __name__ == '__main__':
    # http://stackoverflow.com/questions/28579142/attributeerror-context-object-has-no-attribute-wrap-socket/28590266
    cert = os.environ.get('HTTPS_CERT_PATH')
    key = os.environ.get('HTTPS_KEY_PATH')
    if cert and key:
        context = (cert, key)
        app.run(host='0.0.0.0', port=8080, ssl_context=context, threaded=True, debug=True)
    else:
        app.run(host='0.0.0.0', port=8080)
