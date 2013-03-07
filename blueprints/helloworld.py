# Easiest API module ever made in the world.
from flask import Blueprint

module = Blueprint('helloworld', __name__)

@module.route('/hello', methods=['GET'])
def helloworld():
    """ Example of validating request data and formulating customized response. """
    from flask import request   # Required to access request.method etc
    from flask import Response  # Lets us get fancy with Responses.
    if request.method == 'GET':
        return Response("Hello, world.\n",200,mimetype='application/json')

@module.route('/hello/<world>', methods=['GET'])
def hello(world):
    """ Simple example, using <world> as an object """
    return "Hello, " + str(world) + ".\n" 
