# Easiest API module ever made in the world.
from flask import Blueprint
module = Blueprint('helloworld', __name__)
@module.route('/hello', methods=['GET'])
def testone():
    return "Hello, world.\n"

@module.route('/hello/<world>', methods=['GET'])
def testtwo(world):
    return "Hello, " + str(world) + ".\n" 
