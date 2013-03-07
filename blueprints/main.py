from flask import Blueprint
module = Blueprint('main', __name__)

@module.route('/')
def index():
    return "YOu hit da root"
