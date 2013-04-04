# Get logging.
import logging
log = logging.getLogger(__name__)

# Load the configs.
from classes.party import Config
import ConfigParser
config = ConfigParser.ConfigParser()
try:
    config.read(Config.location) # This is where we use the party config.

    USA_URL = config.get('AuthClientSetting', 'usa_url')
    USA_USER = config.get('AuthClientSetting', 'usa_user')
    USA_KEY = config.get('AuthClientSetting', 'usa_key')
    LON_CACHEFILE = config.get('AuthClientSetting', 'usa_cachefile')
    
    LON_URL = config.get('AuthClientSetting', 'lon_url')
    LON_USER = config.get('AuthClientSetting', 'lon_user')
    LON_KEY = config.get('AuthClientSetting', 'lon_key')
    LON_CACHEFILE = config.get('AuthClientSetting', 'lon_cachefile')
except ConfigParser.NoSectionError:
    classlog.logger.critical("Missing config section [AuthClientSetting] ",exc_info=True)
    raise
except ConfigParser.NoOptionError:
    classlog.logger.critical("Missing expected parameter inside of [AuthClientSetting] ",exc_info=True)
    raise

# Do flask.
from flask import Blueprint
module = Blueprint('gettoken', __name__)
@module.route('/token/<region>')
def show(region):
    import classes.authcache
    auth = classes.authcache.identity(region='usa',user=USA_USER,apikey=USA_KEY,endpoint=USA_URL)

    return str(auth.get_token() + "\n")
