import logging
from os import environ
from datetime import datetime
from functools import wraps

from http.cookies import SimpleCookie

from flask_jwt_extended import jwt_required, get_jwt_identity, \
    create_access_token, set_access_cookies, unset_jwt_cookies, JWTManager

from flask import Blueprint, jsonify, request, redirect

from indralab_auth_tools.log import is_log_running, set_user_in_log, \
    set_role_in_log
from indralab_auth_tools.src.models import User, Role, BadIdentity, \
    IntegrityError, start_fresh, AuthLog, UserDatabaseError

auth = Blueprint('auth', __name__, template_folder='templates')

logger = logging.getLogger(__name__)


def config_auth(app):
    app.config['JWT_SECRET_KEY'] = environ.get('INDRADB_JWT_SECRET', 'secret')
    if app.config['JWT_SECRET_KEY'] == 'secret':
        logger.warning("No JWT secret set. A very flimsy secret is being "
                       "used. To set secret, assign to INDRADB_JWT_SECRET "
                       "environment variable.")
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3*30*24*60*60  # Around 3 months
    app.config['JWT_TOKEN_LOCATION'] = ['cookies']
    app.config['JWT_COOKIE_SECURE'] = True
    app.config['JWT_SESSION_COOKIE'] = False
    app.config['PROPAGATE_EXCEPTIONS'] = True
    app.config['JWT_COOKIE_CSRF_PROTECT'] = False
    app.config['EXPLAIN_TEMPLATE_LOADING'] = True
    # Setting JWT_IDENTITY_CLAIM to 'identity' to override the new default 'sub'. This
    # allows those with tokens still active and issued by the old deployment (which
    # used Flask-JWT-Extended < 4) to still load the homepage of the new deployment. If
    # this is not done, a user with an active old JWT will be greeted with an error
    # that refers to a missing key ('identity' or 'sub'). See more at:
    # https://flask-jwt-extended.readthedocs.io/en/stable/v4_upgrade_guide.html#encoded-jwt-changes-important
    app.config['JWT_IDENTITY_CLAIM'] = 'identity'
    SC = SimpleCookie()
    jwt = JWTManager(app)

    @jwt.expired_token_loader
    def handle_expired_token(token):
        resp = redirect(request.url)
        unset_jwt_cookies(resp)
        return resp

    return SC, jwt


def auth_wrapper(func):
    @jwt_required(optional=True)
    @wraps(func)
    def with_auth_log():
        start_fresh()
        logger.info("Handling %s request." % func.__name__)

        user_identity = get_jwt_identity()
        logger.info("Got user identity: %s" % user_identity)

        auth_log = AuthLog(date=datetime.utcnow(), action=func.__name__,
                           attempt_ip=request.remote_addr,
                           input_identity_token=user_identity)
        auth_details = {}

        ret = func(auth_details, user_identity)

        if isinstance(ret, tuple) and len(ret) == 2:
            resp, code = ret
        else:
            resp = ret
            code = 200
        auth_log.response = resp.json
        auth_log.code = code
        auth_log.details = auth_details
        auth_log.success = (func.__name__ in resp.json
                            and resp.json[func.__name__]
                            and code == 200)

        auth_log.save()
        return ret

    return with_auth_log


@auth.errorhandler(Exception)
def handle_any_error(e):
    logger.exception(e)
    return jsonify({'message': str(e)}), 500


@auth.route('/register', methods=['POST'])
@auth_wrapper
def register(auth_details, user_identity):
    try:
        user = User.get_by_identity(user_identity)
        auth_details['user_id'] = user.id
        return jsonify({"message": "User is already logged in."}), 400
    except BadIdentity:
        pass

    data = request.json
    missing = [field for field in ['email', 'password']
               if field not in data]
    if missing:
        auth_details['missing'] = missing
        return jsonify({"message": "No email or password provided"}), 400

    auth_details['new_email'] = data['email']

    new_user = User.new_user(
        email=data['email'],
        password=data['password']
    )

    try:
        new_user.save()
        auth_details['new_user_id'] = new_user.id
        return jsonify({'register': True,
                        'message': 'User {} created'.format(data['email'])})
    except IntegrityError:
        return jsonify({'message': 'User {} exists.'.format(data['email'])}), \
               400
    except Exception as e:
        logger.exception(e)
        logger.error("Unexpected error creating user.")
        return jsonify({'message': 'Could not create account. '
                                   'Something unexpected went wrong.'}), 500


@auth.route('/login', methods=['POST'])
@auth_wrapper
def login(auth_details, user_identity):
    try:
        if user_identity:
            user = User.get_by_identity(user_identity)
            auth_details['user_id'] = user.id
            logger.info("User was already logged in.")
            return jsonify({"message": "User is already logged in.",
                            'login': False, 'user_email': user.email})
    except BadIdentity:
        logger.warning("User had malformed identity or invalid.")
    except Exception as e:
        logger.exception(e)
        logger.error("Got an unexpected exception while looking up user.")

    data = request.json
    missing = [field for field in ['email', 'password']
               if field not in data]
    if missing:
        auth_details['missing'] = missing
        return jsonify({"message": "No email or password provided"}), 400

    logger.debug("Looking for user: %s." % data['email'])
    current_user = User.get_by_email(data['email'], verify=data['password'])

    logger.debug("Got user: %s" % current_user)
    if not current_user:
        logger.info("Got no user, username or password was incorrect.")
        return jsonify({'message': 'Username or password was incorrect.'}), 401
    else:
        # note the user id and the new identity.
        auth_details['user_id'] = current_user.id
        auth_details['new_identity'] = current_user.identity()

        # Save some metadata for this login.
        current_user.current_login_at = datetime.utcnow()
        current_user.current_login_ip = request.remote_addr
        current_user.active = True
        current_user.save()

    access_token = create_access_token(identity=current_user.identity())
    logger.info("Produced new access token.")
    resp = jsonify({'login': True, 'user_email': current_user.email})
    set_access_cookies(resp, access_token)
    return resp


@auth.route('/logout', methods=['POST'])
@auth_wrapper
def logout(auth_details, user_identity):
    # Stash user details
    auth_details['user_id'] = None
    if user_identity:
        try:
            user = User.get_by_identity(user_identity)
        except Exception as e:
            logger.exception(e)
            logger.error("Got error while checking identity on logout.")
            user = None
        if user:
            auth_details['user_id'] = user.id
            user.last_login_at = user.current_login_at
            user.current_login_at = None
            user.last_login_ip = user.current_login_ip
            user.current_login_ip = None
            user.active = False
            user.save()
        else:
            logger.warning("Logging out user without entry in the database.")

    resp = jsonify({'logout': True})
    unset_jwt_cookies(resp)
    return resp


def resolve_auth(query, failure_reason=None):
    """Get the roles for the current request, either by JWT or API key.

    If by API key, the key must be in the query. If by JWT,
    @jwt_required(optional=True) or similar must wrap the calling function.

    If the reason for credentials failing is of interest, you can pass an empty
    dictionary to `failure_reason`. If there is an auth problem, it will be
    populated with 'auth_attempted' and 'reason', indicating the kind of auth
    (e.g. "API key" or "Identity") that was attempted, and the reason it was
    rejected (e.g. "Invalid").

    Returns a tuple with the current user, if applicable, and a list of
    associated roles.
    """
    start_fresh()
    api_key = query.pop('api_key', None)
    logger.info("Got api key %s" % api_key)
    if api_key:
        logger.info("Using API key role.")
        try:
            role = Role.get_by_api_key(api_key)
        except UserDatabaseError:
            if failure_reason is not None:
                failure_reason['auth_attempted'] = "API key"
                failure_reason['reason'] = "Invalid"
            return None, []
        set_role_in_log(role)
        return None, [role]

    user_identity = get_jwt_identity()
    logger.debug("Got user_identity: %s" % user_identity)
    if not user_identity:
        logger.info("No user identity, no role.")
        if failure_reason is not None:
            failure_reason['auth_attempted'] = None
            failure_reason['reason'] = "No auth"
        return None, []

    try:
        current_user = User.get_by_identity(user_identity)
        logger.debug("Got user: %s" % current_user)
    except BadIdentity:
        logger.info("Identity malformed, no role.")
        if failure_reason is not None:
            failure_reason['auth_attempted'] = "Identity"
            failure_reason['reason'] = "Invalid"
        return None, []
    except Exception as e:
        logger.exception(e)
        logger.error("Unexpected error looking up user.")
        if failure_reason is not None:
            failure_reason['auth_attempted'] = "Identity"
            failure_reason['reason'] = 'Unexpected'
        return None, []

    if not current_user:
        logger.info("Identity not mapped to user, no role.")
        if failure_reason is not None:
            failure_reason['auth_attempted'] = "Identity"
            failure_reason['reason'] = "No user"
        return None, []

    logger.info("Identity mapped to the user, returning roles.")
    if is_log_running():
        set_user_in_log(current_user)
    return current_user, list(current_user.roles)
