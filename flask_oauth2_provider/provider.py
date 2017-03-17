import binascii
import os
import pytz
import re
import json
import dateutil.parser
import urlparse

from jsonschema import validate, ValidationError
from datetime import datetime, timedelta
from flask import request, Response, _request_ctx_stack

from flask_oauth2_provider.exceptions import Oauth2Exception, \
    Oauth2InvalidCredentialsException, Oauth2NotImplementedException
from flask_oauth2_provider.schemata import Schemata


class Provider(object):
    """Main class taking care about almost everything.

    It should exist as a single instance for one Flask application which must
    pe passed during init.
    """

    # Initializers ------------------------------------------------------------
    def __init__(self, app=None):
        """Initiliaze provider.

        If you do not want to pass app now, you can do it later calling
        :func:`init_app`

        :param app: Flask application object
        :type app: Flask application

        """
        self._app = app
        self._token_len = None
        self._token_expire = None

        if self._app is not None:
            self._do_the_init_()

        # User defined method to create a response from data and status code
        self._response_maker = self.make_default_response

        # User defined method to verify username-password credentials
        self._password_verifier = None

        # User defined method to store token
        self._token_saver = None

        # User defined method which loads token from whatever hell
        self._token_loader = None

        # User defined method which loads user data
        self._user_loader = None

        # User defined method which loads client data
        self._client_loader = None

    def init_app(self, app):
        """Initialize class with flask application.

        :param app: Flask application object
        :type app: Flask application
        :returns: None
        """
        self._app = app
        self._do_the_init_()


    def set_password_verifier(self, f):
        """
        Set a function which verifies provided username-password credentials

        Function must accept four parameters:
            client_id - your client_id object/string
            scope - list of string scopes for which access should be granted
            username - a username of user which wants to be authenticated
            password - a secret stored for each user

        Return value should be None or user_id to be stored in token.
        In both cases a token will be issued. In case of invalid credentials
        Oauth2InvalidCredentialsException should be raised with a reason in
        message.
        """
        self._password_verifier = f

    def set_token_saver(self, f):
        """
        Set a function which saves provided token

        Function must accept one parameter:
            token - a dictinary with token

        Token is considered stored if function passes without raising an
        exception.
        """
        self._token_saver = f

    def set_token_loader(self, f):
        """
        Set a function which loads all token information.

        Funtion must accept two optional parameters:
            access_token_str - access token to be found
            refresh_token_str - refresh token to be found

        Function should return the token according to provided string(s)
        regardless on expiration time. If no token is found a None should be
        returned.
        """
        self._token_loader = f

    def set_user_loader(self, f):
        """
        Set a function which loads user data associated with a token.

        Funtion must accept one paramter:
            access_token_str - access token string used for authorization

        Function should return the user data according to provided token.
        If not user is associated with the token, None should be returned.
        If no token is found Oauth2TokenNotFoundException should be raised.
        """
        self._user_loader = f

    def set_client_loader(self, f):
        """
        Set a function which loads client data associated with a token.

        Funtion must accept one paramter:
            access_token_str - access token string used for authorization

        Function should return the client data according to provided token.
        If no client is associated with the token, None should be returned.
        If no token is found Oauth2TokenNotFoundException should be raised.
        """
        self._client_loader = f

    def set_token_revoker(self, f):
        """
        Set a function which permanently deletes token

        Funtion must accept two optional parameters:
            access_token_str - access token to be deleted
            refresh_token_str - refresh token to be deleted

        Function should return None on success. If no token is found sillent
        success is expected.
        """
        self._token_revoker = f

    def set_response_maker(self, f):
        """
        Set a function which makes Flask Responses in the format you need

        Function must accept two mandatory parameters:
            data - data which should be in body (can be dict or string)
            status_code - integet HTTP status code of response

        """
        self._response_maker = f

    # Built-in resources  -----------------------------------------------------

    def token_resource(self):
        """Instantly creates a token resource
        """
        grant_data = Provider._get_data_from_request()
        try:
            validate(grant_data, Schemata.GRANT_SCHEMA)
        except ValidationError as e:
            return self._response_maker(
                "Wrong data supplied: {0}".format(e.message),
                400
            )

        try:
            if grant_data["grant_type"] == "password":
                return self._response_maker(
                    self.verify_password_grant(
                        grant_data["client_id"],
                        grant_data["scope"],
                        grant_data["username"],
                        grant_data["password"]
                    ),
                    201
                )
            elif grant_data["grant_type"] == "refresh_token":
                return self._response_maker(
                    self.verify_refresh_grant(
                        grant_data["client_id"],
                        grant_data["refresh_token"]
                    ),
                    201
                )
            else:
                return self._response_maker(
                    "Token for grant {0} is not implemented".format(
                        grant_data["grant_type"]
                    ),
                    400
                )
        except Oauth2InvalidCredentialsException as e:
            return self._response_maker(
                "Invalid credentials supplied", 401
            )


    def revoke_resource(self):
        """Instantly creates a revoke resource
        """
        token_data = Provider._get_data_from_request()

        try:
            validate(token_data, Schemata.REVOKE_SCHEMA)
        except ValidationError as e:
            self._response_maker(
                "Wrong data supplied: {0}".format(e.message),
                400
            )
        try:
            self._token_revoker(access_token_str=token_data["access_token"])
        except Oauth2InvalidCredentialsException as e:
            self._response_maker(
                "Invalid credentials supplied", 401
            )
        except Oauth2Exception as e:
            self._response_maker(
                "Could not revoke token: {0}".format(e.message),
                    500
            )

        return self._response_maker("Token revoked", 200)

    def restrict(self, to_scopes=None):
        """Decorate your resource to restrict access to certain scope.

        Usage:
        .. code-block:: python

            @restrict(["user_scope"])
            @app.route("/api/my_endpoint")
            def my_handler():
                return Response("Works", 200)

        :param to_scopes: List of scope strings for which resource is accessible
        :type to_scopes:  list of strings
        """
        def wrapper(f):
            def decor(*args, **kwargs):
                auth = request.headers.get("Authorization")
                if auth is None:
                    return self._response_maker("Unauthorized", 401)

                bearer = re.compile("^[Bb]earer\s+(?P<token>\S+)\s*$")
                res = bearer.search(auth)
                if res is None:
                    return self._response_maker("Unauthorized", 401)
                token_string = res.group("token")
                if len(token_string) == 0:
                    return self._response_maker("Unauthorized", 401)

                if self._token_loader is None:
                    raise Oauth2Exception(
                        "You must set token loader before restricting access"
                    )
                token = self._token_loader(access_token_str=token_string)
                # No token means it does not exist
                if token is None:
                    return self._response_maker("Unauthorized", 401)

                # Different token returned, error on user side probably
                if token["access_token"] != token_string:
                    raise Oauth2Exception(
                        "Different access token returned"
                    )

                if datetime.now(pytz.UTC) > dateutil.parser.parse(token["expires"]):
                    return self._response_maker("Token expired", 401)

                if to_scopes is not None:
                    if len(set(token["scope"]).intersection(to_scopes)) == 0:
                        return Response("Unauthorized", 401)

                # Store the stuff in request context
                ctx = _request_ctx_stack.top
                ctx.oauth2_data = {}
                if self._user_loader is not None:
                    ctx.oauth2_data["user"] = self._user_loader(token_string)
                if self._client_loader is not None:
                    ctx.oauth2_data["client"] = self._client_loader(
                        token_string
                    )

                return f(*args, **kwargs)
            return decor
        return wrapper

    def make_default_response(self, data, status_code):
        """Default response maker if you do not provide any other

        If data are dictionary it will dump it to data, otherwise it will just
        pass it to response.
        """
        if isinstance(data, dict):
            return Response(json.dumps(data), status_code)
        else:
            return Response(data, status_code)

    def verify_password_grant(self, client_id, scope, username, password):
        """
        Verify whether provided credentials are valid and return token

        This method should be called in token (login) resource. It returns
        either token (access granted) or None (access refused).  In case of
        provided password grant verifier raises exceptions, these exceptions
        may occur as a result of calling this function.
        """

        user_id = self._password_verifier(
            client_id, scope, username, password
        )

        token = self._create_token(
            client_id, scope, include_refresh=True, user_id=user_id
        )

        if self._token_saver is None:
            raise Oauth2NotImplementedException(
                "You must set token saver callback before issuing a token"
            )

        self._token_saver(token)
        return token

    def verify_refresh_grant(self, client_id, refresh_token):
        """
        Verifies whether refresh token is valid and issues a new token.
        """
        if self._token_loader is None:
            raise Oauth2NotImplementedException(
                "You must set token loader callback before issuing a token"
            )

        old_token = self._token_loader(refresh_token_str=refresh_token)
        if old_token is None or old_token["client_id"] != client_id:
            raise Oauth2InvalidCredentialsException(
                "Provided refresh token is invalid."
            )

        new_token = self._create_token(
            client_id, old_token["scope"], include_refresh=True,
            user_id=old_token["user_id"]
        )
        self._token_revoker(access_token_str=old_token["access_token"])
        self._token_saver(new_token)

        return new_token

    # Internal stuff --------------------------------------------------------

    def _do_the_init_(self):
        if "OAUTH2_TOKEN_LEN" not in self._app.config:
            raise Oauth2Exception(
                "OAUTH2_TOKEN_LEN is mandatory configuration parameter."
            )
        if "OAUTH2_TOKEN_EXPIRE" not in self._app.config:
            raise Oauth2Exception(
                "OAUTH2_TOKEN_EXPIRE is mandatory configuration parameter."
            )

        self._token_len = self._app.config["OAUTH2_TOKEN_LEN"]
        self._token_expire = self._app.config["OAUTH2_TOKEN_EXPIRE"]

    def _create_token(
        self, client_id, scope, include_refresh=False, user_id=None
    ):
        token = {
            "access_token": binascii.hexlify(os.urandom(self._token_len)),
            "scope": scope,
            "expires":
                (
                    datetime.now(pytz.UTC) +
                    timedelta(seconds=self._token_expire)
                ).isoformat(),
            "client_id": client_id,
            "user_id": user_id
        }

        if include_refresh is True:
            token["refresh_token"] = binascii.hexlify(
                os.urandom(self._token_len)
            )
        else:
            token["refresh_token"] = None

        return token

    @staticmethod
    def _get_data_from_request():
        request_data = {}
        if request.is_json:
            request_data = request.json
        else:
            for key, value in request.args.iteritems():
                request_data[key] = value

            if "scope" in request_data and request_data["scope"] is not None:
                request_data["scope"] = request_data["scope"].split(",")

        return request_data

# Functions out of provider scope used to access data in request context ------

def get_user_data():
    """
    Return user data associated with access_token in current request context.

    The result is obtained from calling a callback stored by
    :func set_user_loader:. It can be None in case of no user loader is defined
    or no user data are associated with the token currently used for
    authenication (a token was issued for an internal script or so).
    """
    ctx = _request_ctx_stack.top
    if hasattr(ctx, 'oauth2_data') and "user" in ctx.oauth2_data:
        return ctx.oauth2_data["user"]
    else:
        return None

def get_client_data():
    """
    Return client data associated with access_token in current request context.

    The result is obtained from calling a callback stored by
    :func set_client_loader:. It can be None in case of no client loader is
    defined or the client loader returned None.
    """
    ctx = _request_ctx_stack.top
    if hasattr(ctx, 'oauth2_data') and "client" in ctx.oauth2_data:
        return ctx.oauth2_data["client"]
    else:
        return None
