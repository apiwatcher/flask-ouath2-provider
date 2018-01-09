import binascii
import os
import pytz
import re
import json
import dateutil.parser
import urlparse
import jwt
import random

from jsonschema import validate, ValidationError
from datetime import datetime, timedelta
from flask import request, Response, _request_ctx_stack, redirect

from flask_oauth2_provider.exceptions import Oauth2Exception, \
    Oauth2InvalidCredentialsException, Oauth2NotImplementedException
from flask_oauth2_provider.schemata import Schemata

from urlparse import parse_qs, urlsplit, urlunsplit
from urllib import urlencode

class Provider(object):
    """Main class taking care about almost everything.

    It should exist as a single instance for each Flask application. The common
    practice in project which uses just one Flask application at the time is
    to instantiate this during startup and then share this one instance
    as global variable or you can wrapper into a singleton class.
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
        self._token_expire = None
        self._refresh_token_expire = None
        self._secret = None

        if self._app is not None:
            self._do_the_init_()

        # User defined method to create a response from data and status code
        self._response_maker = self.make_default_response

        # User defined method to verify username-password credentials
        self._password_verifier = None

        # User defined method to verify client credentials
        self._client_verifier = None

        # User defined method to verify refresh
        self._refresh_verifier = None

        # User defined method which loads user data
        self._user_loader = None

        # User defined method which loads client data
        self._client_loader = None

        # User defined method which saves authorization_code for user
        self._auth_code_saver = None

        # User defined method which verifies and invalidates authorization code
        self._auth_code_verifier = None

        # User defined method which invalidates authorization code
        self._auth_code_invalidator = None


    def init_app(self, app):
        """Initialize class with flask application.

        Use only if application was not passed to provider during __init__.
        It must be called before application runs.

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

    def set_client_verifier(self, f):
        """
        Set a function which verifies provided client credentials

        Function must accept four parameters:
            client_id - your client_id object/string
            scope - list of string scopes for which access should be granted
            client_secret - a client "password" (may be None)

        Return value is ignored by default, token will be issuesd if passes
        function passes without exception. In case of invalid credentials
        Oauth2InvalidCredentialsException should be raised with a reason in
        message.
        """
        self._client_verifier = f

    def set_refresh_verifier(self, f):
        """
        Set a function which verifies whether a refresh can be done

        Function must accept four parameters:
            client_id - your client_id object/string
            scope - list of string scopes for which access should be granted
            user_id - optional, may be null
        """
        self._refresh_verifier = f

    def set_user_loader(self, f):
        """
        Set a function which loads user data associated with a token.

        Funtion must accept one paramter:
            user_id - access token string used for authorization

        Function should return the user data according to provided token.
        If no user is associated with the token, None should be returned.
        """
        self._user_loader = f

    def set_client_loader(self, f):
        """
        Set a function which loads client data associated with a token.

        Funtion must accept one paramter:
            client_id - access token string used for authorization

        Function should return the client data according to provided token.
        If no client is associated with the token, None should be returned.
        """
        self._client_loader = f


    def set_response_maker(self, f):
        """
        Set a function which makes Flask Responses in the format you need

        Function must accept two mandatory parameters:
            data - data which should be in body (can be dict or string)
            status_code - integer HTTP status code of response

        """
        self._response_maker = f


    def set_auth_code_saver(self, f):
        """
        Set a function which persists auth code and user tupple

        Function must accept 5 mandatory parameters:
            auth_code - string, auth_code
            user_id - id of the user to whome key belongs
            client_id - id of application making this requests
            scope - array of scopes that should be granted
            expire - UTC time when suth code should expire
        """
        self._auth_code_saver = f


    def set_auth_code_verifier(self, f):
        """
        Set a function which verifies that auth code is valid

        Function must accept two mandatory parameters:
            auth_code - authorization_code itself
            client_secret - secret information that client holds

        Function must return user tuple (user_id, client_id, scope)
        """
        self._auth_code_verifier = f


    def set_auth_code_invalidator(self, f):
        """
        Set a function which invalidates authorization code

        Function must accept two mandatory parameters:
            auth_code - authorization_code itself

        Function return value is ignored
        """
        self._auth_code_invalidator = f



    # Built-in resources  -----------------------------------------------------

    def token_resource(self):
        """Instantly creates a token resource

        If your application authorization flow is straightforward, you can use
        this method to create a token resource. Usage is pretty simple:

        Usage:

        .. code-block:: python

            @app.route("/api/token")
            def handler():

                retrurn oauth2.token_resource()

        It uses defined callbacks and verifies whether provided data are
        sufficient to issue the token.
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
            elif (
                grant_data["grant_type"] == "authorization_code" or
                grant_data["grant_type"] == "code"
            ):
                return self._response_maker(
                    self.verify_authorization_code(
                        grant_data["code"],
                        grant_data["client_secret"]
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
            elif grant_data["grant_type"] == "client_credentials":
                return self._response_maker(
                    self.verify_client_grant(
                        grant_data["client_id"],
                        grant_data["scope"],
                        grant_data["client_secret"],
                    ),
                    201
                )
            else:
                return self._response_maker(
                    u"Unknown grant type '{0}'".format(
                        grant_data["grant_type"]
                    ),
                    400
                )
        except Oauth2InvalidCredentialsException as e:
            return self._response_maker(
                u"Invalid credentials supplied - {0}".format(e.message), 401
            )
        except jwt.ExpiredSignatureError:
            return self._response_maker(
                "Token is expired.", 401
            )
        except jwt.DecodeError as e:
            return self._response_maker(
                "Token could not be decoded - {0}".format(e.message),
                401
            )

    def authorize_resource(self):
        """
        Instantly creates a authorize resource

        If your application authorization flow is straightforward, you can use
        this method to create a authorization resource. Usage is pretty simple:

        Usage:

        .. code-block:: python

            @app.route("/api/authorize")
            def handler():

                retrurn oauth2.authorize_resource()

        It uses defined callbacks and verifies whether provided data are
        sufficient to issue the token.
        """
        auth_data = Provider._get_data_from_request()
        try:
            validate(auth_data, Schemata.AUTHORIZE_SCHEMA)
        except ValidationError as e:
            return self._response_maker(
                "Wrong data supplied: {0}".format(e.message),
                400
            )

        try:
            user_id = self._password_verifier(
                auth_data["client_id"], auth_data["scope"],
                auth_data["username"], auth_data["password"]
            )
        except Oauth2InvalidCredentialsException as e:
            return self._response_maker(
                u"Invalid credentials supplied - {0}".format(e.message), 401
            )

        auth_code = self.get_authorization_code()

        self._auth_code_saver(
            auth_code, user_id, auth_data["client_id"], auth_data["scope"],
            datetime.utcnow() + timedelta(seconds=self._token_expire)
        )

        redirect_url = auth_data["redirect_url"]
        redirect_url = set_query_parameter(redirect_url, "code", auth_code)
        redirect_url = set_query_parameter(redirect_url,
            "state", auth_data["state"]
        )

        return redirect(redirect_url)

    def get_authorization_code(self):
        alphabet = (
            u"0123456789"
            "abcdefghijklmnopqrstuvwxyz"
        )
        chars = []

        for i in range(128):
            chars.append(random.choice(alphabet))

        return "".join(chars)


    def restrict(self, to_scopes=None):
        """Decorate your resource to restrict access to certain scope.

        :param to_scopes: List of scope strings for which resource is accessible
        :type to_scopes:  list of strings

        Usage:

        .. code-block:: python

            @restrict(["user_scope"])
            @app.route("/api/my_endpoint")
            def my_handler():

                return Response("Works", 200)

        """
        def wrapper(f):
            def decor(*args, **kwargs):
                auth = request.headers.get("Authorization")
                if auth is None:
                    return self._response_maker(
                        "No Authorization header provided.", 401)

                bearer = re.compile("^[Bb]earer\s+(?P<token>\S+)\s*$")
                res = bearer.search(auth)
                if res is None:
                    return self._response_maker(
                        "Wrong token format, must be 'Bearer XXX'", 401
                    )
                encrypted_token_string = res.group("token")
                if len(encrypted_token_string) == 0:
                    return self._response_maker("Token string is empty.", 401)

                decrypted_token = None
                try:
                    decrypted_token = jwt.decode(
                        encrypted_token_string, self._secret, leeway=60
                    )
                except jwt.ExpiredSignatureError:
                    return self._response_maker(
                        "Token is expired.", 401
                    )
                except jwt.DecodeError as e:
                    return self._response_maker(
                        "Token could not be decoded - {0}".format(e.message),
                        401
                    )

                if decrypted_token["type"] != "access":
                    return self._response_maker(
                        "This is not an access token.", 401
                    )


                if to_scopes is not None:
                    if len(set(decrypted_token["scope"]).\
                        intersection(to_scopes)) == 0:
                        return Response(
                            "Token scope is different from resource scope.",
                            401
                        )

                # Store the stuff in request context
                ctx = _request_ctx_stack.top
                ctx.oauth2_data = {}
                if self._user_loader is not None and \
                    decrypted_token["user_id"] is not None:
                    ctx.oauth2_data["user"] = self._user_loader(
                        decrypted_token["user_id"]
                    )
                if self._client_loader is not None and \
                    decrypted_token["client_id"] is not None:
                    ctx.oauth2_data["client"] = self._client_loader(
                        decrypted_token["client_id"]
                    )

                return f(*args, **kwargs)
            return decor
        return wrapper

    def make_default_response(self, data, status_code):
        """Default response maker if you do not provide another

        If data are dictionary it will dump it to data, otherwise it will just
        pass it to response.
        """
        if isinstance(data, dict):
            return Response(json.dumps(data), status_code)
        else:
            return Response(data, status_code)

    # Token issuing stuff -----------------------------------------------------

    def issue_token(
        self, client_id, scope, include_refresh=False, user_id=None
    ):
        """
        Issue token directly

        :param client_id: Id of the client for which token will be issued
        :type client_id: string
        :param scope: A scope of the token
        :type scope: list of strings
        :param include_refresh: Whether refresh token should be issued as well
        :type include_refresh: boolean
        :param user_id: An id of the user to which token bellows (if any)
        :type user_id: Whatever is your user id (none for non-user tokens)

        This method should be used direclty only in case of you really know
        what are you doing. Normaly token should be issued by calling
        methods :func:`Provider.verify_password_grant`,
        :func:`Provider.verify_client_grant`, ... which do both verification
        and token issued at once. But it may happen that your verification
        process does not map to the standard flow (e.g. using OAuth of 3rd
        party service to verify user). In such a case you can issue token
        directly calling this method.

        .. warning:: It is up to you to verify credentials before you call this
            to issued the token!
        """
        expire = datetime.utcnow() + timedelta(seconds=self._token_expire)

        access_token = {
            "type": "access",
            "scope": scope,
            "client_id": client_id,
            "user_id": user_id,
            "exp": expire # Integer, used by jwt
        }
        access_token_str = jwt.encode(
            access_token, self._secret
        )

        rsp = {
            "access_token": access_token_str,
            "expire": expire.isoformat(),
            "expires_in": self._token_expire,
            "type": "bearer",
            "refresh_token": None
        }

        if include_refresh is True:
            refresh_token = {
                "type": "refresh",
                "scope": scope,
                "client_id": client_id,
                "user_id": user_id,
                "exp": datetime.utcnow() + timedelta(
                    seconds=self._refresh_token_expire
                )

            }
            rsp["refresh_token"] = jwt.encode(
                refresh_token, self._secret
            )

        return rsp

    def verify_password_grant(self, client_id, scope, username, password):
        """
        Verify provided credentials for password grant and issue token.

        :param client_id: Id of the client for which token will be issued
        :type client_id: string
        :param scope: A scope of the token
        :type scope: list of strings
        :param username: A string which identifies user
        :type username: string
        :param password: A super-secret user password
        :type password: string

        :returns: Token object
        """
        if self._password_verifier is None:
            raise Oauth2NotImplementedException(
                "You must set password verifier callback before verifying "
                "password grant."
            )

        user_id = self._password_verifier(
            client_id, scope, username, password
        )

        return self.issue_token(
            client_id, scope, include_refresh=True, user_id=user_id
        )

    def verify_refresh_grant(self, client_id, refresh_token_str):
        """
        Verify provided refresh token grant and issue new token.

        Scope of the new token is the same as the old token, currently it is
        not possible to change it.

        :param client_id: Id of the client for which token will be issued
        :type client_id: string
        :param refresh_token: A string representing refresh token
        :type scope: string

        :returns: Token object
        """

        if self._refresh_verifier is None:
            raise Oauth2NotImplementedException(
                "You must set refresh verifier callback before verifying "
                "password grant."
            )

        decrypted_token = jwt.decode(
            refresh_token_str, self._secret
        )

        if decrypted_token["type"] != "refresh":
            raise Oauth2InvalidCredentialsException(
                "This is not a refresh token."
            )

        self._refresh_verifier(
            client_id, decrypted_token["scope"], decrypted_token["user_id"]
        )

        return self.issue_token(
            client_id, decrypted_token["scope"], include_refresh=True,
            user_id=decrypted_token["user_id"]
        )


    def verify_client_grant(self, client_id, scope, client_secret):
        """
        Verifies whether refresh token is valid and issues a new token.
        """
        if self._client_verifier is None:
            raise Oauth2NotImplementedException(
                "You must set client verifier callback before verifying "
                "client_credentials grant."
            )

        self._client_verifier(
            client_id, scope, client_secret
        )

        return self.issue_token(
            client_id, scope, include_refresh=False
        )

    def verify_authorization_code(self, code, client_secret):
        """
        Verifies that provided authorization code is valid
        """

        if self._auth_code_verifier is None:
            raise Oauth2NotImplementedException(
                "You must set auth code verifier callback before verifying "
                "code grant."
            )

        user_id, client_id, scope = self._auth_code_verifier(
            code, client_secret
        )

        if self._auth_code_invalidator is None:
            raise Oauth2NotImplementedException(
                "You must set auth code invalider callback before using "
                "code grant."
            )

        self._auth_code_invalidator(code)

        return self.issue_token(
            client_id, scope, include_refresh=True, user_id=user_id
        )


    # Internal stuff --------------------------------------------------------
    def _do_the_init_(self):
        if "OAUTH2_TOKEN_EXPIRE" not in self._app.config:
            raise Oauth2Exception(
                "OAUTH2_TOKEN_EXPIRE is mandatory configuration parameter."
            )
        if "OAUTH2_SECRET" not in self._app.config:
            raise Oauth2Exception(
                "OAUTH2_SECRET is mandatory configuration parameter."
            )

        self._secret = self._app.config["OAUTH2_SECRET"]
        self._token_expire = self._app.config["OAUTH2_TOKEN_EXPIRE"]
        self._refresh_token_expire = self._app.config.\
            get("OAUTH2_REFRESH_TOKEN_EXPIRE", None)

    @staticmethod
    def _get_data_from_request():

        content_type = request.headers.get("content_type", None)

        request_data = {}
        if request.is_json:
            request_data = request.json
        else:
            if content_type == "application/x-www-form-urlencoded":
                for key, value in request.form.iteritems():
                    request_data[key] = value
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


# Helper methods
def set_query_parameter(url, param_name, param_value):
    """Given a URL, set or replace a query parameter and return the
    modified URL.

    >>> set_query_parameter('http://example.com?foo=bar&biz=baz', 'foo', 'stuff')
    'http://example.com?foo=stuff&biz=baz'
    """
    scheme, netloc, path, query_string, fragment = urlsplit(url)
    query_params = parse_qs(query_string)

    query_params[param_name] = [param_value]
    new_query_string = urlencode(query_params, doseq=True)

    return urlunsplit((scheme, netloc, path, new_query_string, fragment))
