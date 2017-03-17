
class Oauth2Exception(Exception):
    """
    Generic oauth2 exception. Every other exception should subclass this one.
    """
    pass

class Oauth2InvalidCredentialsException(Exception):
    """
    Should be returned from callbacks when invalid credentials are supplied
    """
    pass

class Oauth2NotImplementedException(Exception):
    """
    Raised when a user defined function is being used and is not set
    """
    pass
