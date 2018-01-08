A simple flask oauth2 provider
================================

This project aims to be lightweight (not only) oauth2 provider for flask based
applications.

Currently it supports:
 - Issuing JWT tokens for password and client_credentials grants
   - Out of the box support for refresh tokens
   - No need for storage, token is self contained and it's validity can be
   checked without accessing DB
 - Issuing long-term API keys
   - Not part of the Oauth2 process, however useful for simple scripts or
   clients unable to manage oauth2 flows
   - Also self contained, revoking can be implemented for cost of DB access

Authorization_code grant is not supported at this time but it may be added in
near future.


Installation
=============

Best way is to use *pip*.

.. code-block:: shell

  pip install Flask-OAuth2-Provider

Make html documentation
========================

Doc is "in construction" mode but most of code is documented even with some
example usage. The general overview how to integrate all this into your
code is a task to be done.

.. code-block:: shell

  cd docs
  make html

And then open it as file in you favorite browser. :)

Issues
=======

Currently there is no way how to revoke tokens and since we use JWT this
probably will not be fixed.
