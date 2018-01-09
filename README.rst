A simple flask oauth2 provider
================================

This project aims to be lightweight (not only) oauth2 provider for flask based
applications.

Currently it supports:
 - Issuing authorization codes
 - Issuing JWT tokens for password, authorization_code, client_credentials
  grants
   - Out of the box support for refresh tokens
   - No need for storage, token is self contained and it's validity can be
   checked without accessing DB

The project is still in alpha state, API might change a bit in future.

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
