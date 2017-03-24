A simple flask oauth2 provider
================================

This project aims to be lightweight oauth2 provider for flask based
applications.

Functionality now is rather limited - just password and client credentials
grant authorization + token refresh. The other parts of ouath2 process and some
documentation are coming soon.

The project is still in pre-alpha state, API might change a bit in future.

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
