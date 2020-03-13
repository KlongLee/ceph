from __future__ import absolute_import

from pecan import request, response
from pecan import expose as pecan_expose
from base64 import b64decode
from functools import wraps

import traceback

from . import context


# Handle authorization
def auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not request.authorization:
            response.status = 401
            response.headers['WWW-Authenticate'] = 'Basic realm="Login Required"'
            return {'message': 'auth: No HTTP username/password'}

        username, password = b64decode(request.authorization[1]).decode('utf-8').split(':')

        # Check that the username exists
        if username not in context.instance.keys:
            response.status = 401
            response.headers['WWW-Authenticate'] = 'Basic realm="Login Required"'
            return {'message': 'auth: No such user'}

        # Check the password
        if context.instance.keys[username] != password:
            response.status = 401
            response.headers['WWW-Authenticate'] = 'Basic realm="Login Required"'
            return {'message': 'auth: Incorrect password'}

        return f(*args, **kwargs)
    return decorated


# Helper function to lock the function
def lock(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        with context.instance.requests_lock:
            return f(*args, **kwargs)
    return decorated


# Support ?page=N argument
def paginate(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        _out = f(*args, **kwargs)

        # Do not modify anything without a specific request
        if not 'page' in kwargs:
            return _out

        # A pass-through for errors, etc
        if not isinstance(_out, list):
            return _out

        # Parse the page argument
        _page = kwargs['page']
        try:
            _page = int(_page)
        except ValueError:
            response.status = 500
            return {'message': 'The requested page is not an integer'}

        # Raise _page so that 0 is the first page and -1 is the last
        _page += 1

        if _page > 0:
            _page *= 100
        else:
            _page = len(_out) - (_page*100)

        return _out[_page - 100: _page]
    return decorated


def expose(body=None):
    json_decorator = pecan_expose(template="json", generic=False, content_type="application/json")
    empty_decorator = pecan_expose()

    def decorated(f):
        if f.__name__ in ("_lookup", "_route", "_default"):
            return empty_decorator(f)

        @wraps(f)
        def _method(self, *args, **kwargs):
            if body is not None:
                try:
                    req_body = body.from_request()
                    return f(self, req_body, *args, **kwargs)
                except ValueError as err:
                    return {"message": str(err)}
            return f(self, *args, **kwargs)

        return json_decorator(_method)

    return decorated
