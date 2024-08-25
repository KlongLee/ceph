# -*- coding: utf-8 -*-

import base64
import hashlib
import hmac
import json
import logging
import os
import threading
import time
import uuid
from typing import Optional

import cherrypy

from .. import mgr
from ..exceptions import DashboardException, ExpiredSignatureError, InvalidAlgorithmError, InvalidTokenError
from .access_control import LocalAuthenticator, UserDoesNotExist

cherrypy.config.update({
    'response.headers.server': 'Ceph-Dashboard',
    'response.headers.content-security-policy': "frame-ancestors 'self';",
    'response.headers.x-content-type-options': 'nosniff',
    'response.headers.strict-transport-security': 'max-age=63072000; includeSubDomains; preload'
})


class JwtManager(object):
    JWT_TOKEN_BLOCKLIST_KEY = "jwt_token_block_list"
    JWT_TOKEN_TTL = 28800  # default 8 hours
    JWT_ALGORITHM = 'HS256'
    _secret = None

    LOCAL_USER = threading.local()

    @staticmethod
    def _gen_secret():
        secret = os.urandom(16)
        return base64.b64encode(secret).decode('utf-8')

    @classmethod
    def init(cls):
        cls.logger = logging.getLogger('jwt')  # type: ignore
        # generate a new secret if it does not exist
        secret = mgr.get_store('jwt_secret')
        if secret is None:
            secret = cls._gen_secret()
            mgr.set_store('jwt_secret', secret)
        cls._secret = secret

    @classmethod
    def array_to_base64_string(cls, message):
        jsonstr = json.dumps(message, sort_keys=True).replace(" ", "")
        string_bytes = base64.urlsafe_b64encode(bytes(jsonstr, 'UTF-8'))
        return string_bytes.decode('UTF-8').replace("=", "")

    @classmethod
    def encode(cls, message, secret):
        header = {"alg": cls.JWT_ALGORITHM, "typ": "JWT"}
        base64_header = cls.array_to_base64_string(header)
        base64_message = cls.array_to_base64_string(message)
        base64_secret = base64.urlsafe_b64encode(hmac.new(
            bytes(secret, 'UTF-8'),
            msg=bytes(base64_header + "." + base64_message, 'UTF-8'),
            digestmod=hashlib.sha256
        ).digest()).decode('UTF-8').replace("=", "")
        return base64_header + "." + base64_message + "." + base64_secret

    @classmethod
    def decode(cls, message, secret):
        oauth2_sso_protocol = mgr.SSO_DB.protocol == 'oauth2'
        split_message = message.split(".")
        base64_header = split_message[0]
        base64_message = split_message[1]
        base64_secret = split_message[2]

        decoded_header = decode_jwt_segment(base64_header)

        if decoded_header['alg'] != cls.JWT_ALGORITHM and not oauth2_sso_protocol:
            raise InvalidAlgorithmError()

        incoming_secret = ''
        if decoded_header['alg'] == cls.JWT_ALGORITHM:
            incoming_secret = base64.urlsafe_b64encode(hmac.new(
                bytes(secret, 'UTF-8'),
                msg=bytes(base64_header + "." + base64_message, 'UTF-8'),
                digestmod=hashlib.sha256
            ).digest()).decode('UTF-8').replace("=", "")

        if base64_secret != incoming_secret and not oauth2_sso_protocol:
            raise InvalidTokenError()

        decoded_message = decode_jwt_segment(base64_message)
        if decoded_header['alg'] == 'RS256' and oauth2_sso_protocol:
            decoded_message['username'] = decoded_message['sub']
        now = int(time.time())
        if decoded_message['exp'] < now:
            raise ExpiredSignatureError()

        return decoded_message

    @classmethod
    def gen_token(cls, username, ttl: Optional[int] = None):
        if not cls._secret:
            cls.init()
        if ttl is None:
            ttl = mgr.get_module_option('jwt_token_ttl', cls.JWT_TOKEN_TTL)
        else:
            ttl = int(ttl) * 60 * 60  # convert hours to seconds
        now = int(time.time())
        payload = {
            'iss': 'ceph-dashboard',
            'jti': str(uuid.uuid4()),
            'exp': now + ttl,
            'iat': now,
            'username': username
        }
        return cls.encode(payload, cls._secret)  # type: ignore

    @classmethod
    def decode_token(cls, token):
        if not cls._secret:
            cls.init()
        return cls.decode(token, cls._secret)  # type: ignore

    @classmethod
    def get_token_from_header(cls):
        auth_cookie_name = 'token'
        if mgr.SSO_DB.protocol == 'oauth2':
            return cherrypy.request.headers.get('X-Access-Token')
        try:
            # use cookie
            return cherrypy.request.cookie[auth_cookie_name].value
        except KeyError:
            try:
                # fall-back: use Authorization header
                auth_header = cherrypy.request.headers.get('authorization')
                if auth_header is not None:
                    scheme, params = auth_header.split(' ', 1)
                    if scheme.lower() == 'bearer':
                        return params
            except IndexError:
                return None

    @classmethod
    def set_user(cls, username):
        cls.LOCAL_USER.username = username

    @classmethod
    def reset_user(cls):
        cls.set_user(None)

    @classmethod
    def get_username(cls):
        return getattr(cls.LOCAL_USER, 'username', None)

    @classmethod
    def get_user(cls, token):
        try:
            dtoken = cls.decode_token(token)
            if 'jti' in dtoken and not cls.is_blocklisted(dtoken['jti']):
                user = AuthManager.get_user(dtoken['username'])
                if ('iat' in dtoken and user.last_update <= dtoken['iat']) or mgr.SSO_DB.protocol == 'oauth2':
                    return user
                cls.logger.debug(  # type: ignore
                    "user info changed after token was issued, iat=%s last_update=%s",
                    dtoken['iat'], user.last_update
                )
            else:
                cls.logger.debug('Token is block-listed')  # type: ignore
        except ExpiredSignatureError:
            cls.logger.debug("Token has expired")  # type: ignore
        except InvalidTokenError:
            cls.logger.debug("Failed to decode token")  # type: ignore
        except InvalidAlgorithmError:
            cls.logger.debug("Only the HS256 algorithm is supported.")  # type: ignore
        except UserDoesNotExist:
            cls.logger.debug(  # type: ignore
                "Invalid token: user %s does not exist", dtoken['username']
            )
        return None

    @classmethod
    def blocklist_token(cls, token):
        token = cls.decode_token(token)
        blocklist_json = mgr.get_store(cls.JWT_TOKEN_BLOCKLIST_KEY)
        if not blocklist_json:
            blocklist_json = "{}"
        bl_dict = json.loads(blocklist_json)
        now = time.time()

        # remove expired tokens
        to_delete = []
        for jti, exp in bl_dict.items():
            if exp < now:
                to_delete.append(jti)
        for jti in to_delete:
            del bl_dict[jti]

        bl_dict[token['jti']] = token['exp']
        mgr.set_store(cls.JWT_TOKEN_BLOCKLIST_KEY, json.dumps(bl_dict))

    @classmethod
    def is_blocklisted(cls, jti):
        blocklist_json = mgr.get_store(cls.JWT_TOKEN_BLOCKLIST_KEY)
        if not blocklist_json:
            blocklist_json = "{}"
        bl_dict = json.loads(blocklist_json)
        return jti in bl_dict


class AuthManager(object):
    AUTH_PROVIDER = None

    @classmethod
    def initialize(cls):
        cls.AUTH_PROVIDER = LocalAuthenticator()

    @classmethod
    def get_user(cls, username):
        return cls.AUTH_PROVIDER.get_user(username)  # type: ignore

    @classmethod
    def authenticate(cls, username, password):
        return cls.AUTH_PROVIDER.authenticate(username, password)  # type: ignore

    @classmethod
    def authorize(cls, username, scope, permissions):
        return cls.AUTH_PROVIDER.authorize(username, scope, permissions)  # type: ignore


class AuthManagerTool(cherrypy.Tool):
    def __init__(self):
        super(AuthManagerTool, self).__init__(
            'before_handler', self._check_authentication, priority=20)
        self.logger = logging.getLogger('auth')

    def _check_authentication(self):
        JwtManager.reset_user()
        token = JwtManager.get_token_from_header()
        if token:
            user = JwtManager.get_user(token)
            if user:
                self._check_authorization(user.username)
                return

        resp_head = cherrypy.response.headers
        req_head = cherrypy.request.headers
        req_header_cross_origin_url = req_head.get('Access-Control-Allow-Origin')
        cross_origin_urls = mgr.get_module_option('cross_origin_url', '')
        cross_origin_url_list = [url.strip() for url in cross_origin_urls.split(',')]

        if req_header_cross_origin_url in cross_origin_url_list:
            resp_head['Access-Control-Allow-Origin'] = req_header_cross_origin_url

        self.logger.debug('Unauthorized access to %s',
                          cherrypy.url(relative='server'))
        raise cherrypy.HTTPError(401, 'You are not authorized to access '
                                      'that resource')

    def _check_authorization(self, username):
        self.logger.debug("checking authorization...")
        handler = cherrypy.request.handler.callable
        controller = handler.__self__
        sec_scope = getattr(controller, '_security_scope', None)
        sec_perms = getattr(handler, '_security_permissions', None)
        JwtManager.set_user(username)

        if not sec_scope:
            # controller does not define any authorization restrictions
            return

        self.logger.debug("checking '%s' access to '%s' scope", sec_perms,
                          sec_scope)

        if not sec_perms:
            self.logger.debug("Fail to check permission on: %s:%s", controller,
                              handler)
            raise cherrypy.HTTPError(403, "You don't have permissions to "
                                          "access that resource")

        if not AuthManager.authorize(username, sec_scope, sec_perms):
            raise cherrypy.HTTPError(403, "You don't have permissions to "
                                          "access that resource")

class Oauth2JWTManager:

    def __init__(self, token) -> None:
        self.token = token;
        self.token_payload = self.get_token_payload()
        pass

    def set_token(self, token):
        self.token = token

    def get_token_payload(self):
        if self.token:
            return decode_jwt_segment(self.token.split(".")[1])
        return {}

    def get_user_roles(self):
        user_roles = []
        # check for client roles
        if 'resource_access' in self.token_payload:
            # Find the first value where the key is not 'account'
            user_roles = next((value['roles'] for key, value in self.token_payload['resource_access'].items() if key != "account"), user_roles)
        # check for global roles
        elif 'realm_access' in self.token_payload:
            user_roles = next((value['roles'] for _, value in self.token_payload['realm_access'].items()), user_roles)
        else:
            raise DashboardException(f'Provided user roles, {user_roles} are not valid')
        return user_roles

    def get_user(self):
        if not 'sub' in self.token_payload:
            return None
        try:
            user = AuthManager.get_user(self.token_payload['sub'])
            return user
        except UserDoesNotExist:
            self._create_user()

    def _create_user(self):
        user_roles = self.get_user_roles()
        user = mgr.ACCESS_CTRL_DB.create_user(self.token_payload['sub'], None, self.token_payload['name'], self.token_payload['email'])
        user.set_roles(user_roles)

        # set user last update to token time issued
        user.last_update = self.token_payload['iat']
        mgr.ACCESS_CTRL_DB.save()


def decode_jwt_segment(encoded_segment: str):
    # We add ==== as padding to ignore the requirement to have correct padding in
    # the urlsafe_b64decode method.
    return json.loads(base64.urlsafe_b64decode(encoded_segment + "===="))
