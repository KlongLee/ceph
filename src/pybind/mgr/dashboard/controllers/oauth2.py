import logging
import cherrypy

from dashboard.controllers._auth import ControllerAuthMixin
from dashboard.services.auth import JwtManager
from dashboard.services.orchestrator import OrchClient

from .. import mgr
from ..tools import prepare_url_prefix
from . import BaseController, Endpoint, Router


logger = logging.getLogger('oauth2')

@Router('/auth/oauth2', secure=False)
class Oauth2(BaseController, ControllerAuthMixin):

    def __init__(self):
        # Needed to request to IDP's endpoints
        self.realm_name = mgr.SSO_DB.oauth2.idp_realm_name

    @Endpoint(json_response=False, version=None)
    def login(self):
        # if is_authenticated(): # TODO: CHECK KEYCLOAK SESSION

        if self._meets_login_requirements():
            access_token = cherrypy.request.headers.get('X-Access-Token')
            if not access_token:
                return 'Failed to login: Missing access token'

            ''' TODO: keep create/delete user?
            oauth_jwt_manager = Oauth2JWTManager(access_token)
            user = oauth_jwt_manager.get_user()
            '''
            url_prefix = prepare_url_prefix(mgr.get_module_option('url_prefix', default=''))

            self._set_token_cookie(url_prefix, access_token)
            raise cherrypy.HTTPRedirect(f"{url_prefix}/#/login?access_token={access_token}")

        return 'Failed to login'

    # def is_authenticated(self):
        # TODO

    @Endpoint(json_response=False, version=None)
    def logout(self):
        JwtManager.reset_user()
        token = JwtManager.get_token_from_header()
        self._delete_token_cookie(token)
        url_prefix = prepare_url_prefix(mgr.get_module_option('url_prefix', default=''))

        ''' TODO: keep create/delete user?
        token_payload = decode_jwt_segment(token.split(".")[1])
        if 'sub' in token_payload:
            mgr.ACCESS_CTRL_DB.delete_user(token_payload['sub'])
            mgr.ACCESS_CTRL_DB.save()
        '''
        #TODO : end IDP's session and redirect to IDP login
        raise cherrypy.HTTPRedirect("https://192.168.100.100:8080")

    def _meets_login_requirements(self) -> bool:
        try:
           bool(cherrypy.request.cookie['_oauth2_proxy'].value)
        except (AttributeError, KeyError):
            return False

        orch = OrchClient().instance()
        if not orch.services.list_daemons(daemon_type='oauth2-proxy') or not orch.services.list_daemons(daemon_type='mgmt-gateway'):
            logger.warning('Can not access Dashboard with oauth2 SSO, mgmt-gateway and oauth2-proxy services are required')
            return False
        return True
