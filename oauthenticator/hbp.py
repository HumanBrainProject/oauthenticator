"""
Custom Authenticator to use HBP OIDC with JupyterHub
"""

import json

from tornado.auth import OAuth2Mixin
from tornado import gen, web, escape

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from traitlets import Unicode
from traitlets.config.application import get_config

from oauthenticator.oauth2 import OAuthLoginHandler, OAuthenticator, OAuthCallbackHandler

# load env from config
c = get_config()
env = c.HbpOAuthenticator.env

if env in ['dev', 'staging']:
    HBP_HOST = 'services-%s.humanbrainproject.eu/oidc' % env
else:
    HBP_HOST = 'services.humanbrainproject.eu/oidc'

HBP_USERINFO_URL = '%s/v0/api/user/me' % HBP_HOST


class HbpMixin(OAuth2Mixin):
    """
    define HBP OAuth endpoints
    """
    _OAUTH_AUTHORIZE_URL = "https://%s/authorize" % HBP_HOST
    _OAUTH_ACCESS_TOKEN_URL = "https://%s/token" % HBP_HOST


class HbpLoginHandler(OAuthLoginHandler, HbpMixin):
    '''customized OAuthLoginHandler'''
    def get(self):
        redirect_uri = self.authenticator.oauth_callback_url
        if self.get_query_argument('next', None):
            redirect_uri += '?next=%s' % escape.url_escape(self.get_query_argument('next'))

        self.log.info('oauth redirect: %r', redirect_uri)

        self.authorize_redirect(
            redirect_uri=redirect_uri,
            client_id=self.authenticator.client_id,
            scope=[],
            response_type='code')


class HBPCallbackHandler(OAuthCallbackHandler):
    """Custom handler for OAuth callback.
    Calls authenticator to verify username.
    Support next query argument to customize redirect
    """
    @gen.coroutine
    def get(self):
        # TODO: Check if state argument needs to be checked
        username = yield self.authenticator.authenticate(self)
        if username:
            user = self.user_from_username(username)
            self.set_login_cookie(user)

            if self.get_query_argument('next', None):
                self.redirect(escape.url_unescape(self.get_query_argument('next')))
            else:
                self.redirect(url_path_join(self.hub.server.base_url, 'home'))
        else:
            # todo: custom error page?
            raise web.HTTPError(403)


class HbpOAuthenticator(OAuthenticator):
    """
    HBP Authenticator class
    """
    login_service = "HBP"
    client_id_env = 'HBP_CLIENT_ID'
    client_secret_env = 'HBP_CLIENT_SECRET'
    login_handler = HbpLoginHandler
    oauth_callback_url = Unicode(config=True)
    callback_handler = HBPCallbackHandler

    def _get_redirect_uri(self, handler):
        """append callback_url with next query param if present"""
        redirect_uri = self.oauth_callback_url
        if handler.get_query_argument('next', None):
            redirect_uri += '?next=%s' % escape.url_escape(handler.get_query_argument('next'))
        return redirect_uri

    @gen.coroutine
    def authenticate(self, handler):
        code = handler.get_argument("code", False)
        if not code:
            raise web.HTTPError(400, "oauth callback made without a token")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        # Exchange the OAuth code for an Access Token
        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            code=code,
            redirect_uri=self._get_redirect_uri(handler),
            grant_type='authorization_code'
        )

        url = url_concat("https://%s/token" % HBP_HOST, params)

        req = HTTPRequest(url,
                          method="POST",
                          headers={"Accept": "application/json"},
                          body='')

        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']

        # Determine who the logged in user is
        headers = {"Accept": "application/json",
                   "User-Agent": "JupyterHub",
                   "Authorization": "Bearer {}".format(access_token)}

        req = HTTPRequest("https://%s" % HBP_USERINFO_URL,
                          method="GET",
                          headers=headers)

        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        # return user's sciper
        return resp_json["id"]
