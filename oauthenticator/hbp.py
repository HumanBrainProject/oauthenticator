"""
Custom Authenticator to use HBP OIDC with JupyterHub
"""

import json

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from traitlets import Unicode
from traitlets.config.application import get_config

from oauthenticator.oauth2 import OAuthLoginHandler, OAuthenticator

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
    pass


class HbpOAuthenticator(OAuthenticator):
    """
    HBP Authenticator class
    """
    login_service = "HBP"
    client_id_env = 'HBP_CLIENT_ID'
    client_secret_env = 'HBP_CLIENT_SECRET'
    login_handler = HbpLoginHandler
    oauth_callback_url = Unicode(config=True)

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
            redirect_uri=self.oauth_callback_url,
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
