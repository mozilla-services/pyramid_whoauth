# ***** BEGIN LICENSE BLOCK *****
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is pyramid_whoauth
#
# The Initial Developer of the Original Code is the Mozilla Foundation.
# Portions created by the Initial Developer are Copyright (C) 2011
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   Ryan Kelly (rkelly@mozilla.com)
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.
#
# ***** END LICENSE BLOCK *****

import unittest2
import base64

import pyramid.testing
from pyramid.testing import DummyRequest
from pyramid.security import Everyone, Authenticated
from pyramid.interfaces import IAuthenticationPolicy

from zope.interface import implements
from repoze.who.interfaces import IAuthenticator


class DummyAuthenticator(object):
    """Authenticator that accepts login and password."""
    implements(IAuthenticator)
    def authenticate(self, environ, identity):  # NOQA
        if identity.get("login") == identity.get("password"):
            return identity.get("login")


def groupfinder(userid, request):
    """Groupfinder that only recognised the "test" user."""
    if userid != "test":
        return None
    return ["group"]


GOOD_AUTHZ = {
  "test": "Basic " + base64.b64encode("test:test"),
  "test2": "Basic " + base64.b64encode("test2:test2")
}

BAD_AUTHZ = {
  "test": "Basic " + base64.b64encode("test:badpwd"),
  "test2": "Basic " + base64.b64encode("test2:horseyhorseyneigh")
}

SETTINGS = {
    "who.callback": "pyramid_whoauth.tests:groupfinder",
    "who.plugin.basicauth.use": "repoze.who.plugins.basicauth:make_plugin",
    "who.plugin.basicauth.realm": "MyRealm",
    "who.plugin.authtkt.use": "repoze.who.plugins.auth_tkt:make_plugin",
    "who.plugin.authtkt.secret": "Oh So Secret!",
    "who.plugin.dummy.use": "pyramid_whoauth.tests:DummyAuthenticator",
    "who.identifiers.plugins": "authtkt basicauth",
    "who.authenticators.plugins": ["authtkt", "dummy"],
    "who.challengers.plugins": "basicauth"
}


def make_request(**kwds):
    environ = {}
    environ["wsgi.version"] = (1, 0)
    environ["wsgi.url_scheme"] = "http"
    environ["SERVER_NAME"] = "localhost"
    environ["SERVER_PORT"] = "80"
    environ["REQUEST_METHOD"] = "GET"
    environ["SCRIPT_NAME"] = ""
    environ["PATH_INFO"] = "/"
    environ.update(kwds)
    return DummyRequest(environ=environ)


class WhoAuthPolicyTests(unittest2.TestCase):
    def setUp(self):
        self.config = pyramid.testing.setUp(autocommit=False)
        self.config.add_settings(**SETTINGS)
        self.config.include("pyramid_whoauth")
        self.config.commit()

    def tearDown(self):
        pyramid.testing.tearDown()

    def test_authenticated_userid(self):
        policy = self.config.registry.getUtility(IAuthenticationPolicy)
        # Authenticated and found by groupfinder.
        req = make_request(HTTP_AUTHORIZATION=GOOD_AUTHZ["test"])
        self.assertEquals(policy.authenticated_userid(req), "test")
        # Authenticated but not found by groupfinder.
        req = make_request(HTTP_AUTHORIZATION=GOOD_AUTHZ["test2"])
        self.assertEquals(policy.authenticated_userid(req), None)
        # Not authenticated
        req = make_request(HTTP_AUTHORIZATION=BAD_AUTHZ["test2"])
        self.assertEquals(policy.authenticated_userid(req), None)

    def test_unauthenticated_userid(self):
        policy = self.config.registry.getUtility(IAuthenticationPolicy)
        # Authenticated and found by groupfinder.
        req = make_request(HTTP_AUTHORIZATION=GOOD_AUTHZ["test"])
        self.assertEquals(policy.unauthenticated_userid(req), "test")
        # Authenticated but not found by groupfinder.
        req = make_request(HTTP_AUTHORIZATION=GOOD_AUTHZ["test2"])
        self.assertEquals(policy.unauthenticated_userid(req), "test2")
        # Not authenticated
        req = make_request(HTTP_AUTHORIZATION=BAD_AUTHZ["test2"])
        self.assertEquals(policy.unauthenticated_userid(req), None)

    def test_effective_principals(self):
        policy = self.config.registry.getUtility(IAuthenticationPolicy)
        # Authenticated and found by groupfinder.
        req = make_request(HTTP_AUTHORIZATION=GOOD_AUTHZ["test"])
        self.assertEquals(sorted(policy.effective_principals(req)),
                          ["group", Authenticated, Everyone, "test"])
        # Authenticated but not found by groupfinder.
        req = make_request(HTTP_AUTHORIZATION=GOOD_AUTHZ["test2"])
        self.assertEquals(sorted(policy.effective_principals(req)),
                          [Everyone])
        # Not authenticated.
        req = make_request(HTTP_AUTHORIZATION=BAD_AUTHZ["test2"])
        self.assertEquals(sorted(policy.effective_principals(req)),
                          [Everyone])

    def test_remember(self):
        policy = self.config.registry.getUtility(IAuthenticationPolicy)
        req = make_request(HTTP_AUTHORIZATION=GOOD_AUTHZ["test"])
        headers = policy.remember(req, "test")
        for name, value in headers:
            self.assertEquals(name, "Set-Cookie")
            self.assertTrue(value.startswith("auth_tkt="))

    def test_forget(self):
        policy = self.config.registry.getUtility(IAuthenticationPolicy)
        req = make_request(HTTP_AUTHORIZATION=GOOD_AUTHZ["test"])
        headers = policy.forget(req)
        for name, value in headers[:-1]:
            self.assertEquals(name, "Set-Cookie")
            self.assertTrue(value.startswith("auth_tkt="))
        self.assertEquals(headers[-1][0], "WWW-Authenticate")
        self.assertEquals(headers[-1][1], "Basic realm=\"MyRealm\"")
