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
import tempfile
import base64
from textwrap import dedent

import pyramid.testing
from pyramid.testing import DummyRequest
from pyramid.security import Everyone, Authenticated, authenticated_userid
from pyramid.interfaces import IAuthenticationPolicy, IRequest
from pyramid.response import Response
from pyramid.router import Router
from pyramid.exceptions import Forbidden

from zope.interface import implements
from repoze.who.interfaces import IAuthenticator, IIdentifier, IAPIFactory

from pyramid_whoauth import WhoAuthenticationPolicy, whoauth_tween_factory


class DummyAuthenticator(object):
    """Authenticator that accepts login and password."""

    implements(IAuthenticator)

    def authenticate(self, environ, identity):  # NOQA
        if identity.get("login") == identity.get("password"):
            return identity.get("login")


class DummyRememberer(object):
    """Identifier that sets some dummy headers."""

    implements(IIdentifier)

    def identify(self, environ):
        return None

    def remember(self, environ, identity):
        if identity:
            return [("X-Dummy-Remember", "DUMMY")]

    def forget(self, environ, identity):
        return [("X-Dummy-Forget", "DUMMY")]


def groupfinder(userid, request):
    """Groupfinder that only recognised the "test" user."""
    if userid != "test":
        return None
    return ["group"]


GOOD_AUTHZ = {
  "test": "Basic " + base64.b64encode("test:test"),
  "test2": "Basic " + base64.b64encode("test2:test2")}

BAD_AUTHZ = {
  "test": "Basic " + base64.b64encode("test:badpwd"),
  "test2": "Basic " + base64.b64encode("test2:horseyhorseyneigh")}

SETTINGS = {
    "who.callback": "pyramid_whoauth.tests:groupfinder",
    "who.plugin.basicauth.use": "repoze.who.plugins.basicauth:make_plugin",
    "who.plugin.basicauth.realm": "MyRealm",
    "who.plugin.dummyauth.use": "pyramid_whoauth.tests:DummyAuthenticator",
    "who.plugin.dummyid.use": "pyramid_whoauth.tests:DummyRememberer",
    "who.identifiers.plugins": "dummyid basicauth",
    "who.authenticators.plugins": ["dummyauth"],
    "who.challengers.plugins": "basicauth"}


def raise_forbidden(request):
    """View that always just raises Forbidden."""
    raise Forbidden()


def return_ok(request):
    """View that always just returns "OK" as a string."""
    authenticated_userid(request)
    return Response("OK")


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
        self.config.add_route("forbidden", path="/forbidden")
        self.config.add_view(raise_forbidden, route_name="forbidden")
        self.config.add_route("ok", path="/ok")
        self.config.add_view(return_ok, route_name="ok")
        self.config.commit()

    def tearDown(self):
        pyramid.testing.tearDown()

    def assertHeadersContain(self, headers, expect_name, expect_value=None):
        for name, value in headers:
            if name == expect_name:
                if expect_value is not None:
                    self.failUnless(expect_value in value)
                break
        else:
            msg = "No %r header was issued"     # pragma: nocover
            assert False, msg % (expect_name,)  # pragma: nocover

    def failIfHeadersContain(self, headers, expect_name, expect_value=None):
        for name, value in headers:
            if name == expect_name:
                if expect_value is None:                     # pragma: nocover
                    msg = "Header %r was present"            # pragma: nocover
                    assert False, msg % (expect_name,)       # pragma: nocover
                elif expect_value in value:                  # pragma: nocover
                    msg = "Header %r contained value %r"     # pragma: nocover
                    msg = msg % (expect_name, expect_value)  # pragma: nocover
                    assert False, msg                        # pragma: nocover

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
        self.assertEquals(len(headers), 1)
        self.assertEquals(headers[0][0], "X-Dummy-Remember")
        self.assertEquals(headers[0][1], "DUMMY")

    def test_forget(self):
        policy = self.config.registry.getUtility(IAuthenticationPolicy)
        req = make_request(HTTP_AUTHORIZATION=GOOD_AUTHZ["test"])
        headers = policy.forget(req)
        print headers
        self.assertEquals(len(headers), 2)
        self.assertEquals(headers[0][0], "X-Dummy-Forget")
        self.assertEquals(headers[0][1], "DUMMY")
        self.assertEquals(headers[1][0], "WWW-Authenticate")
        self.assertEquals(headers[1][1], "Basic realm=\"MyRealm\"")

    def test_default_groupfinder(self):
        settings = SETTINGS.copy()
        del settings["who.callback"]
        policy = WhoAuthenticationPolicy.from_settings(settings)
        req = make_request(HTTP_AUTHORIZATION=GOOD_AUTHZ["test"])
        self.assertEquals(sorted(policy.effective_principals(req)),
                          [Authenticated, Everyone, "test"])

    def test_settings_from_config_file(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(dedent("""
            [plugin:basicauth]
            use = repoze.who.plugins.basicauth:make_plugin
            realm = SomeRealm
            [plugin:dummy]
            use = pyramid_whoauth.tests:DummyAuthenticator
            [identifiers]
            plugins = basicauth
            [authenticators]
            plugins = dummy
            [challengers]
            plugins = basicauth
            """))
            f.flush()
            settings = {"who.config_file": f.name}
            policy = WhoAuthenticationPolicy.from_settings(settings)
            req = make_request(HTTP_AUTHORIZATION=GOOD_AUTHZ["test"])
            self.assertEquals(policy.authenticated_userid(req), "test")

    def test_challenge_view_gets_invoked(self):
        app = self.config.make_wsgi_app()
        req = make_request(PATH_INFO="/forbidden")
        def start_response(status, headers):  # NOQA
            self.assertEquals(status, "401 Unauthorized")
            self.assertHeadersContain(headers, "WWW-Authenticate", "MyRealm")
        "".join(app(req.environ, start_response))

    def test_challenge_view_with_no_challengers(self):
        policy = self.config.registry.getUtility(IAuthenticationPolicy)
        del policy.api_factory.challengers[:]
        app = self.config.make_wsgi_app()
        req = make_request(PATH_INFO="/forbidden")
        def start_response(status, headers):  # NOQA
            self.assertEquals(status, "403 Forbidden")
        "".join(app(req.environ, start_response))

    def test_login_view(self):
        app = self.config.make_wsgi_app()

        #  Requesting the login view with no credentials gives a challenge.
        req = make_request(PATH_INFO="/login",
                           QUERY_STRING="came_from=/somewhere")
        def start_response(status, headers):  # NOQA
            self.assertEquals(status, "401 Unauthorized")
            self.assertHeadersContain(headers, "WWW-Authenticate", "MyRealm")
        "".join(app(req.environ, start_response))

        #  Requesting the login view with basic-auth creds gives a redirect
        req = make_request(PATH_INFO="/login",
                           HTTP_AUTHORIZATION=GOOD_AUTHZ["test"],
                           QUERY_STRING="came_from=/somewhere")
        def start_response(status, headers):  # NOQA
            self.assertEquals(status, "302 Found")
            self.assertHeadersContain(headers, "Location", "/somewhere")
        "".join(app(req.environ, start_response))

        #  Requesting the login view with creds in params gives a redirect
        query_string = "came_from=/somewhere&login=test&password=test"
        req = make_request(PATH_INFO="/login",
                           QUERY_STRING=query_string)
        def start_response(status, headers):  # NOQA
            self.assertEquals(status, "302 Found")
            self.assertHeadersContain(headers, "Location", "/somewhere")
        "".join(app(req.environ, start_response))

        #  Requesting the login view with bad creds gives a challenge
        req = make_request(PATH_INFO="/login",
                           HTTP_AUTHORIZATION=BAD_AUTHZ["test"],
                           QUERY_STRING="came_from=/somewhere_outthere")
        def start_response(status, headers):  # NOQA
            self.assertEquals(status, "401 Unauthorized")
            self.assertHeadersContain(headers, "WWW-Authenticate", "MyRealm")
        "".join(app(req.environ, start_response))

    def test_logout_view(self):
        app = self.config.make_wsgi_app()

        #  Requesting the logout view with no creds gives challenge+redirect.
        req = make_request(PATH_INFO="/logout",
                           QUERY_STRING="came_from=/somewhere")
        def start_response(status, headers):  # NOQA
            self.assertEquals(status, "302 Found")
            self.assertHeadersContain(headers, "Location", "/somewhere")
            self.assertHeadersContain(headers, "WWW-Authenticate", "MyRealm")
        "".join(app(req.environ, start_response))

        #  Requesting the logout view with creds gives challenge+redirect.
        req = make_request(PATH_INFO="/logout",
                           HTTP_AUTHORIZATION=GOOD_AUTHZ["test"],
                           QUERY_STRING="came_from=/somewhere")
        def start_response(status, headers):  # NOQA
            self.assertEquals(status, "302 Found")
            self.assertHeadersContain(headers, "Location", "/somewhere")
            self.assertHeadersContain(headers, "WWW-Authenticate", "MyRealm")
        "".join(app(req.environ, start_response))

    def test_tween_sets_remember_headers(self):
        app = self.config.make_wsgi_app()

        #  Requesting a view with no creds should not try to remember me
        req = make_request(PATH_INFO="/ok")
        def start_response(status, headers):  # NOQA
            self.assertEquals(status, "200 OK")
            self.failIfHeadersContain(headers, "X-Dummy-Remember")
        "".join(app(req.environ, start_response))

        #  Requesting a view with bad creds should not try to remember me
        req = make_request(PATH_INFO="/ok",
                           HTTP_AUTHORIZATION=BAD_AUTHZ["test"])
        def start_response(status, headers):  # NOQA
            self.assertEquals(status, "200 OK")
            self.failIfHeadersContain(headers, "X-Dummy-Remember")
        "".join(app(req.environ, start_response))

        #  Requesting a view with good creds should try to remember me
        req = make_request(PATH_INFO="/ok",
                           HTTP_AUTHORIZATION=GOOD_AUTHZ["test"])
        def start_response(status, headers):  # NOQA
            self.assertEquals(status, "200 OK")
            self.assertHeadersContain(headers, "X-Dummy-Remember", "DUMMY")
        "".join(app(req.environ, start_response))

    def test_tween_factory_can_find_api_factory(self):
        registry = self.config.registry
        router = Router(registry)
        # This palaver is necessary to call the tween directly.
        def _make_request(**environ):  # NOQA
            req = make_request(**environ)
            req.__dict__["request_iface"] = IRequest
            req.__dict__["registry"] = registry
            return req
        # Create the factory with no IAPIFactory registered.
        # It should look up the api factory on the auth policy itself.
        registry.registerUtility(None, IAPIFactory)
        tween = whoauth_tween_factory(router.handle_request, registry)
        req = _make_request(PATH_INFO="/ok",
                            HTTP_AUTHORIZATION=GOOD_AUTHZ["test"])
        response = tween(req)
        self.assertHeadersContain(response.headerlist, "X-Dummy-Remember")
        # Create the factory with no authentication policy registered.
        # It should grab the api from the request environ.
        policy = registry.getUtility(IAuthenticationPolicy)
        registry.registerUtility(None, IAuthenticationPolicy)
        tween = whoauth_tween_factory(router.handle_request, registry)
        registry.registerUtility(policy, IAuthenticationPolicy)
        req = _make_request(PATH_INFO="/ok",
                            HTTP_AUTHORIZATION=GOOD_AUTHZ["test"])
        response = tween(req)
        self.assertHeadersContain(response.headerlist, "X-Dummy-Remember")
