import unittest2

from pyramid.testing import DummyRequest
from pyramid.security import Everyone, Authenticated

from zope.interface import implements
from repoze.who.interfaces import IAuthenticator

from pyramid_whoauth import WhoAuthenticationPolicy


class DummyAuthenticator(object):
    """Authenticator that accepts any and all login credentials."""
    implements(IAuthenticator)
    def authenticate(self, environ, identity):
        return identity.get("login")


class WhoAuthPolicyTests(unittest2.TestCase):
    pass
