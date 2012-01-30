# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

IAuthenticationPolicy implementation for pyramid_whoauth

"""

from zope.interface import implements

from pyramid.interfaces import IAuthenticationPolicy
from pyramid.security import Everyone, Authenticated

from repoze.who.utils import resolveDotted

from pyramid_whoauth.utils import (get_api, api_factory_from_settings,
                                   ApplicationRedirectException)


def _null_callback(userid, request):
    """Default group-finder callback for WhoAuthenticationPolicy."""
    return ()


class WhoAuthenticationPolicy(object):
    """Pyramid authentication policy built on top of repoze.who.

    This is a pyramid authentication policy built on top of the repoze.who
    API.  It takes a repoze.who API factory and an optional groupfinder
    callback, and does a straightforward transformation between the repoze.who
    API methods and those of pyramid.
    """

    implements(IAuthenticationPolicy)

    def __init__(self, api_factory=None, callback=None):
        if callback is None:
            callback = _null_callback
        self.api_factory = api_factory
        self._callback = callback

    @classmethod
    def from_settings(cls, settings, prefix="who."):
        """Create a new WhoAuthenticationPolicy from app settings dict."""
        api_factory = api_factory_from_settings(settings, prefix)
        callback = settings.get(prefix + "callback")
        if callback is not None:
            callback = resolveDotted(callback)
            if callback is not None:
                assert callable(callback)
        return cls(api_factory, callback)

    def authenticated_userid(self, request):
        """Get the authenticated userid for the given request.

        This method extracts the userid from the request and passes it
        through two levels of authentication - the repoze.who authenticate
        method, and the configured groupfinder callback.
        """
        userid = self.unauthenticated_userid(request)
        if userid is None:
            return None
        if self._callback(userid, request) is None:
            return None
        return userid

    def unauthenticated_userid(self, request):
        """Get the unauthenticated userid for the given request.

        This method extracts the claimed userid from the request.  Since
        repoze.who does not provide an API to extract the userid without
        authenticating it, the only different between this method and the
        authenticated version is that it does not invoke the groupfinder
        callback function.
        """
        identity = request.environ.get("repoze.who.identity")
        if identity is None:
            api = get_api(request, self.api_factory)
            # Call the repoze.who API to authenticate.
            # If it sets environ["repoze.who.application"] then raise an
            # exception so that this can be taken care of upstream.
            app = request.environ.get("repoze.who.application")
            identity = api.authenticate()
            if app is not request.environ.get("repoze.who.application"):
                raise ApplicationRedirectException
            if identity is None:
                return None
        return identity["repoze.who.userid"]

    def effective_principals(self, request):
        """Get the list of effective principals for the given request.

        This method combines the authenticated userid returned by repoze.who
        with the list of groups returned by the groupfinder callback, if any.
        """
        principals = [Everyone]
        userid = self.unauthenticated_userid(request)
        if userid is None:
            return principals
        groups = self._callback(userid, request)
        if groups is None:
            return principals
        principals.insert(0, userid)
        principals.append(Authenticated)
        principals.extend(groups)
        return principals

    def remember(self, request, principal, **kw):
        """Get headers to remember the given principal.

        This method calls the remember() method on all configured repoze.who
        plugins, and returns the combined list of headers.
        """
        identity = {"repoze.who.userid": principal}
        api = get_api(request, self.api_factory)
        #  Give all IIdentifiers a chance to remember the login.
        #  This is the same logic as inside the api.login() method,
        #  but without repeating the authentication step.
        headers = []
        for name, plugin in api.identifiers:
            i_headers = plugin.remember(request.environ, identity)
            if i_headers is not None:
                headers.extend(i_headers)
        return headers

    def forget(self, request):
        """Get headers to forget the identify of the given request.

        This method calls the repoze.who logout() method, which in turn calls
        the forget() method on all configured repoze.who plugins.
        """
        api = get_api(request, self.api_factory)
        return api.logout() or []
