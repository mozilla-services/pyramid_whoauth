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
"""

repoze.who auth policy for pyramid.

"""

__ver_major__ = 0
__ver_minor__ = 1
__ver_patch__ = 0
__ver_sub__ = ""
__ver_tuple__ = (__ver_major__, __ver_minor__, __ver_patch__, __ver_sub__)
__version__ = "%d.%d.%d%s" % __ver_tuple__


from zope.interface import implements

from pyramid.interfaces import IAuthenticationPolicy
from pyramid.security import Everyone, Authenticated
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.httpexceptions import HTTPFound
from pyramid.response import Response

from repoze.who.config import WhoConfig
from repoze.who.api import APIFactory, IAPIFactory, get_api
from repoze.who.utils import resolveDotted


def _null_callback(userid, request):
    """Default group-finder callback for WhoAuthenticationPolicy."""
    return ()


class WhoAuthenticationPolicy(object):
    """Pyramid authentication policy built on top of repoze.who.

    This is a pyramid authentication policy built on top of the repoze.who
    API.  It takes a repoze.who API factory and an optional groupfinder
    callback, and does a straightforward transformation between the repoze.who
    API methods and those of pyramid.

    This class also provides some convenience methods which you may use as
    required for your application:

        * challenge_view:  a pyramid view that challenges for credentials
                           by calling into the repoze.who API.

        * login_view:  a view that authenticates its POST parameters via
                       repoze.who and then redirects.

        * logout_view:  a view that issues forget headers from repoze.who
                        and then redirects.

    """

    implements(IAuthenticationPolicy)

    def __init__(self, api_factory, callback=None):
        if callback is None:
            callback = _null_callback
        self.api_factory = api_factory
        self._callback = callback

    @classmethod
    def from_settings(cls, settings, prefix="who."):
        """Create a new WhoAuthenticationPolicy from app settings dict."""
        # Grab out all the settings keys that start with our prefix.
        who_settings = {}
        for name, value in settings.iteritems():
            if not name.startswith(prefix):
                continue
            who_settings[name[len(prefix):]] = value
        # Load the callback function if specified.
        callback = who_settings.get("callback")
        if callback is not None:
            callback = resolveDotted(callback)
            if callback is not None:
                assert callable(callback)
        # Construct a who.ini config file in memory.
        # First, read in any config file specified in the settings.
        who_ini_lines = []
        if "config_file" in who_settings:
            with open(who_settings["config_file"], "r") as f:
                who_ini_lines.extend(ln.strip() for ln in f)
        # Format any dotted setting names into an ini-file section.
        # For example, a settings file line like:
        #    who.identifiers.plugins = blah
        # Will become an ini-file entry like:
        #    [identifiers]
        #    plugins = blah
        for name, value in who_settings.iteritems():
            if isinstance(value, (list, tuple)):
                value = " ".join(value)
            else:
                value = str(value)
            try:
                section, var = name.rsplit(".", 1)
            except ValueError:
                pass
            else:
                who_ini_lines.append("[%s]" % (section.replace(".", ":"),))
                who_ini_lines.append("%s = %s" % (var, value))
        # Now we can parse that config using repoze.who's own machinery.
        parser = WhoConfig(who_settings.get("here", ""))
        parser.parse("\n".join(who_ini_lines))

        api_factory = APIFactory(parser.identifiers,
                                 parser.authenticators,
                                 parser.challengers,
                                 parser.mdproviders,
                                 parser.request_classifier,
                                 parser.challenge_decider)

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
        authentication version is that it does not invoke the groupfinder
        callback function.
        """
        identity = request.environ.get("repoze.who.identity")
        if identity is None:
            api = self.api_factory(request.environ)
            identity = api.authenticate()
            if identity is None:
                return None
        return identity["repoze.who.userid"]

    def effective_principals(self, request):
        """Get the list of effective principals for the given request.

        This method combines the authenticated userid return by repoze.who
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
        api = self.api_factory(request.environ)
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
        api = self.api_factory(request.environ)
        return api.logout() or []

    def challenge_view(self, request, *challenge_args):
        """View that challenges for credentials using repoze.who.

        This method provides a pyramid view that uses the repoze.who challenge
        API to prompt for credentials.  If no challenge can be generated then
        it displays a "403 Forbidden" page.
        """
        api = self.api_factory(request.environ)
        challenge_app = api.challenge(*challenge_args)
        if challenge_app is not None:
            response = request.get_response(challenge_app)
        else:
            response = Response("<h1>Forbidden</h1>", status="403 Forbidden")
        # Make sure all IIdentifier plugins forget the login.
        response.headerlist.extend(self.forget(request))
        return response

    def login_view(self, request):
        """View to process login credentials and remember the user.

        This method provides a pyramid view that uses the repoze.who API
        to authenticate any submitted credentials, then redirects to
        whatever page the user was trying to view.  You can use it as
        a convenient redirection point for plugins that need to submit
        credentials via POST.
        """
        came_from = request.params.get("came_from", request.referer or "/")
        # Try to authenticate, either via standard plugin auth
        # or by using the request parameters at the identity.
        userid = self.authenticated_userid(request)
        if userid is not None:
            headers = self.remember(request, userid)
        else:
            api = self.api_factory(request.environ)
            userid, headers = api.login(dict(request.params))
        # If that worked, send them back to where they came from.
        # If not, render the usual challenge view.
        if userid is None:
            return self.challenge_view(request)
        return HTTPFound(location=came_from, headers=headers)

    def logout_view(self, request):
        """View to forget the logged-in user.

        This method provides a pyramid view that uses the repoze.who API
        to forget any remembered credentials.
        """
        came_from = request.params.get("came_from", request.referer or "/")
        headers = self.forget(request)
        return HTTPFound(location=came_from, headers=headers)


def whoauth_tween_factory(handler, registry):
    """Tween factory for managing repoze.who egress hooks.

    This is a pyramid tween factory that duplicates the egress logic from
    the repoze.who middleware.  Its responsibilities include:

        * calling the challenge decider, and:
            * if a challenge is not necessary, sending remember headers
            * if a challenge is necessary, sending the appropriate response

    """
    # Find an appropriate API factory.
    # With luck one has been registered into the application regsitry.
    # Failing that, we look on the registered IAuthenticationPolicy.
    # Failing even that, we fall back to looking in the request environ.
    api_factory = registry.queryUtility(IAPIFactory)
    if api_factory is None:
        authn_policy = registry.queryUtility(IAuthenticationPolicy)
        if authn_policy is not None:
            api_factory = getattr(authn_policy, "api_factory", None)
        if api_factory is None:
            api_factory = get_api

    # Create and return the tween.
    def whoauth_tween(request):
        response = handler(request)
        api = api_factory(request.environ)
        if api is not None:
            # Remember the identity if there is one.
            # This depends on the app calling api.logout() for a challenge
            # view, so that the identity is removed from the environ and we
            # don't end up sending conflicting headers.
            identity = request.environ.get("repoze.who.identity", {})
            #  Give all IIdentifiers a chance to remember the login.
            #  This is the same logic as inside the api.login() method,
            #  but without repeating the authentication step.
            for name, plugin in api.identifiers:
                i_headers = plugin.remember(request.environ, identity)
                if i_headers is not None:
                    response.headerlist.extend(i_headers)
        return response

    return whoauth_tween


def includeme(config):
    """Include default whoauth settings into a pyramid config.

    This function provides a hook for pyramid to include the default settings
    for auth via repoze.who.  Activate it like so:

        config.include("pyramid_whoauth")

    It will set up the following defaults for you:

        * add a repoze.who-based AuthenticationPolicy.
        * add a "forbidden view" to invoke repoze.who when auth is required.
        * add default "login" and "logout" routes and views.
        * add a tween to call remember() or challenge() on response egress.

    """
    # Hook up a default AuthorizationPolicy.
    # ACLAuthorizationPolicy is usually what you want.
    # If the app configures one explicitly then this will get overridden.
    # In auto-commit mode this needs to be set for adding an authn policy.
    authz_policy = ACLAuthorizationPolicy()
    config.set_authorization_policy(authz_policy)

    # Build a WhoAuthenticationPolicy from the deployment settings.
    settings = config.get_settings()
    authn_policy = WhoAuthenticationPolicy.from_settings(settings)
    config.set_authentication_policy(authn_policy)

    # Hook up the policy's challenge_view as the "forbidden view"
    config.add_view(authn_policy.challenge_view,
                    context="pyramid.exceptions.Forbidden")

    # Hook up the policy's login_view using configured path and route name.
    login_route = settings.get("who.login_route", "login")
    login_path = settings.get("who.login_path", "/login")
    config.add_route(login_route, login_path)
    config.add_view(authn_policy.login_view,
                    route_name=login_route)

    # Hook up the policy's logout_view using configured path and route name.
    logout_route = settings.get("who.logout_route", "logout")
    logout_path = settings.get("who.logout_path", "/logout")
    config.add_route(logout_route, logout_path)
    config.add_view(authn_policy.logout_view,
                    route_name=logout_route)

    # Set up a tween to call remember() or challenge() on egress.
    # Store the APIFactory on the registry for easy access.
    def register_api_factory():
        config.registry.registerUtility(authn_policy.api_factory, IAPIFactory)
    config.action(IAPIFactory, register_api_factory)
    config.add_tween("pyramid_whoauth.whoauth_tween_factory")
