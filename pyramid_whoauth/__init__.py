"""
repoze.who auth plugins for pyramid.
"""

from zope.interface import implements

from pyramid.interfaces import IAuthenticationPolicy
from pyramid.security import Everyone, Authenticated
from pyramid.httpexceptions import HTTPFound
from pyramid.response import Response

from repoze.who.config import WhoConfig
from repoze.who.api import APIFactory
from repoze.who.utils import resolveDotted


def _null_callback(userid, request):
    """Default group-finder callback for WhoAuthenticationPolicy."""
    return ()


class WhoAuthenticationPolicy(object):
    """Pyramid authentication policy built on top of repoze.who.

    This is a pyramid authentication policy built on top of the repoze.who
    API.  It's a lot like the one found in the "pyramid_who" package, but
    has some API tweaks, more configuration options and some default views.
    """

    implements(IAuthenticationPolicy)

    def __init__(self, api_factory, callback=None):
        if callback is None:
            callback = _null_callback
        self._api_factory = api_factory
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
        callback = who_settings.get("config_file")
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
            try:
                section, var = name.rsplit(".", 1)
            except ValueError:
                pass
            else:
                who_ini_lines.append("[%s]" % (section.replace(".", ":"),))
                who_ini_lines.append("%s = %s" % (var, value))
        # Now we can parse that config using who's own machinery.
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
        userid = self.unauthenticated_userid(request)
        if userid is None:
            return None
        if self._callback(userid, request) is None:
            return None
        return userid

    def unauthenticated_userid(self, request):
        identity = request.environ.get("repoze.who.identity")
        if identity is None:
            api = self._api_factory(request.environ)
            identity = api.authenticate()
        if identity is None:
            return None
        return identity["repoze.who.userid"]

    def effective_principals(self, request):
        principals = [Everyone]
        userid = self.unauthenticated_userid(request)
        if userid is None:
            return principals
        groups = self._callback(userid, request)
        if groups is None:
            return principals
        principals.append(userid)
        principals.append(Authenticated)
        principals.extend(groups)
        return principals

    def remember(self, request, principal, **kw):
        headers = []
        identity = {"repoze.who.userid": principal}
        api = self._api_factory(request.environ)
        #  Give all IIdentifiers a chance to remember the login.
        #  This is the same logic as inside the api.login() method,
        #  but without repeating the authentication step.
        for name, plugin in api.identifiers:
            i_headers = plugin.remember(request.environ, identity)
            if i_headers is not None:
                headers.extend(i_headers)
        return headers

    def forget(self, request):
        api = self._api_factory(request.environ)
        return api.logout() or []

    def challenge_view(self, request):
        """View that challenges for credentials using repoze.who.

        This method provides a pyramid view that uses the repoze.who challenge
        API to prompt for credentials.  If no challenge can be generated then
        it displays a "403 Forbidden" page.
        """
        api = self._api_factory(request.environ)
        challenge_app = api.challenge()
        if challenge_app is not None:
            return request.get_response(challenge_app)
        return Response("<h1>Forbidden</h1>", status="403 Forbidden")

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
            api = self._api_factory(request.environ)
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


def includeme(config):
    """Include default whoauth settings into a pyramid config.

    This function provides a hook for pyramid to include the default settings
    for auth via repoze.who.  Activate it like so:

        config.include("pyramid_whoauth")

    It will set up the following defaults for you:

        * add a repoze.who-based AuthenticationPolicy.
        * add a "forbidden view" to invoke repoze.who when auth is required.
        * default "login" and "logout" routes and views.

    """
    # Extract repoze.who settings from the pyramid-wide settings,
    # and use them to construct an AuthenticationPolicy.
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
