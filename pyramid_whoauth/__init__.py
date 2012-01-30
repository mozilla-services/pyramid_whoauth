# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

Pyramid authentication policy build on repoze.who.

"""

__ver_major__ = 0
__ver_minor__ = 1
__ver_patch__ = 1
__ver_sub__ = ""
__ver_tuple__ = (__ver_major__, __ver_minor__, __ver_patch__, __ver_sub__)
__version__ = "%d.%d.%d%s" % __ver_tuple__


from repoze.who.api import IAPIFactory

from pyramid.authorization import ACLAuthorizationPolicy

from pyramid_whoauth import utils, auth, views


def includeme(config):
    """Include default whoauth settings into a pyramid config.

    This function provides a hook for pyramid to include the default settings
    for auth via repoze.who.  Activate it like so:

        config.include("pyramid_whoauth")

    It will set up the following defaults for you:

        * add a repoze.who-based AuthenticationPolicy.
        * add a "forbidden view" to invoke repoze.who when auth is required.
        * add default "login" and "logout" routes and views.
        * add a tween to call remember() on response egress.

    """
    # Hook up a default AuthorizationPolicy.
    # ACLAuthorizationPolicy is usually what you want.
    # If the app configures one explicitly then this will get overridden.
    # In auto-commit mode this needs to be set before adding an authn policy.
    authz_policy = ACLAuthorizationPolicy()
    config.set_authorization_policy(authz_policy)

    # Build a WhoAuthenticationPolicy from the deployment settings.
    settings = config.get_settings()
    authn_policy = auth.WhoAuthenticationPolicy.from_settings(settings)
    config.set_authentication_policy(authn_policy)

    # Register the API Factory for other components to find.
    def register_api_factory():
        utils.register_api_factory(config.registry, authn_policy.api_factory)
    config.action(IAPIFactory, register_api_factory)

    # Hook up the challenge view as pyramid's "forbidden view"
    config.add_view(views.challenge, context="pyramid.exceptions.Forbidden")

    # Hook up the login view using configured path and route name.
    login_route = settings.get("who.login_route", "login")
    login_path = settings.get("who.login_path", "/login")
    config.add_route(login_route, login_path)
    config.add_view(views.login, route_name=login_route)

    # Hook up the logout view using configured path and route name.
    logout_route = settings.get("who.logout_route", "logout")
    logout_path = settings.get("who.logout_path", "/logout")
    config.add_route(logout_route, logout_path)
    config.add_view(views.logout, route_name=logout_route)

    # Set up a tween to handle response egress.
    config.add_tween("pyramid_whoauth.tweens.whoauth_tween_factory")
