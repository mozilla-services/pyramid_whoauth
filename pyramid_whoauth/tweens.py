# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

Tween implementation for pyramid_whoauth.

"""

from pyramid import security
from pyramid.exceptions import NotFound

from pyramid_whoauth.utils import get_api, ApplicationRedirectException


def whoauth_tween_factory(handler, registry):
    """Tween factory for managing repoze.who egress hooks.

    This is a pyramid tween factory that emulates some of the response egress
    hooks from the repoze.who middleware.  In particular:

        * handling plugins that set environ["repoze.who.application"]
        * calling remember() on each authenticated response

    It's useful for compatability with repoze.who plugins that rely on these
    particular behaviours from the middleware, e.g. the OpenID plugin which
    manages its own redirects internally.

    You don't need this if you're actually using the repoze.who middleware
    as a wrapper around your pyramid application.

    This tween does *not* use the challenge decider or issue challenges, since
    pyramid has its own way of doing that.
    """

    def whoauth_tween(request):
        # We have nothing to do on ingress, since the application will call
        # into the repoze.who API as it needs.  Just call the downstream app.
        try:
            # If we're asked to access a non-existent URL, it might be
            # a repoze.who plugin trying to do an internal redirection.
            # to an unknown URL.  Trigger the AuthnPolicy so that it gets
            # a chance to set things up and raise ApplicationRedirectException.
            try:
                response = handler(request)
            except NotFound:
                if "repoze.who.api" not in request.environ:
                    security.unauthenticated_userid(request)
                raise
            else:
                if response.status.startswith("404 "):
                    if "repoze.who.api" not in request.environ:
                        security.unauthenticated_userid(request)
        except ApplicationRedirectException:
            # The AuthnPolicy throws this to indicate that a plugin wants to
            # take control of the response.  Respect any WSGI app that it
            # has put into environ["repoze.who.application"]
            app = request.environ["repoze.who.application"]
            response = request.get_response(app)
        # If there is an identity, make sure it gets remembered.
        # Some plugins depend on this being called on every response rather
        # than explicitly when a new identity is issued.
        identity = request.environ.get("repoze.who.identity")
        if identity:
            api = get_api(request)
            # Give all plugins a chance to remember the login if there is one.
            for name, plugin in api.identifiers:
                i_headers = plugin.remember(request.environ, identity)
                if i_headers is not None:
                    response.headerlist.extend(i_headers)
        return response

    return whoauth_tween
