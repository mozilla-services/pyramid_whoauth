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
