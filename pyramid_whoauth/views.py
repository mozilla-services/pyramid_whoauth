# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

Generic view functions for pyramid_whoauth.

"""

from pyramid import security
from pyramid.httpexceptions import HTTPFound, HTTPForbidden
from pyramid.response import Response

from pyramid_whoauth.utils import get_api


def challenge(request, *challenge_args):
    """View that challenges for credentials using repoze.who.

    This method provides a pyramid view that uses the repoze.who challenge
    API to prompt for credentials.  If no challenge can be generated then
    it displays a "403 Forbidden" page.

    You might like to use this as pyramid's "Forbidden View".
    """
    response = None
    api = get_api(request)
    challenge_app = api.challenge(*challenge_args)
    if challenge_app is not None:
        response = request.get_response(challenge_app)
    else:
        response = Response("<h1>Forbidden</h1>", status="403 Forbidden")
    response.headerlist.extend(security.forget(request))
    return response


def login(request):
    """View to process login credentials and remember the user.

    This method provides a pyramid view that uses the repoze.who API
    to authenticate any submitted credentials, then redirects to
    whatever page the user was trying to view.  You can use it as
    a convenient redirection point for plugins that need to submit
    credentials via POST, or as the target for a custom login form.
    """
    came_from = request.params.get("came_from", request.referer or "/")
    # Try to authenticate, either via standard plugin auth
    # or by using the request parameters at the identity.
    userid = security.authenticated_userid(request)
    if userid is not None:
        headers = security.remember(request, userid)
    else:
        api = get_api(request)
        userid, headers = api.login(dict(request.params))
    # If that worked, send them back to where they came from.
    if userid is not None:
        return HTTPFound(location=came_from, headers=headers)
    # If not, trigger the usual forbidden view.
    # In theory this should eventually post back to us again.
    raise HTTPForbidden()


def logout(request):
    """View to forget the logged-in user.

    This method provides a pyramid view that uses the repoze.who API
    to forget any remembered credentials.
    """
    came_from = request.params.get("came_from", request.referer or "/")
    headers = security.forget(request)
    return HTTPFound(location=came_from, headers=headers)
