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
