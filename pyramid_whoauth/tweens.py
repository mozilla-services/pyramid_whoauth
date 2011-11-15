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

Tween implementations for pyramid_whoauth.

"""

from pyramid_whoauth.utils import get_api


def whoauth_tween_factory(handler, registry):
    """Tween factory for managing repoze.who egress hooks.

    This is a pyramid tween factory that ensures api.remember() is called on
    every response.  This is the behvaiour expected by many repoze.who
    plugins and guaranteed by the repoze.who middleware.
    """

    def whoauth_tween(request):
        response = handler(request)
        # Remember the identity if there is one.
        # This depends on the app calling api.logout() for a challenge
        # view, so that the identity is removed from the environ and we
        # don't end up sending conflicting headers.
        identity = request.environ.get("repoze.who.identity", {})
        if identity:
            # Grab the API only if there is an identity.  This prevents
            # useless overhead for e.g. static resource requests.
            api = get_api(request)
            #  Give all IIdentifiers a chance to remember the login.
            #  This is the same logic as inside the api.login() method,
            #  but without repeating the authentication step.
            for name, plugin in api.identifiers:
                i_headers = plugin.remember(request.environ, identity)
                if i_headers is not None:
                    response.headerlist.extend(i_headers)
        return response

    return whoauth_tween
