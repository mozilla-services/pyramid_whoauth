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

Helper functions for pyramid_whoauth

"""

from repoze.who.config import WhoConfig
from repoze.who.api import IAPIFactory, APIFactory


class ApplicationRedirectException(Exception):
    """Control flow exception for redirecting the downstream app.

    This exception is raised by the WhoAuthenticationPolicy when it detects
    that a plugin is trying to redirect the downstream application by setting
    environ["repoze.who.application"].  It will bubble up as an error in your
    handler unless you have installed the pyramid_whoauth tween, which catches
    the error and does the appropriate redirection.
    """
    pass


def get_api(request, api_factory=None):
    """Get the repoze.who API object for use with the given request.

    This function will lookup and returns the repoze.who API object to use
    for the given request.  If no object exists then it gets the registered
    IAPIFactory utility and uses it to create one.
    """
    # Yes, this is very similar to the logic inside APIFactory itself.
    # I'm re-implementing it so we can look up the default APIFactory
    # in the application registry.
    api = request.environ.get("repoze.who.api")
    if api is None:
        if api_factory is None:
            api_factory = request.registry.getUtility(IAPIFactory)
        api = api_factory(request.environ)
    return api


def register_api_factory(registry, api_factory):
    """Record the APIFactory in the given application registry.

    This function stores a reference to a repoze.who APIFactory in the
    application registry, so that other parts of the application can find
    it at runtime.
    """
    registry.registerUtility(api_factory, IAPIFactory)


def api_factory_from_settings(settings, prefix="who."):
    """Create a new repoze.who APIFactory from the deployment settings.

    This function uses the paster deployment settings to create a repoze.who
    APIFactory object.  Settings starting with "who." are collected and
    formatted into an ini-file which can be read by the repoze.who config
    parser, and the resulting APIFactory object is returned.
    """
    # If we have already built and cached one, just use it directly.
    cache_key = prefix + "api_factory"
    if cache_key in settings:
        return settings[cache_key]

    # Grab out all the settings keys that start with our prefix.
    who_settings = {}
    for name, value in settings.iteritems():
        if not name.startswith(prefix):
            continue
        who_settings[name[len(prefix):]] = value

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

    # Cache it so we don't have to repeat all that work.
    settings[cache_key] = api_factory
    return api_factory
