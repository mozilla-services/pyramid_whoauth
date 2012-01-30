# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
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

    This function will lookup and return the repoze.who API object to use
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
