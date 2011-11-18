===============
pyramid_whoauth
===============

An authentication policy for Pyramid that uses the repoze.who v2 API.


Overview
========

This plugin allows you to configure a repoze.who authentication stack as a
pyramid authentication policy.  It takes a repoze.who API factory and turns
it into an pyramid IAuthenticationPolicy::

    from repoze.who.config import make_api_factory_with_config

    api_factory = make_api_factory_with_config(global_conf, "etc/who.ini")
    authn_policy = WhoAuthenticationPolicy(api_factory)
    config.set_authentication_policy(authn_policy)

This will load the repoze.who configuration from the specified config file
and hook it into Pyramid.

The advantage of using pyramid_whoauth instead of the repoze.who middleware
is that authentication is only performed when your application explicitly
requests it using e.g. pyramid's authenticated_userid() function.

For convenience, you can also specify all of the repoze.who configuration
settings as part of your paster deployment settings.  For example, you
might have the following::

    [app:pyramidapp]
    use = egg:mypyramidapp

    who.plugin.basicauth.use = repoze.who.plugins.basicauth:make_plugin
    who.plugin.basicauth.realm = MyRealm

    who.plugin.authtkt.use = repoze.who.plugins.auth_tkt:make_plugin
    who.plugin.authtkt.secret = Oh So Secret!

    who.identifiers.plugins = authtkt basicauth
    who.authenticators.plugins = authtkt basicauth
    who.challengers.plugins = basicauth

This configures repoze.who to use the "basicauth" and "auth_tkt" plugins,
using pyramid's dotted-settings style rather than the repoze.who config file.
Then it is a simple matter of including the pyramid_whoauth module into your
configurator::

    config.include("pyramid_whoauth")

In addition to configuring the repoze.who API factory from the given settings,
this will also set up some extra conveniences for your application:

    * a forbidden view that challenges for credentials via repoze.who
    * a login view that authenticates any credentials submitted via POST
    * a logout view that sends forget headers when accessed
    * a tween that calls the repoze.who "remember" method for each response

