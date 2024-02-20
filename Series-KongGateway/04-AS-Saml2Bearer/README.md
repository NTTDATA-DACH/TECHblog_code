# Kong – Token Exchange with SAML 2.0 Bearer Assertion
by Alexander Suchier

This LUA plugin implements an Security Assertion Markup Language (SAML) 2.0 profile for OAuth 2.0 grant  on the Kong API Gateway. Such complex token orchestration tasks can be easily handled on the API Gateway while ensuring the highest security standards which even make zero-trust architectures (ZTA) possible in the first place.

The plugin code is proxy-aware and can seamlessly adapted to proxy settings. Also the plugin supports client certificate configurations for enhanced security requirements (however, this makes the plugin dependent on enterprise libraries). An advanced caching complements the feature list. All configuration parameters are explained in the schema description.

New to Kong plugin coding? It's best to start with the Kong introduction "Develop Custom Plugins" [here] https://docs.konghq.com/gateway/latest/plugin-development/

For more details read the full article [here](https://nttdata-dach.github.io/posts/as-konggateway-saml2bearer/).