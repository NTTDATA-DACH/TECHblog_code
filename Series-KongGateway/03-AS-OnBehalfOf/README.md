# Kong – Token Exchange On-Behalf-Of
by Alexander Suchier

This LUA plugin implements an OAuth 2.0-based On-Behalf-Of (delegation) grant flow on the Kong API Gateway. Such complex token orchestration tasks can be easily handled on the API Gateway while ensuring the highest security standards which even make zero-trust architectures (ZTA) possible in the first place.

The plugin code is proxy-aware and can be seamlessly adapted to proxy settings. Furthermore, the plugin supports client certificate configurations for enhanced security requirements (however, this makes the plugin dependent on enterprise libraries). An advanced caching complements the feature list. All configuration parameters are explained in the schema description.

New to Kong plugin coding? It's best to start with the Kong introduction "Develop Custom Plugins" [here](https://docs.konghq.com/gateway/latest/plugin-development/).

For more details read the full article (to be published).