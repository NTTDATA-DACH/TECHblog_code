# Kong – mTLS Header
by Alexander Suchier

This LUA plugin implements mTLS authentication based on client certificate MTLS header on the Kong API Gateway. These mTLS header are coming from TLS terminating reverse proxies (TTRP) in perimeter security. mTLS with consumer authentication via the client certificate subject alternative name (SAN) can play an important role in implementing a zero-trust architecture (ZTA). Perimeter security combined with mTLS consumer authentication at the gateway improves the overall security posture of the system, making it more resilient to various threats in today's dynamic and distributed computing environments. 

The mtls-header plugin have to be set up and used on top of the existing Kong mutual TLS authentication configuration (however, this makes the plugin dependent on an enterprise version). All configuration parameters are explained in the schema description.

New to Kong plugin coding? It's best to start with the Kong introduction "Develop Custom Plugins" [here](https://docs.konghq.com/gateway/latest/plugin-development/).

For more details read the full article [here](https://nttdata-dach.github.io/posts/as-konggateway-mtls_header/).