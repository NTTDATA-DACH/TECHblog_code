--[[
  
Disclaimer:
NTT DATA Deutschland SE gives no assurances regarding the suitability and usability of the source code provided here. The source code is provided
without warranty of any kind and may be used in any identical or edited form. Accordingly, NTT DATA Deutschland SE hereby excludes all warranties 
and guarantees with respect to the source code, including all explicit, implied or statutory warranties and guarantees of merchantability, fitness
for purpose, title and non-infringement. In no event shall NTT DATA Deutschland SE be liable for any direct, indirect and/or consequential damages
and/or any damages whatsoever.

Haftungsausschluss:
Die NTT DATA Deutschland SE gibt keine Zusicherungen hinsichtlich der Eignung und Verwendbarkeit des hier zur Verfuegung gestellten Quellcodes.
Der Quellcode wird ohne Gewaehrleistung jeglicher Art bereitgestellt und kann beliebig identisch bzw. bearbeitet genutzt werden. Entsprechend
schliesst die NTT DATA Deutschland SE hiermit saemtliche Gewaehrleistungen und Garantien in Bezug auf den Quellcode aus, einschliesslich saemtlicher
ausdruecklicher, konkludenter oder gesetzlicher Gewaehrleistungen und Garantien in Bezug auf Handelsueblichkeit, Eignung und Eigentum und Verletzung
von Rechten Dritter. In keinem Fall ist die NTT DATA Deutschland SE fuer direkte, indirekte Schaeden und /oder Folgeschaeden und / oder Schaeden
welcher Art auch immer haftbar zu machen.

-------

  name = "oauth2-saml2-bearer/schema"
  author = Alexander Suchier, NTT DATA Deutschland SE
  description = "Kong plugin schema to retrieve access tokens via OAuth 2.0 SAML2 bearer flow"

  note:
  - RFC 7522: https://datatracker.ietf.org/doc/html/rfc7522

--]]

local typedefs = require "kong.db.schema.typedefs"

local kong = kong

local FORMATS = {
  "urlencoded",
  "xml",
  "json"
}

local TOKEN_TYPES = {
  "urn:ietf:params:oauth:token-type:opaque", -- not Internet Engineering Task Force (IETF) conform, but useful
  "urn:ietf:params:oauth:token-type:jwt"
}

local function validate_cache_csrf_protection(config)
  local caching = config.enable_caching
  kong.log.debug("# caching: ", caching)
  local csrf_protection = config.enable_csrf_protection
  kong.log.debug("# csrf_protection: ", csrf_protection)

  if ((csrf_protection) and (not(caching))) then
    return nil, "CSRF protection needs caching. Activate caching or the consumer has to take care of CSRF himself."
  end

  return true
end

return {
  name = "oauth2-saml2-bearer",

  fields = {
    {
      consumer = typedefs.no_consumer
    },
    {
      protocols = typedefs.protocols_http
    },
    {
      config = {
        type = "record",
        fields = {
          -- networking configuration
          { http_version = { type = "number", default  = 1.1, required = false, description = "HTTP version number. Defaults to 1.1." }, },
          { timeout = { type = "number", default = 30000, required = false, description = "Socket timeout (in ms) for subsequent operations. Defaults to 30000." }, },
          { keepalive = { type = "boolean", default = true, required = false, description = "Disable keepalives (false) and immediately close the connection. Defaults to true." }, },
          { keepalive_timeout = { type = "number", default = 60000, required = false, description = "The maximal idle timeout (ms). Defaults to 60000." }, },
          { keepalive_pool = { type = "number", default = 10, required = false, description = "The maximum number of connections in the pool. Defaults to 10." }, },
          { enable_proxy = { type = "boolean", default = false, required = false, description = "Connect to the IdP through the given proxy settings. Defaults to false." }, },
          { http_proxy =  typedefs.url { required = false, description = "URI to a proxy server to be used with HTTP requests." }, },    
          { http_proxy_authorization = { type = "string", default = "", len_min = 0, required = false, description = "Proxy-Authorization header value to be used with http_proxy." }, }, 
          { https_proxy = typedefs.url { required = false, description = "URI to a proxy server to be used with HTTPS requests." }, },
          { https_proxy_authorization = { type = "string", default = "", len_min = 0, required = false, description = "Proxy-Authorization header value to be used with https_proxy." }, },
          { no_proxy = { type = "string", default = "localhost, 127.0.0.1", len_min = 0, required = false, description = "Comma separated list of hosts that should not be proxied." }, }, 
          { https_verify = { type = "boolean", default = true, required = false, description = "Control whether to perform SSL verification (server name parsed from token_endpoint). Defaults to true." }, },
          { enable_client_certificate = { type = "boolean", default = true, required = false, description = "Client certificate will be sent to clients (true). Defaults to true." }, },
          { client_certificate_id = { type = "string", uuid = true, required = false, description = "Client certificate Id configured with Kong. If not set, the client certificate setting from the target service will be used." }, },
          -- flow configuration
          { token_endpoint = typedefs.url { required = false, description = "Token endpoint used by Kong to perform an SAML 2.0 Assertion Bearer for OAuth 2.0 grant. Example: https://<authz server>/sap/bc/sec/oauth2/token" }, },
          { enable_basic_authn = { type = "boolean", default = false, required = false, description = "Basic authentication user/password will be sent to clients (true). Defaults to false." }, },
          { basic_authn_username = { type = "string", default = "", len_min = 0, required = false, description = "Username for basic authentication who has the permission to call OAuth2 SAML2 bearer grant type." }, },
          { basic_authn_password = { type = "string", default = "", len_min = 0, required = false, description = "Password for basic authentication user who has the permission to call OAuth2 SAML2 bearer grant type." }, },
          { client_id = { type = "string", default = "", len_min = 0, required = true, description = "Application (client) ID that the authorization server has assigned to the app." }, },
          { format = { type = "string", default = FORMATS[3], one_of = FORMATS, len_min = 0, required = false, description = "Expected return format: urlencoded, xml, json (default). Defaults to json." }, },
          { scope = { type = "array", elements = { type = "string", }, required = false, description = "Array of scopes for the token request. Requests permissions needed in the scope parameter." }, },
          -- additional configuration
          { expected_token_type = { type = "string", default = TOKEN_TYPES[1], one_of = TOKEN_TYPES, len_min = 0, required = true, description = "Specifies the type of token expected (opaque, JWT). Defaults to opaque." }, },
          { keep_original_token = { type = "boolean", default = false, required = false, description = "Activate, if the input token should be retained in the request (original_authorization)." }, },
          { enable_csrf_protection = { type = "boolean", default = false, required = false, description = "CSRF protection for non-GET requests. Defaults to false." }, },
          { enable_caching = { type = "boolean", default = false, required = false, description = "Activate, if the token should be cached. Defaults to false." }, },
          { ttl = { type = "number", default = 180, required = false, description = "Token cache ttl (time-to-live) specifies the expiration time (sec). Defaults to 180 sec." }, },
          { enable_factor_ttl = { type = "boolean", default = false, required = false, description = "Activate, if the token cache ttl (time-to-live) should be calculated based on the AAD expiration time multiplied by a factor" }, },
          { ttl_factor = { type = "number", default = 0.5, between = {0, 1}, required = false, description = "Multiplication factor for the proportional ttl time on the AAD expiration time. Defaults to 0.5." }, },
          { enable_conformity_check = { type = "boolean", default = false, required = false, description = "Activate, if the SAML 2.0 Assertion Bearer grant returned token should be subjected to a conformity check (token will be parsed)." }, },
          { enable_siem = { type = "boolean", default = true, required = false, description = "Active, if SIEM (Security Information and Event Management) should be informed in case of an error." } },
          { event_marker_siem = { type = "string", default = "SiemEventLoggingListener", required = false, description = "SIEM (Security Information and Event Management) marker added on logging." } },
          { stopwatch = { type = "boolean", default = false, required = false, description = "Active, if runtime of the plugin should be be measured (msec)." } },
        },
        custom_validator = validate_cache_csrf_protection,
      },
    },
  },
}

