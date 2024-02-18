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

  name = "oauth2-on-behalf-of/handler"
  author = Alexander Suchier, NTT DATA Deutschland SE
  description = "Kong plugin handler to retrieve access tokens via OAuth 2.0 On-Behalf-Of flow"

  note:
  - MS OBO: https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-on-behalf-of-flow
  - Kong Caching - https://docs.konghq.com/gateway/latest/plugin-development/entities-cache/

--]]

local log = require "kong.plugins.oauth2-on-behalf-of.log"

local bearer = require "kong.plugins.oauth2-on-behalf-of.bearer"
local token = require "kong.plugins.oauth2-on-behalf-of.token"
local jwt = require "kong.plugins.oauth2-on-behalf-of.jwt"

local cert_utils = require "kong.enterprise_edition.cert_utils"

local url = require "net.url"
local http = require "resty.http"

local cjson_safe = require "cjson.safe"

local pl_url = require "pl.url"
local pl_pretty = require "pl.pretty"

local kong = kong

local ngx_now = ngx.now
local ngx_update_time = ngx.update_time
local ngx_http_time = ngx.http_time

local PLUGIN_VERSION = "1.0.1"
local PLUGIN_PRIORITY = 800
local PLUGIN_NAME = "oauth2-on-behalf-of"

local LOG_HIGHLIGHT_PREFIX = '################### '

local CACHE_KEY = "OnBehalfOfKey"
local CACHE_KEY_STRATEGY_JWT_ID = "JWT_ID"
local CACHE_KEY_STRATEGY_JWT_SIGNATURE = "JWT_SIGNATURE"
local CACHE_KEY_STRATEGY_CLIENT_ID_USER_IDENTIFIER = "CLIENT_ID_USER_IDENTIFIER"

local AUTHORIZATION = "Authorization"
local KONG_OAUTH2_OBO_CACHE_REMAINING_TTL = "X-Kong-OAuth2-OBO-Cache-Remaining-TTL"

local JTI_CLAIM = "jti"

local HTTP_CODE_500_INTERNAL_SERVER_ERROR = 500
local HTTP_CODE_502_BAD_GATEWAY = 502

local EPOCH_SEC = false
local EPOCH_MSEC = true


--[[
  get the time in seconds or milliseconds (needed for stowatch)
  @param ms defines time unit return (true=MSEC, false=SEC)
  @return time in seconds or milliseconds
--]]
local function now(ms)
  ngx_update_time()

  -- floating-point number for the elapsed time in seconds (including milliseconds as the decimal part)
  local ngxNow = ngx_now()

  if (ms) then
    ngxNow = ngxNow * 1000
  else
    ngxNow = math.floor(ngxNow)
  end

  return ngxNow
end


--[[
  build optional scope string
  @param conf the kong plugin configuration 
  @return scopeStr separated with spaces
  note: https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
--]]
local function buildScopeStr(conf)
  local scopeStr = nil

  if (conf.scope) then
    scopeStr = ""

    for k, v in pairs(conf.scope) do
      if (k == 1) then
        scopeStr = v
      else
        scopeStr = scopeStr .. " " .. v
      end
    end
  end

  kong.log.debug("scope string: ", scopeStr)

  return scopeStr
end


--[[
  buildPayload for the on-behalf-of grant type
  @param conf the kong plugin configuration
  @return payload string
--]]
local function buildPayload(conf,assertionToken)
  local payload = ''

  payload = payload .. "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" -- the type of token request
  payload = payload .. "&client_id=" .. conf.client_id                          -- the application (client) ID that the Azure portal - App registrations
  payload = payload .. "&client_secret=" .. conf.client_secret                  -- the client secret that you generated for your app in the Azure portal - App registrations
  payload = payload .. "&assertion=" .. assertionToken                          -- the access token that was sent to the middle-tier API. This token must have an audience (aud) claim of the app making this OBO request (the app denoted by the client-id field)
  payload = payload .. "&requested_token_use=on_behalf_of"                      -- specifies how the request should be processed (in the OBO flow, the value must be set to on_behalf_of)

  -- add requestedTokenType parameter only for SAML, JWT is default anyway
  if ((token:isTokenTypeSAML1(conf.requested_token_type)) or (token:isTokenTypeSAML2(conf.requested_token_type))) then
    payload = payload .. "&requested_token_type=" .. conf.requested_token_type  -- specifies the type of token requested (urn:ietf:params:oauth:token-type:saml1 or urn:ietf:params:oauth:token-type:saml2)
  end

  if ((conf.resource) and (#conf.resource>0)) then
    payload = payload .. "&resource=" .. conf.resource       -- v1 endpoint, the app of the receiving service (secured resource)
  end

  local scopeStr = buildScopeStr(conf)

  if (scopeStr) then
    payload = payload .. "&scope=" .. pl_url.quote(scopeStr) -- v2 endpoint, space separated list of scopes for the token request
  end

  kong.log.debug("payload: ", payload)

  return payload
end


--[[
  on-behalf-of flow to retrieve a valid access token
  @param conf the kong plugin configuration
  @param assertionToken the assertion token
  @return accessToken (handle exits because error return has been difficult with caching)

  note: 
  function could be a callback handler for caching (special attention)!
  Lua HTTP client-httpc documentation: https://github.com/ledgetech/lua-resty-http

  If https_verity is activated, the root CA certificate must be made known to Kong. 
  OpenRusty needs the lua_ssl_trusted_certificate configuration with a CA file path.
  The file path specifies a (one!) file with trusted CA certificates in the PEM format 
  used to verify the certificate of the SSL/TLS server. CA certificates can be stacked 
  in the file. For a container-based Kong installation, simply set the environment 
  variable KONG_LUA_SSL_TRUSTED_CERTIFICATE.

  The root certificate can be exported in the browser by calling the AAD token endpoint.
  Export: certificate viewer, details, certificate chain, export base64 *.pem;*.crt
--]]
local function doOnBehalfOfFlow(conf, assertionToken)
  local accessToken = nil
  local err = nil
  local ttl = nil

  local HTTP_METHOD = "POST"
  local HTTP_CONTENT_APPLICATION_JSON_TYPE = "application/json"
  local HTTP_CONTENT_FORM_URLENCODED_TYPE = "application/x-www-form-urlencoded"

  local siemEventMarker = ""

  if (conf.enable_siem) then
    siemEventMarker = conf.event_marker_siem
  end

  local httpc = http.new()

  if (conf.timeout) then
    httpc:set_timeout(conf.timeout)
  end

  if (conf.enable_proxy) then
    httpc:set_proxy_options({
      http_proxy                = conf.http_proxy,
      http_proxy_authorization  = conf.http_proxy_authorization,
      https_proxy               = conf.https_proxy,
      https_proxy_authorization = conf.https_proxy_authorization,
      no_proxy                  = conf.no_proxy,
    })
  end

  local ctx = ngx.ctx
  local ssl_client_cert, ssl_client_priv_key, ssl_server_name, ssl_err

  if (conf.enable_client_certificate) then
    -- load and convert the PEM-formatted SSL client cert and key into an opaque cdata pointer, cdata<void *>
    if (conf.client_certificate_id) then
      kong.log.debug("load client cert from conf.client_certificate_id: ", conf.client_certificate_id)
      ssl_client_cert, ssl_client_priv_key, ssl_err = cert_utils.load_certificate(conf.client_certificate_id)
    elseif (ctx.service.client_certificate) then
      kong.log.debug("load client cert from service: ", ctx.service.client_certificate.id)
      ssl_client_cert, ssl_client_priv_key, ssl_err = cert_utils.load_certificate(ctx.service.client_certificate.id)
    else
      kong.log.err(HTTP_CODE_500_INTERNAL_SERVER_ERROR, ", ", "client certificate enabled, but no client certificate configured", " ", siemEventMarker)
      kong.response.exit(HTTP_CODE_500_INTERNAL_SERVER_ERROR, "client certificate enabled, but no client certificate configured")
    end

    -- check that cdata pointer is different from nil 
    if ((not(ssl_client_cert)) or (not (ssl_client_priv_key))) then
      kong.log.err(HTTP_CODE_500_INTERNAL_SERVER_ERROR, ", ", "load certificate [" .. ssl_err .. "]", " ", siemEventMarker)
      kong.response.exit(HTTP_CODE_500_INTERNAL_SERVER_ERROR, "load certificate [" .. ssl_err .. "]")
    end

    kong.log.debug("ssl client cert: ", tostring(ssl_client_cert))
    kong.log.debug("ssl_client_priv_key: ", tostring(ssl_client_priv_key))

    local u = url.parse(conf.token_endpoint)
    ssl_server_name = u.host

    kong.log.debug("ssl_server_name: ", ssl_server_name)
  end

  local http_res, http_err = httpc:request_uri(conf.token_endpoint, {
    version = conf.http_version,
    method = HTTP_METHOD,
    body = buildPayload(conf,assertionToken),
    headers = {
      ["Content-Type"] = HTTP_CONTENT_FORM_URLENCODED_TYPE,
    },
    keepalive = conf.keepalive,
    keepalive_timeout = conf.keepalive_timeout,
    keepalive_pool = conf.keepalive_pool,
    ssl_verify = conf.https_verify,
    ssl_server_name = ssl_server_name,
    ssl_client_cert = ssl_client_cert,
    ssl_client_priv_key = ssl_client_priv_key,
  })

  -- connection pool seems to be closed
  if (log:debugging()) then
    local reused_times, reused_err = httpc:get_reused_times()

    if (not(reused_times)) then
      kong.log.debug("connection pool reused times error: ", reused_err)
    else
      kong.log.debug("connection comes from the pool: ", (reused_times>0), " [", reused_times, "]")
    end
  end 

  local http_err_msg = "request to " .. conf.token_endpoint .. ", " .. (conf.enable_proxy and "via proxy" or "no proxy")

  if (not(http_res)) then
    kong.log.err(HTTP_CODE_502_BAD_GATEWAY, ", ", http_err_msg .. ": [" .. http_err .. "]", " ", siemEventMarker)
    kong.response.exit(HTTP_CODE_502_BAD_GATEWAY, http_err_msg .. ": [" .. http_err .. "]")
  end

  local success = (http_res.status < 400)

  if (not(success)) then
    if (http_res.body) then
      local fault = { msg = http_err_msg }
      local json_fault_value, json_fault_err = cjson_safe.decode(http_res.body)

      if (json_fault_value) then
        -- error and error_description parameters are defined by OAuth2 spec, Keycloak and ForgeRock have it on response
        if ((json_fault_value.error) and (json_fault_value.error_description)) then
          fault.error = json_fault_value.error
          fault.error_description = json_fault_value.error_description
        else
          -- proprietary response
          kong.log.err(HTTP_CODE_502_BAD_GATEWAY, ", ", pl_pretty.write(json_fault_value,"",false))
        end
      end

      if (json_fault_err) then
        kong.log.err(HTTP_CODE_502_BAD_GATEWAY, ", ", http_res.body, " ", siemEventMarker)
      else
         kong.log.err(HTTP_CODE_502_BAD_GATEWAY, ", ", pl_pretty.write(fault,"",false), " ", siemEventMarker)
      end

      kong.response.exit(HTTP_CODE_502_BAD_GATEWAY, fault, {["Content-Type"] = HTTP_CONTENT_APPLICATION_JSON_TYPE})
    end

    kong.log.err(HTTP_CODE_502_BAD_GATEWAY, ", ", http_err_msg .. ": [" .. http_res.status .. "]", " ", siemEventMarker)
    kong.response.exit(HTTP_CODE_502_BAD_GATEWAY, http_err_msg .. ": [" .. http_res.status .. "]")
  end

  if (not (http_res.body)) then
    kong.log.err(HTTP_CODE_502_BAD_GATEWAY, ", ", "no response body", " ", siemEventMarker)
    kong.response.exit(HTTP_CODE_502_BAD_GATEWAY, "no response body")
  end

  local json_value, json_err = cjson_safe.decode(http_res.body)

  if (json_err) then
    kong.log.err(pl_pretty.write(http_res.body,"",false))
    kong.log.err(HTTP_CODE_500_INTERNAL_SERVER_ERROR, ", ", "decode response body [" .. json_err .. "]", " ", siemEventMarker)
    kong.response.exit(HTTP_CODE_500_INTERNAL_SERVER_ERROR, "decode response body [" .. json_err .. "]")
  end

  accessToken = json_value.access_token

  if (not(accessToken)) then
    kong.log.err(pl_pretty.write(http_res.body,"",false))
    kong.log.err(HTTP_CODE_502_BAD_GATEWAY, ", ", "no access token", " ", siemEventMarker)
    kong.response.exit(HTTP_CODE_502_BAD_GATEWAY, "no access token")
  end

  -- OAuth2 RFC 6749 specification recommends expires_in parameter in successful access token responses (section 4.2.2 and 5.1)
  -- AAD, Keycloak and ForgeRock accept this recommendation and return an expires_in parameter
  if ((conf.enable_caching) and (conf.enable_factor_ttl) and (json_value.expires_in)) then
    -- override the cache item (or option) ttl, rule: Token-TTL * TTL-Factor.
    ttl = math.floor(json_value.expires_in * conf.ttl_factor)

    -- emergency brake
    local expires_in = 0

    -- keycloak delivers a number, aad a string
    if (type(json_value.expires_in) == "string") then
      expires_in = tonumber(json_value.expires_in)
    else
      expires_in = json_value.expires_in
    end

    if (ttl >= expires_in) then
      kong.log.err(HTTP_CODE_500_INTERNAL_SERVER_ERROR, ", ", "calculated factor ttl >= token validity [" .. tostring(ttl) .. " >= " .. tostring(expires_in) .. "]", " ", siemEventMarker)
      kong.response.exit(HTTP_CODE_500_INTERNAL_SERVER_ERROR, "calculated factor ttl >= token validity [" .. tostring(ttl) .. " >= " .. tostring(expires_in) .. "]")
    end

    kong.log.debug("token expires in: ", expires_in, " sec")
    kong.log.debug("token cache item ttl: ", ttl, " sec")

    kong.log.debug("token cached until (UTC): ", ngx_http_time(now(EPOCH_SEC)+ttl))
  end

  if (log:debugging() and (ttl)) then
    kong.response.set_header(KONG_OAUTH2_OBO_CACHE_REMAINING_TTL, ttl)
  end

  return accessToken, err, ttl
end


--[[
  conformity check
  @param conf > the kong configuration
  @param uncheckedToken > the security token
  @return true/false, error message
--]]
local function conformityCheck(conf,uncheckedToken)
  local valid, errorMsg = token:conformityCheck(uncheckedToken,conf.requested_token_type)
  return valid, errorMsg
end


--[[
  security aware token output
  @param conf > the kong plugin configuration
  @param unsafeToken > the security token
  @return log token (secure because unusable due to signature removal)
--]]
local function logTokenSecurityAware(conf,unsafeToken)
  local LOG_PREFIX = "bearer token: "
  log:tokenLoggingSecurityAware(LOG_PREFIX,unsafeToken,conf.requested_token_type)
end


--[[
  build cache key
  @param accessToken > access token
  @return cache key
--]]
local function buildCacheKey(conf, assertionToken)
  local cacheKey = nil

  if (conf.cache_key_strategy==CACHE_KEY_STRATEGY_CLIENT_ID_USER_IDENTIFIER) then
    -- cache key needs an unique user identifier, Keycloak/AAD = preferred_username, AAD = oid (better than preferred_username)
    local userIdentifier, userIdentifierErr = jwt:claimValue(assertionToken,conf.user_identifier_claim)

    if (userIdentifierErr) then
      kong.log.err(userIdentifierErr.status,userIdentifierErr.message)
      return nil, { status = userIdentifierErr.status, message = userIdentifierErr.message }
    end

    -- does the cache key also need the recipients that the JWT is intended for (e.g. aud)? taken out for now.
    cacheKey = CACHE_KEY .. "#" .. conf.client_id .. "#" .. userIdentifier
  end

  if (conf.cache_key_strategy==CACHE_KEY_STRATEGY_JWT_ID) then
    -- cache key needs an jwt id
    -- note: AAD JWT ver 1.0 tokens do not provide jti claims
    local jti, jtiErr = jwt:claimValue(assertionToken,JTI_CLAIM)

    if (jtiErr) then
      kong.log.err(jtiErr.status,jtiErr.message)
      return nil, { status = jtiErr.status, message = jtiErr.message }
    end

    cacheKey = CACHE_KEY .. "#" .. jti
  end

  if (conf.cache_key_strategy==CACHE_KEY_STRATEGY_JWT_SIGNATURE) then
    -- cache key needs an jwt signature
    local jwtSignature, jwtSignatureErr = jwt:signature(assertionToken)

    if (jwtSignatureErr) then
      kong.log.err(jwtSignatureErr.status,", ",jwtSignatureErr.message)
      return nil, { status = jwtSignatureErr.status, message = jwtSignatureErr.message }
     end

    -- does the cache key also need the recipients that the JWT is intended for (e.g. aud)? taken out for now.
    cacheKey = CACHE_KEY .. "#" .. jwtSignature
  end

  kong.log.debug("cacheKey: ",cacheKey)

  return cacheKey, nil
end


--[[
  log the plugin configuration 
  @param conf the kong plugin configuration
--]]
local function logConf(conf)
  kong.log.debug('plugin priority: ', PLUGIN_PRIORITY)
  -- networking configuration
  kong.log.debug('conf.http_version: ', conf.http_version)
  kong.log.debug('conf.timeout: ', conf.timeout, ' ms')
  kong.log.debug('conf.keepalive: ', conf.keepalive)
  kong.log.debug('conf.keepalive_timeout: ', conf.keepalive_timeout, ' ms')
  kong.log.debug('conf.keepalive_pool: ', conf.keepalive_pool)
  kong.log.debug('conf.enable_proxy: ', conf.enable_proxy)
  kong.log.debug('conf.http_proxy: ', conf.http_proxy)
  kong.log.debug('conf.http_proxy_authorization: ', conf.http_proxy_authorization)
  kong.log.debug('conf.https_proxy: ', conf.https_proxy)  
  kong.log.debug('conf.https_proxy_authorization: ', conf.https_proxy_authorization)
  kong.log.debug('conf.no_proxy: ', conf.no_proxy)
  kong.log.debug('conf.https_verify: ',conf.https_verify)
  kong.log.debug('conf.enable_client_certificate: ', conf.enable_client_certificate)
  kong.log.debug('conf.client_certificate_id: ', conf.client_certificate_id)
  -- flow configuration
  kong.log.debug('conf.token_endpoint: ', conf.token_endpoint)
  kong.log.debug('conf.client_id: ', conf.client_id)
  kong.log.debug('conf.client_secret: ', conf.client_secret)
  kong.log.debug('conf.resource: ', conf.resource)
  kong.log.debug('conf.scope: ', pl_pretty.write(conf.scope,"",false))
  kong.log.debug('conf.requested_token_type: ', conf.requested_token_type)
  -- additional configuration
  kong.log.debug('conf.keep_original_token: ', conf.keep_original_token)
  kong.log.debug('conf.enable_caching: ', conf.enable_caching)
  kong.log.debug('conf.cache_key_strategy: ', conf.cache_key_strategy)
  kong.log.debug('conf.user_identifier_claim: ', conf.user_identifier_claim)
  kong.log.debug('conf.ttl: ', conf.ttl, ' sec')
  kong.log.debug('conf.enable_factor_ttl: ', conf.enable_factor_ttl)
  kong.log.debug('conf.ttl_factor: ', conf.ttl_factor)
  kong.log.debug('conf.enable_conformity_check: ', conf.enable_conformity_check)
  kong.log.debug('conf.enable_siem: ', conf.enable_siem)
  kong.log.debug('conf.event_marker_siem: ', conf.event_marker_siem)
  kong.log.debug('conf.stopwatch: ', conf.stopwatch)
end


-- Kong ceremony

local OAuth2OnBehalfOfHandler = {
  VERSION = PLUGIN_VERSION,
  PRIORITY = PLUGIN_PRIORITY
}

--[[
  plugin handler for the ngx access phase
  @param conf the kong plugin configuration
--]]
function OAuth2OnBehalfOfHandler:access(conf)
  local startTimeMS = now(EPOCH_MSEC)

  kong.log.debug(LOG_HIGHLIGHT_PREFIX .. PLUGIN_NAME .. ' plugin enabled - access')
  logConf(conf)

  local assertionToken, assertionTokenErr = bearer:token()

  if (assertionTokenErr) then
    return kong.response.exit(assertionTokenErr.status, { message = assertionTokenErr.message })
  end

  kong.log.debug("assertion token: ", assertionToken)

  local accessToken = ""
  local accessTokenErr = {}

  if (conf.enable_caching) then
    local cacheKey, cacheKeyErr = buildCacheKey(conf, assertionToken)

    if (cacheKeyErr) then
      return kong.response.exit(cacheKeyErr.status, { message = cacheKeyErr.message } )
    end

    -- for debugging purposes: cache control (plugin development only)
    if (log:debugging()) then
      local remaining_ttl, err, value = kong.cache:probe(cacheKey)

      if (value) then
        kong.log.debug("cacheKey: ", cacheKey, " remaining ttl: ", remaining_ttl, " sec")
        kong.response.set_header(KONG_OAUTH2_OBO_CACHE_REMAINING_TTL, remaining_ttl)
      else
         kong.log.debug("cacheKey: ", cacheKey, " not yet included in the cache")
      end
    end

    accessToken, accessTokenErr = kong.cache:get(cacheKey, { ttl = conf.ttl }, doOnBehalfOfFlow, conf, assertionToken)

    if (accessTokenErr) then
      kong.log.err(HTTP_CODE_502_BAD_GATEWAY, ", ", pl_pretty.write(accessTokenErr,"",false))
    end
  else
    accessToken = doOnBehalfOfFlow(conf,assertionToken)
  end

  kong.log.debug('access token: ', accessToken)

  if (conf.enable_conformity_check) then
    local checkRes, checkErr = conformityCheck(conf,accessToken)

    if (checkErr) then
      kong.log.err(HTTP_CODE_500_INTERNAL_SERVER_ERROR, ", ", pl_pretty.write(checkErr,"",false))
      return kong.response.exit(HTTP_CODE_500_INTERNAL_SERVER_ERROR, { message = checkErr.message })
    end

    kong.log.debug("token conformity check: ", checkRes)
  end

  -- logging: remove signature and thereby invalidate the token if the log level is other than debug (prevent replay attacks)
  logTokenSecurityAware(conf,accessToken)

  if (conf.keep_original_token) then
    kong.service.request.clear_header('original_obo_' .. AUTHORIZATION)
    kong.service.request.set_header('original_obo_' .. AUTHORIZATION, bearer:buildBearerHeader(assertionToken))
    kong.log.debug("set request header: ", 'original_obo_' .. AUTHORIZATION, " = ", bearer:buildBearerHeader(assertionToken))
  end

  kong.service.request.clear_header(AUTHORIZATION)
  kong.service.request.set_header(AUTHORIZATION, bearer:buildBearerHeader(accessToken))

  kong.log.notice(PLUGIN_NAME, ": OBO successfully executed, proxying towards upstream")

  if (conf.stopwatch) then
    kong.log.info(PLUGIN_NAME, " plugin stopwatch - access: ", tostring(now(EPOCH_MSEC)-startTimeMS))
  end
end

return OAuth2OnBehalfOfHandler
