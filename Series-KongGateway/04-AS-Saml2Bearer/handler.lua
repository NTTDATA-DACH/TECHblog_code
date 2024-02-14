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

  name = "oauth2-saml2-bearer/handler"
  author = Alexander Suchier, NTT DATA Deutschland SE
  description = "Kong plugin handler to retrieve access tokens via OAuth 2.0 SAML2 bearer flow"

  note:
  - RFC 7522: https://datatracker.ietf.org/doc/html/rfc7522
  - Kong caching - https://docs.konghq.com/gateway/latest/plugin-development/entities-cache/
  - Kong request/response lifetime table - https://docs.konghq.com/gateway/latest/plugin-development/pdk/kong.ctx/#kongctxshared

  restrictions:
  - The plugin currently does not offer an L3 distributed caching mechanism for data caching. 
    This means that cache data is not shared between Kong instances. 
    With one Kong instance there is no problem with caching and CSRF protection, 
    otherwise CSRF tokens/cookies can be requested multiple times. 
    This can be circumvented effectively with instance stickiness or the implementation of L3 caching capabilities (DB, Redis, etc.).
    Or you can hand over CSRF handling in the responsibility of the calling client (enable_csrf_protection=false).

--]]

local log = require "kong.plugins.oauth2-saml2-bearer.log"

local bearer = require "kong.plugins.oauth2-saml2-bearer.bearer"
local token = require "kong.plugins.oauth2-saml2-bearer.token"
local saml = require "kong.plugins.oauth2-saml2-bearer.saml"

local csrf = require "kong.plugins.oauth2-saml2-bearer.csrf"

local cert_utils = require "kong.enterprise_edition.cert_utils"

local http = require "resty.http"
local url = require "net.url"

local cjson_safe = require "cjson.safe"

local pl_url = require "pl.url"
local pl_pretty = require "pl.pretty"

local kong = kong

local ngx_now = ngx.now
local ngx_update_time = ngx.update_time
local ngx_http_time = ngx.http_time

local PLUGIN_VERSION = "1.0.0"
local PLUGIN_PRIORITY = 700
local PLUGIN_NAME = "oauth2-saml2-bearer"

local LOG_HIGHLIGHT_PREFIX = '################### '

local AUTHORIZATION = "Authorization"
local KONG_OAUTH2_SAML2_CACHE_REMAINING_TTL = "X-Kong-OAuth2-SAML2-Cache-Remaining-TTL"

local CACHE_KEY = "SAML2BearerKey"

local HTTP_CODE_401_UNAUTHORIZED = 401
local HTTP_CODE_500_INTERNAL_SERVER_ERROR = 500
local HTTP_CODE_502_BAD_GATEWAY = 502

local HTTP_GET_METHOD = "GET"

local EPOCH_SEC = false
local EPOCH_MSEC = true


--[[
  get the time in seconds or milliseconds (needed for stowatch)
  @param ms > defines time unit return (true=MSEC, false=SEC)
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
  @param conf > the kong plugin configuration
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

  return scopeStr
end


--[[
  buildPayload for the saml2-bearer grant type
  @param conf > the kong plugin configuration
  @return payload string
--]]
local function buildPayload(conf,assertionToken)
  local payload = ''

  -- the OAuth 2.0 grant type. The value must be urn:ietf:params:oauth:grant-type:saml2-bearer
  payload = payload .. "grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer"
  kong.log.debug("payload, grant_type: ", "urn:ietf:params:oauth:grant-type:saml2-bearer")

  -- the client ID - app registrations
  payload = payload .. "&client_id=" .. conf.client_id
  kong.log.debug("payload, client_id: ",conf.client_id)

  -- the SAML2 bearer assertion, - encoded
  payload = payload .. "&assertion=" .. assertionToken
  kong.log.debug("payload, assertion: ",assertionToken)

  -- optional: the expected return format: urlencoded, xml, json (default)
  if ((conf.format) and (#conf.format>0)) then
    payload = payload .. "&format=" .. conf.format 
    kong.log.debug("payload, format: ",conf.format)
  end

  -- optional: scopes in a SAML bearer assertion flow. Instead, the value for this parameter is the combination of scopes issued from previous access tokens.
  local scopeStr = buildScopeStr(conf)

  if (scopeStr) then
    payload = payload .. "&scope=" .. pl_url.quote(scopeStr) 
    kong.log.debug("payload, scope: ",pl_url.quote(scopeStr))
  end

  return payload
end


--[[
  SAML2 bearer flow to retrieve a valid access token
  @param conf > the kong plugin configuration
  @param assertionToken > the assertion token
  @return accessToken (handle exits because error return has been difficult with caching)
  note:
  - function could be callback handler for caching!
  - Lua HTTP client - httpc documentation: https://github.com/ledgetech/lua-resty-http
--]]
local function doSAML2BearerFlow(conf, assertionToken)
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

  local request_headers = {
    ["Content-Type"] = HTTP_CONTENT_FORM_URLENCODED_TYPE,
  }

  if (conf.enable_basic_authn) then
    kong.log.debug("conf.basic_authn_username: ", conf.basic_authn_username)
    kong.log.debug("conf.basic_authn_password: ", conf.basic_authn_password)

    local basicAuthUserPass = conf.basic_authn_username .. ":" .. conf.basic_authn_password
    kong.log.debug("basicAuthUserPass: ", basicAuthUserPass)

    -- has to be the ngx encoder
    local basicAuthUserPassEncode, base64_err = ngx.encode_base64(basicAuthUserPass)

    if (base64_err) then
      kong.log.err(HTTP_CODE_502_BAD_GATEWAY, ", ", "failed to decode username and password: ", base64_err, " ", siemEventMarker)
      kong.response.exit(HTTP_CODE_502_BAD_GATEWAY, ", ", "failed to decode username and password: ", base64_err, " ", siemEventMarker)
    end

    kong.log.debug("basicAuthUserPassEncode: ", basicAuthUserPassEncode)

    -- request_headers["Authorization"] = "Basic " .. basicAuthUserPassEncode
    request_headers[AUTHORIZATION] = "Basic " .. basicAuthUserPassEncode
  end

  local http_res, http_err = httpc:request_uri(conf.token_endpoint, {
    version = conf.http_version,
    method = HTTP_METHOD,
    body = buildPayload(conf,assertionToken),
    headers = request_headers,
    keepalive = conf.keepalive,
    keepalive_timeout = conf.keepalive_timeout,
    keepalive_pool = conf.keepalive_pool,
    ssl_verify = conf.https_verify,
    ssl_server_name = ssl_server_name,
    ssl_client_cert = ssl_client_cert,
    ssl_client_priv_key = ssl_client_priv_key,
  })

  -- for debugging purposes: connection pool control (plugin development only)
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

  if (not(http_res.body)) then
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
  -- SAP AuthZ Server, AAD, Keycloak and ForgeRock accept this recommendation and return an expires_in parameter
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
    kong.response.set_header(KONG_OAUTH2_SAML2_CACHE_REMAINING_TTL, ttl)
  end

  return { token = accessToken }, err, ttl
end


--[[
  conformity check
  @param conf > the kong configuration
  @param uncheckedToken > the security token
  @return true/false, error message
--]]
local function conformityCheck(conf,uncheckedToken)
  local valid, errorMsg = token:conformityCheck(uncheckedToken,conf.expected_token_type)
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
  log:tokenLoggingSecurityAware(LOG_PREFIX,unsafeToken,conf.expected_token_type)
end


--[[
  log the plugin configuration
  @param conf > the kong plugin configuration
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
  kong.log.debug('conf.enable_basic_authn: ', conf.enable_basic_authn)
  kong.log.debug('conf.basic_authn_username: ', conf.basic_authn_username)
  kong.log.debug('conf.basic_authn_password: ', conf.basic_authn_password)
  kong.log.debug('conf.client_id: ', conf.client_id)
  kong.log.debug('conf.format: ', conf.format)
  kong.log.debug('conf.scope: ', pl_pretty.write(conf.scope,"",false))
  -- additional configuration
  kong.log.debug('conf.expected_token_type: ', conf.expected_token_type)
  kong.log.debug('conf.keep_original_token: ', conf.keep_original_token)
  kong.log.debug('conf.enable_csrf_protection: ', conf.enable_csrf_protection)
  kong.log.debug('conf.enable_caching: ', conf.enable_caching)
  kong.log.debug('conf.ttl: ', conf.ttl, ' sec')
  kong.log.debug('conf.enable_factor_ttl: ', conf.enable_factor_ttl)
  kong.log.debug('conf.ttl_factor: ', conf.ttl_factor)
  kong.log.debug('conf.enable_conformity_check: ', conf.enable_conformity_check)
  kong.log.debug('conf.enable_siem: ', conf.enable_siem)
  kong.log.debug('conf.event_marker_siem: ', conf.event_marker_siem)
  kong.log.debug('conf.stopwatch: ', conf.stopwatch)
end


-- Kong ceremony

local OAuth2SAML2BearerHandler = {
  VERSION = PLUGIN_VERSION,
  PRIORITY = PLUGIN_PRIORITY
}

--[[
  plugin handler for the ngx access phase 
  @param conf > the kong plugin configuration
--]]
function OAuth2SAML2BearerHandler:access(conf)
  local startTimeMS = now(EPOCH_MSEC)

  kong.log.debug(LOG_HIGHLIGHT_PREFIX .. PLUGIN_NAME .. ' plugin enabled - access')
  logConf(conf)

  local assertionToken, assertionTokenErr = bearer:token()

  if (assertionTokenErr) then
    return kong.response.exit(assertionTokenErr.status, { message = assertionTokenErr.message })
  end

  kong.log.debug("assertion token: ", assertionToken)

  local access = nil
  local accessErr = {}

  local accessToken = ""

  if (conf.enable_caching) then
    local assertionId = saml:assertionId(assertionToken)

    if (not(assertionId)) then
      kong.log.err(HTTP_CODE_500_INTERNAL_SERVER_ERROR, ", ", "incoming SAML token has no assertion id")
      return kong.response.exit(HTTP_CODE_500_INTERNAL_SERVER_ERROR, { message = "incoming SAML token has no assertion id" })
    end

    local cacheKey = CACHE_KEY .. "#" .. conf.client_id .. "#" .. assertionId
    kong.ctx.shared.cacheKey = cacheKey

    -- for debugging purposes: cache control (plugin development only)
    if (log:debugging()) then
      local remaining_ttl, err, value = kong.cache:probe(cacheKey)

      if (value) then
        kong.log.debug("cacheKey: ", cacheKey, " remaining ttl: ", remaining_ttl, " sec")
        kong.response.set_header(KONG_OAUTH2_SAML2_CACHE_REMAINING_TTL, remaining_ttl)
      else
         kong.log.debug("cacheKey: ", cacheKey, " not yet included in the cache")
      end
    end

    access, accessErr = kong.cache:get(cacheKey, { ttl = conf.ttl }, doSAML2BearerFlow, conf, assertionToken)
  else
    access, accessErr = doSAML2BearerFlow(conf,assertionToken)
  end

  if (accessErr) then
    kong.log.err(HTTP_CODE_502_BAD_GATEWAY, ", ", pl_pretty.write(accessErr,"",false))
  else
    accessToken = access.token
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

  if (conf.keep_original_token) then
    kong.service.request.clear_header('original_saml2_' .. AUTHORIZATION)
    kong.service.request.set_header('original_saml2_' .. AUTHORIZATION, bearer:buildBearerHeader(assertionToken))
    kong.log.debug("set request header: ", 'original_saml2_' .. AUTHORIZATION, " = ", bearer:buildBearerHeader(assertionToken))
  end

  kong.service.request.clear_header(AUTHORIZATION)
  kong.service.request.set_header(AUTHORIZATION, bearer:buildBearerHeader(accessToken))

  if ((conf.enable_caching) and (conf.enable_csrf_protection)) then
    if (csrf:hasCSRFAccessCredentials(access)) then
        csrf:setCSRFAccessCredentials(access)
    else
      if (kong.request.get_method()==HTTP_GET_METHOD) then
        -- request csrf token and sap session cookie
        csrf:requestCSRFHeaders()
      else
        kong.log.err(HTTP_CODE_401_UNAUTHORIZED, ", ", "no csrf credentials for non-GET request available, fetch first with GET request")
        return kong.response.exit(HTTP_CODE_401_UNAUTHORIZED, { message = "no csrf credentials for non-GET request available, fetch first with GET request" })
      end
    end
  end

  -- logging: invalidate the token in case the log level is other than debug 
  logTokenSecurityAware(conf,accessToken)

  kong.log.notice(PLUGIN_NAME, ": SAML 2.0 Bearer Assertion successfully executed, proxying towards upstream")

  if (conf.stopwatch) then
    kong.log.info(PLUGIN_NAME, " plugin stopwatch - access: ", tostring(now(EPOCH_MSEC)-startTimeMS))
  end
end


--[[
  plugin handler for the ngx header_filter phase
  @param conf > the kong plugin configuration
--]]
function OAuth2SAML2BearerHandler:header_filter(conf)
  local startTimeMS = now(EPOCH_MSEC)

  kong.log.debug(LOG_HIGHLIGHT_PREFIX .. PLUGIN_NAME .. ' plugin enabled - header_filter')
  logConf(conf)

  -- check the requirements: caching and csrf protection
  if ((conf.enable_caching) and (conf.enable_csrf_protection)) then
    local cacheKey = kong.ctx.shared.cacheKey

    -- check the further requirements: get-request (fetch) and cache-key available
    if ((kong.request.get_method()==HTTP_GET_METHOD) and (cacheKey)) then
      local remaining_ttl, accessErr, access = kong.cache:probe(cacheKey)

      if (access) then
        kong.log.debug("cacheKey: ", cacheKey, " remaining ttl: ", remaining_ttl, " sec")
        kong.log.debug("access: ", pl_pretty.write(access,"",false))

        if (log:debugging()) then
          kong.response.set_header(KONG_OAUTH2_SAML2_CACHE_REMAINING_TTL, remaining_ttl)
        end

        -- do we have already the csrf credentials (think of follow-up gets after fetch get)
        if (not(csrf:hasCSRFAccessCredentials(access))) then
          access, accessErr = csrf:getCSRFAccessCredentials(access)

          kong.log.debug("access: ", pl_pretty.write(access,"",false))
          kong.log.debug("accessErr: ", pl_pretty.write(accessErr,"",false))

          if (not(csrf:isAccessErr(accessErr))) then
            kong.cache:invalidate(cacheKey)

            access, accessErr = kong.cache:get(cacheKey, { ttl = remaining_ttl }, function() return access end)
            kong.log.debug("access ", pl_pretty.write(access,"",false))

            if (not(csrf:isAccessErr(accessErr))) then
              -- if csrf protection is enabled, then keep the csrf credentials Kong internally
              csrf:clearCSRFHeaders()
            end
          end

          if (csrf:isAccessErr(accessErr)) then
            kong.log.err(HTTP_CODE_502_BAD_GATEWAY, ", ", pl_pretty.write(accessErr,"",false))
            return kong.response.exit(HTTP_CODE_502_BAD_GATEWAY, accessErr)
          end
        end
      end
    end
  end

  if (conf.stopwatch) then
    kong.log.info(PLUGIN_NAME, " plugin stopwatch - header_filter: ", tostring(now(EPOCH_MSEC)-startTimeMS))
  end
end


return OAuth2SAML2BearerHandler
