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

--]]

local cert_utils = require "kong.enterprise_edition.cert_utils"
local jwt_parser = require "kong.plugins.jwt.jwt_parser"

local xml = require "xmlua.xml"

local http = require "resty.http"
local url = require "net.url"

local cjson_safe = require "cjson.safe"

local pl_url = require "pl.url"
local pl_pretty = require "pl.pretty"
local pl_stringx = require "pl.stringx"

--[[ enable, if log chunking is desired
local chunk_utils = require 'kong.modules.chunk_utils'
local chunker = chunk_utils.chunker
--]]

local rep = string.rep

local encode_base64 = ngx.encode_base64
local decode_base64 = ngx.decode_base64

local kong = kong

local ngx_now = ngx.now
local ngx_update_time = ngx.update_time
local ngx_http_time = ngx.http_time

local PLUGIN_VERSION = "1.0.0"
local PLUGIN_PRIORITY = 800
local PLUGIN_NAME = "oauth2-on-behalf-of"

local LOG_HIGHLIGHT_PREFIX = '################### '
local LOG_LEVEL_DEBUG = 'debug'
local LOG_LEVEL_INFO = 'info'

local CACHE_KEY = "OnBehalfOfKey"

local BEARER_PREFIX = "Bearer "
local AUTHORIZATION = "Authorization"

local TOKEN_TYPE_JWT = "jwt"
local TOKEN_TYPE_SAML1 = "saml1"
local TOKEN_TYPE_SAML2 = "saml2"

local HTTP_CODE_401_UNAUTHORIZED = 401
local HTTP_CODE_500_INTERNAL_SERVER_ERROR = 500
local HTTP_CODE_502_BAD_GATEWAY = 502

local LOG_REDACTED = 'REDACTED4SECURITY'

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
  check, if Kong is on debug logging 
  @return debug true/false
--]]
local function onDebug()
  local LOG_LEVEL_DEBUG ='debug'
  local logLevel = kong.configuration.log_level

  -- return ((logLevel ~= nil) and (string.lower(logLevel) == LOG_LEVEL_DEBUG))
  return false
end


--[[
  base 64 encoding based on ngx functions
  @param input String to base64 encode
  @return Base64 encoded string
--]
local function base64_encode(input)
  local result = encode_base64(input, true)
  result = result:gsub("+", "-"):gsub("/", "_")

  return result
end


--[[
  base 64 decode based on ngx functions
  @param input String to base64 decode
  @return Base64 decoded string
--]]
local function base64_decode(input)
  local remainder = #input % 4

  if remainder > 0 then
    local padlen = 4 - remainder
    input = input .. rep("=", padlen)
  end

  input = input:gsub("-", "+"):gsub("_", "/")
  return decode_base64(input)
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
  getRequestedTokenType
  @param conf the kong plugin configuration  
  @return token type string
--]]
local function getRequestedTokenType(conf)
  local requestedTokenType=TOKEN_TYPE_JWT

  -- requested_token_type is schema one_of validator checked
  if (conf.requested_token_type) then
    local tokenTypeParts = pl_stringx.split(conf.requested_token_type,':')
    
    if (tokenTypeParts) then
      requestedTokenType = tokenTypeParts[#tokenTypeParts] 
    end
  end

  kong.log.debug("requestedTokenType: ", requestedTokenType)

  return requestedTokenType
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

  local requestedTokenType = getRequestedTokenType(conf)

  -- add requestedTokenType parameter only for SAML, JWT is default anyway
  if ((requestedTokenType==TOKEN_TYPE_SAML1) or (requestedTokenType==TOKEN_TYPE_SAML2)) then
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
  if (onDebug()) then
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

  return accessToken, err, ttl
end


--[[
  get request authorization header
  return authorization header or error table 
--]]
local function getAuthorizationHeader()
  -- get authorization header from request  
  local authorization = kong.request.get_header(AUTHORIZATION)

  if not authorization then
    return nil, { message = "missing " .. AUTHORIZATION .. " header" }
  end

  return authorization, nil 
end


--[[
  check whether the autorization header is of type bearer  
  @return true or false (bearer token or not not bearer token)
--]]
local function isAuthorizationHeaderTypeBearer(authorization)
  local isBearer = false

  if (authorization ~= nil) then
    isBearer = pl_stringx.startswith(string.lower(authorization),string.lower(BEARER_PREFIX))
  end

  return isBearer 
end


--[[
  check whether the autorization header has a valid bearer token structure 
  @return true or false (valid bearer token structure)
--]]
local function isAuthorizationHeaderBearerValid(authorization)
  local isValidBearer = false

  if (authorization ~= nil) then
    if not (pl_stringx.startswith(string.lower(authorization),string.lower(BEARER_PREFIX))) then
      return false, { message = "missing bearer prefix" }
    end

    if not (pl_stringx.count(authorization,'.')==2) then
      return false, { message = "token does not have exact three dot-delimited parts" }
    end

    if not (pl_stringx.count(authorization,' ')==1) then
      return false, { message = "token does only allow a space between bearer prefix and dot-delimited parts" }
    end

    isValidBearer = true
  end

  return isValidBearer, nil
end


--[[
  get request jwt from request header and check structural integrity
  return jwt or error table 
--]]
local function getJWT()
  -- get authorization header from request  
  local authorization, err = getAuthorizationHeader()

  if (err) then
    kong.log.err("Unauthorized; " .. err.message)
    return nil, { status = 401, message = "Unauthorized; " .. err.message }
  end

  if (not(isAuthorizationHeaderTypeBearer(authorization))) then
    kong.log.err("Unauthorized; " .. AUTHORIZATION .. " is not type bearer")
    return nil, { status = 401, message = "Unauthorized; " .. AUTHORIZATION .. " is not type bearer" }
  end

  -- check bearer token for structural validity 
  local checkResult, checkErr = isAuthorizationHeaderBearerValid(authorization)

  if (checkErr) then
     kong.log.err("Unauthorized; " .. checkErr.message)
     return nil, { status = 401, message = "Unauthorized; " .. checkErr.message }
  end

  -- trim bearer prefix with sub (upper/lower case)
  local jsonWebToken = string.sub(authorization, string.len(BEARER_PREFIX)+1)

  return jsonWebToken, nil
end


--[[
  conformity check on access token 
  @param conf the kong plugin configuration  
  @param token the access token
  @return true/false
--]]
local function doJWTConformityCheck(conf,token)
  local siemEventMarker = ""

  if (conf.enable_siem) then
    siemEventMarker = conf.event_marker_siem
  end

  -- check on base64 parts existence <header_64>.<payload_64>.<signature_64>
  -- check base64 decoding validity of base64 parts
  -- secured token must have header parameter alg which must be supported (HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384)
  local jsonWebToken, err = jwt_parser:new(token)

  if (err) then
    kong.log.err(HTTP_CODE_500_INTERNAL_SERVER_ERROR, ", ", "invalid jwt token [" .. err .. "]", " ", siemEventMarker)
    kong.response.exit(HTTP_CODE_500_INTERNAL_SERVER_ERROR, "invalid jwt token [" .. err .. "]")
  end 

  kong.log.debug("token header: ", pl_pretty.write(jsonWebToken.header,"",false))
  kong.log.debug("token payload: ", pl_pretty.write(jsonWebToken.claims,"",false))

  return true
end


--[[
  do conformity check
  @param conf the kong plugin configuration  
  @param token SAML1 or SAML2 token
  @return true/false
--]]
local function doSAMLConformityCheck(conf,token)
  local siemEventMarker = ""

  if (conf.enable_siem) then
    siemEventMarker = conf.event_marker_siem
  end

  local samlXML = base64_decode(token)

  if (samlXML) then
    local success, samlDoc = pcall(xml.parse,samlXML)

    if (not(success)) then
      local err = samlDoc 

      kong.log.err(HTTP_CODE_500_INTERNAL_SERVER_ERROR, ", ", "invalid saml token [" .. err .. "]", " ", siemEventMarker)
      kong.response.exit(HTTP_CODE_500_INTERNAL_SERVER_ERROR, "invalid saml token [" .. err .. "]")
    end
  end

  return true
end


--[[
  conformity check
  @param conf the kong configuration
  @param token
  @return print secure token
--]]
local function conformityCheck(conf,token)
  local requestedTokenType = getRequestedTokenType(conf)

  kong.log.debug('requestedTokenType: ', requestedTokenType)
  kong.log.debug('token: ', token)

  if (conf.enable_conformity_check) then
    if (requestedTokenType==TOKEN_TYPE_JWT) then
      doJWTConformityCheck(conf,token)
    end

    if ((requestedTokenType==TOKEN_TYPE_SAML1) or (requestedTokenType==TOKEN_TYPE_SAML2)) then
      doSAMLConformityCheck(conf,token)
    end
  end

  return true
end


--[[
  remove JWT token signature
  @param token JWT token
  @return secure token without signature for printing
--]]
local function jwtRemoveSignature(token)
  local revBearerToken = token:reverse()
  return bearerToken:sub(1,#revBearerToken-revBearerToken:find('.',1,true)) .. '.' .. LOG_REDACTED
end


--[[
  remove SAML token signature
  @param token SAML token
  @return secure token without signature for printing
  note:
  - saml parser: https://samltool.io/
  - xml processing tutorial: https://clear-code.github.io/xmlua/tutorial/
--]]
local function samlRemoveSignature(token)
  local tokenWithoutSignature= ""

  local samlXML = base64_decode(token)

  if (samlXML) then
    local samlDoc = xml.parse(samlXML)

    local signatureNS = {
      {
        prefix = "signature",
        href = "http://www.w3.org/2000/09/xmldsig#",
      }
    }

    local signatureNoteSet = samlDoc:search("//signature:Signature",signatureNS)

    -- signatureNoteSet:unlink() 
    signatureNoteSet[1]:set_content("Signature " .. LOG_REDACTED)

    tokenWithoutSignature= ngx.encode_base64(samlDoc:to_xml())
  end

  return tokenWithoutSignature
end


--[[
  security aware token output
  @param conf the kong plugin configuration
  @param token the security token
  @return log token (secure because unusable due to signature removal)
--]]
local function logTokenSecurityAware(conf,token)
  local requestedTokenType = getRequestedTokenType(conf)

  if (onDebug()) then
    kong.log.debug('bearer token:', token)
  else
    local securityAwareToken = ''

    -- remove signature for security reasons
    if (requestedTokenType==TOKEN_TYPE_JWT) then
      securityAwareToken = jwtRemoveSignature(token)
    end

    if ((requestedTokenType==TOKEN_TYPE_SAML1) or (requestedTokenType==TOKEN_TYPE_SAML2)) then
      securityAwareToken = samlRemoveSignature(token)
    end

    kong.log.notice('bearer token:', securityAwareToken)
    -- chunker.logChunks(kong.log.notice,'bearer token:', securityAwareToken)
  end
end


--[[
  build bearer header
  @param accessToken
  @return bearer token
--]]
local function buildBearerHeader(accessToken)
  return BEARER_PREFIX .. accessToken
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
  note:
  Kong Caching - https://docs.konghq.com/gateway/latest/plugin-development/entities-cache/
--]]
function OAuth2OnBehalfOfHandler:access(conf)
  local startTimeMS = now(EPOCH_MSEC)

  kong.log.debug(LOG_HIGHLIGHT_PREFIX .. PLUGIN_NAME .. ' plugin enabled - access')
  logConf(conf)

  local accessToken = ""
  local accessTokenErr = {}

  local assertionToken, assertionTokenErr = getJWT()  
    
  if (assertionTokenErr) then
    return kong.response.exit(assertionTokenErr.status, { message = assertionTokenErr.message })
  end

  kong.log.debug("assertion token: ", assertionToken)

  if (conf.enable_caching) then
    -- get the assertion token claims 
    local assertionTokenParsed, assertionTokenParsedErr = jwt_parser:new(assertionToken)

    if (assertionTokenParsedErr) then
      kong.log.err("Bad assertion token; " .. tostring(assertionTokenParsedErr))
      return kong.response.exit(401, { message = "Unauthorized; bad token; " .. tostring(assertionTokenParsedErr) })
    end 

    kong.log.debug("assertion token parsed: ", pl_pretty.write(assertionTokenParsed.claims,"",false))

    -- cache key needs an unique user identifier, Keycload/AAD = preferred_username, AAD = oid (better than preferred_username)
    local user_identifier = assertionTokenParsed.claims[conf.user_identifier_claim]

    if ((not(user_identifier)) and (#user_identifier>0)) then
      return kong.response.exit(HTTP_CODE_401_UNAUTHORIZED, { message = "no valid user identifier at claim " .. conf.user_identifier_claim })
    end

    -- does the cache key also need the recipients that the JWT is intended for (e.g. aud)? taken out for now.
    local cacheKey = CACHE_KEY .. "#" .. conf.client_id .. "#" .. user_identifier

    if (onDebug()) then
      local remaining_ttl, err, value = kong.cache:probe(cacheKey)

      if (value) then
        kong.log.debug("cacheKey: ", cacheKey, " remaining ttl: ", remaining_ttl, " sec")
      else
         kong.log.debug("cacheKey: ", cacheKey, " not yet included in the cache")
      end
    end

    -- https://docs.konghq.com/gateway/latest/plugin-development/entities-cache/#cache-custom-entities
    accessToken, accessTokenErr = kong.cache:get(cacheKey, { ttl = conf.ttl }, doOnBehalfOfFlow, conf, assertionToken)

    if (accessTokenErr) then
      kong.log.err(HTTP_CODE_502_BAD_GATEWAY, ", ", pl_pretty.write(accessTokenErr,"",false))
    end
  else
    accessToken = doOnBehalfOfFlow(conf,assertionToken)
  end

  kong.log.debug('access token: ', accessToken)

  if (conf.enable_conformity_check) then
    conformityCheck(conf,accessToken)
  end

  -- logging: remove signature and thereby invalidate the token if the log level is other than debug 
  logTokenSecurityAware(conf,accessToken)

  if (conf.keep_original_token) then
    kong.service.request.clear_header('original_' .. AUTHORIZATION)
    kong.service.request.set_header('original_' .. AUTHORIZATION, buildBearerHeader(assertionToken))
  end
  
  kong.service.request.clear_header(AUTHORIZATION)
  kong.service.request.set_header(AUTHORIZATION, buildBearerHeader(accessToken))

  kong.log.notice(PLUGIN_NAME, ": OBO successfully executed, proxying towards upstream")

  if (conf.stopwatch) then
    kong.log.info(PLUGIN_NAME, " plugin stopwatch - access: ", tostring(now(EPOCH_MSEC)-startTimeMS))
  end
end

return OAuth2OnBehalfOfHandler
