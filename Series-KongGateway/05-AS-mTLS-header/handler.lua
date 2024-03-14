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

  name = "mtls-header/handler"
  author = Alexander Suchier, NTT DATA Deutschland SE
  description = "Kong plugin handler to set the consumer based on mTLS SAN header"

  note:
  - Penlight date module is deprecated: https://github.com/lunarmodules/Penlight/issues/285
    Recommendation for a date library: https://github.com/daurnimator/luatz (is also used Kong internally)

--]]

local constants = require "kong.constants"
local pretty = require "pl.pretty"

local parseDate = require "luatz".parse.rfc_3339

local kong = kong

local ngx_now = ngx.now
local ngx_update_time = ngx.update_time

local ngxDecode = ngx.decode_base64

local PLUGIN_VERSION = "0.0.1"
local PLUGIN_PRIORITY = 20000
local PLUGIN_NAME = "mtls-header"

local LOG_HIGHLIGHT_PREFIX = '################### '

local EPOCH_SEC = false
local EPOCH_MSEC = true


--[[
  get the time in seconds or milliseconds
  @param ms > defines time unit return
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
  fetch mtls-auth credentials from the db by cache key
  @param cacheKey > the cacheKey must be determined beforehand
  @return mtls-auth credentials
--]]
local function fetchMTLSAuthCredentialsByCacheKey(cacheKey)
  local credentials, err = kong.db.mtls_auth_credentials:select_by_cache_key(cacheKey)

  if (not(credentials)) then
    return nil, err
  end

  return credentials
end


--[[
  get mtls-auth credentials
  @param subjectName > the subject alternative name (SAN)
  @return mtls-auth credentials

  note:
    structure of mtls-auth credentials:
      id:           "bbe2128d-d64e-5de0-90f1-b08ea6e92223"      -- mTLS-auth id (generated), irrelevant
      created_at:   1708681645                                  -- epoch timestamp, irrelevant
      subject_name: "api-consumer.xxx.xxx.xxx"                  -- mTLS-auth subject name (SAN)
      consumer:     {id="ab98d163-9a14-4a46-8dde-254c2c04c695"} -- table with id (generated), that is the reference to the consumer entity
--]]
local function getMTLSAuthCredentials(subjectName)
  kong.log.debug("mtls-auth credentials search for subject name: ", subjectName)

  local credentialCacheKey = kong.db.mtls_auth_credentials:cache_key(subjectName, nil)
  kong.log.debug("mtls-auth credentials cache key is: ", credentialCacheKey)

  local credential, err = kong.cache:get(credentialCacheKey, nil, fetchMTLSAuthCredentialsByCacheKey, credentialCacheKey)

  if (err) then
    kong.log.err(err)
    return kong.response.exit(500, { message = "An unexpected error occurred" })
  end

  kong.log.debug("get mtls-auth credentials: ", pretty.write(credential,"",false))

  return credential
end


--[[
  get consumer
  @param lookupValue > could be an id (uuid 4) or username
  @return consumer

  note:
    structure of consumer entity:
      id:         "589e7b48-7782-43b9-a63a-84caa3df28d4" -- consumer id (generated)
      created_at: 1709110269                             -- epoch timestamp
      updated_at: 1709110269                             -- epoch timestamp
      tags:       {"api-consumer"}                       -- tags
      type:       0                                      -- type
      username:   "api-consumer"                         -- username
--]]
local function getConsumer(lookupValue)
  kong.log.debug("consumer search for lookup value: ", lookupValue)

  local consumerCacheKey = kong.db.consumers:cache_key(lookupValue)
  kong.log.debug("consumer cache key is: ", consumerCacheKey)

  -- free shipping
  local fetchConsumerByLookupValue = kong.client.load_consumer

  local consumer, err = kong.cache:get(consumerCacheKey, nil, fetchConsumerByLookupValue, lookupValue, true)

  if (err) then
    kong.log.err(err)
    return kong.response.exit(500, { message = "An unexpected error occurred" })
  end

  kong.log.debug("get consumer: ", pretty.write(consumer,"",false))

  return consumer
end


--[[
  get consumer via the link with mtls-auth credentials
  @param subjectName > the subject alternative name (SAN)
  @param anonymous > consumer uuid or username to use as anonymous consumer
  @return consumer, anonymousConsumer(boolean)
--]]
local function getConsumerByMTLSAuthCredentials(subjectName, anonymous)
  local consumer = nil
  local anonymousConsumer = false

  if (subjectName) then
    local mtlsAuthCredentials = getMTLSAuthCredentials(subjectName)

    if (mtlsAuthCredentials) then
      consumer = getConsumer(mtlsAuthCredentials.consumer.id)
    end
  else
    kong.log.info("no subject name, go for anonymous ...")
  end

  if ((not(consumer)) and (anonymous)) then
    anonymousConsumer = true
    consumer = getConsumer(anonymous)
  end

  return consumer, anonymousConsumer
end


--[[
  set consumer (see also the "showcase" key-auth example plugin)
  @param consumer > identified consumer entity (table)
  @param credentials > id (table), format {id="<id of consumer>"}, for anonymous nil
--]]
local function setConsumer(consumer, credential)
  kong.client.authenticate(consumer, credential)

  local setHeader = kong.service.request.set_header
  local clearHeader = kong.service.request.clear_header

  -- consumer must have id
  if ((consumer) and (consumer.id)) then
    setHeader(constants.HEADERS.CONSUMER_ID, consumer.id)
  else
    clearHeader(constants.HEADERS.CONSUMER_ID)
  end

  -- consumer could have a custom id
  if ((consumer) and (consumer.custom_id)) then
    setHeader(constants.HEADERS.CONSUMER_CUSTOM_ID, consumer.custom_id)
  else
    clearHeader(constants.HEADERS.CONSUMER_CUSTOM_ID)
  end

  -- consumer should have an username
  if ((consumer) and (consumer.username)) then
    setHeader(constants.HEADERS.CONSUMER_USERNAME, consumer.username)
  else
    clearHeader(constants.HEADERS.CONSUMER_USERNAME)
  end

  if (credential) then
    clearHeader(constants.HEADERS.ANONYMOUS)
  else
    setHeader(constants.HEADERS.ANONYMOUS, true)
  end
end


--[[
  set authenticated consumer via the link with mtls-auth credentials
  @param subjectName > the subject alternative name (SAN)
  @param anonymous > consumer uuid or username to use as anonymous consumer
--]]
local function setConsumerByMTLSAuthCredentials(subjectName, anonymous)
  local consumer = nil
  local anonymousConsumer = false

  for subjectNameValue in subjectName:gmatch("[^,%s]+") do
    kong.log.debug("lookup for subject name: ", subjectNameValue)

    consumer, anonymousConsumer = getConsumerByMTLSAuthCredentials(subjectNameValue, anonymous)

    if (consumer) then
      kong.log.debug("consumer ", consumer.username, " is anonymous: ", anonymousConsumer)

      if (anonymousConsumer) then
        setConsumer(consumer, nil)
        kong.log.debug("anonymous consumer set, search continues ...")
      else
        setConsumer(consumer, { id = consumer.id, })
        break -- we have a consumer, no need to continue
      end
    end
  end

  -- no real consumer and anonymous consumer found
  if (not(consumer)) then
    kong.log.err("consumer authentication failed. no anonymous consumer. unauthorized.")
    return kong.response.exit(401, { message = "Consumer authentication failed. No anonymous consumer. Unauthorized." })
  end
end


--[[
  get mtls san header value
  @param mtlsSANHeaderBase64Encoded > mtls san header value is base64 encoded
  @param mtlsSANHeaderName > mtls san header name
  @return mtls SAN header value
--]]
local function getMTLSSANHeaderValue(mtlsSANHeaderBase64Encoded,mtlsSANHeaderName)
  local mtlsSANHeaderValue = nil

  if (mtlsSANHeaderName) then
    mtlsSANHeaderValue = kong.request.get_header(mtlsSANHeaderName)
    kong.log.debug('mTLS SAN header value: ', mtlsSANHeaderValue)

    if (mtlsSANHeaderBase64Encoded) then
      mtlsSANHeaderValue = ngxDecode(mtlsSANHeaderValue)
      kong.log.debug('mTLS SAN header value base64-decoded: ', mtlsSANHeaderValue)
    end
  end

  return mtlsSANHeaderValue
end


--[[
  get mtls not-before header value
  @param mtlsISO8601TimestampHeaderName > mtls ISO 8601 (RFC 3339) timestamp header name
  @return ISO 8601 string, epoch time

  note:
    RFC 3339 is a subset of ISO 8601
--]]
local function getMTLSISO8601TimestampHeaderValue(mtlsISO8601TimestampHeaderName)
  local mtlsISO8601TimestampHeaderValue = nil
  local mtlsISO8601TimestampHeaderValueEpoch = nil

  if (mtlsISO8601TimestampHeaderName) then
    mtlsISO8601TimestampHeaderValue = kong.request.get_header(mtlsISO8601TimestampHeaderName)
    kong.log.debug('mTLS ISO 8601 timestamp header value: ', mtlsISO8601TimestampHeaderValue)

    if (mtlsISO8601TimestampHeaderValue) then
      local timeTable = parseDate(mtlsISO8601TimestampHeaderValue)

      if (timeTable) then
        mtlsISO8601TimestampHeaderValueEpoch = timeTable:timestamp()
        kong.log.debug('mTLS ISO 8601 timestamp epoch value for ', mtlsISO8601TimestampHeaderName, ': ', mtlsISO8601TimestampHeaderValueEpoch)
      else
        -- no compromises, finish the processing here and now
        kong.log.err("unparseable certification validity date. unauthorized.")
        return kong.response.exit(401, { message = "Unparseable certification validity date. Unauthorized." })
      end
    end
  end

  return mtlsISO8601TimestampHeaderValue, mtlsISO8601TimestampHeaderValueEpoch
end


--[[
  log the plugin configuration
  @param conf > the kong configuration
--]]
local function logConf(conf)
  kong.log.debug('plugin priority: ', PLUGIN_PRIORITY)
  kong.log.debug('conf.anonymous: ', conf.anonymous)
  kong.log.debug('conf.mtls_san_header_base64_encoded: ', conf.mtls_san_header_base64_encoded)
  kong.log.debug('conf.mtls_san_header_name: ', conf.mtls_san_header_name)
  kong.log.debug('conf.mtls_valid_period_check_enabled: ', conf.mtls_valid_period_check_enabled)
  kong.log.debug('conf.mtls_valid_nbf_header_name: ', conf.mtls_valid_nbf_header_name)
  kong.log.debug('conf.mtls_valid_naf_header_name: ', conf.mtls_valid_naf_header_name)
  kong.log.debug('conf.stopwatch: ', conf.stopwatch)
end


-- Kong ceremony

local MTLSHeaderHandler = {
  VERSION = PLUGIN_VERSION,
  PRIORITY = PLUGIN_PRIORITY
}


--[[
  plugin handler for the ngx access phase
  @param conf > the kong plugin configuration
--]]
function MTLSHeaderHandler:access(conf)
  local startTimeMS = now(EPOCH_MSEC)

  kong.log.debug(LOG_HIGHLIGHT_PREFIX .. PLUGIN_NAME .. ' plugin enabled - access')
  logConf(conf)

  -- adapt the behavior of the other authz plugins (basic-auth, key-auth, mtls-auth, jwt, etc.)
  if ((conf.anonymous) and (kong.client.get_credential())) then
    -- we're already authenticated, and we're configured for using anonymous,
    -- hence we're in a logical OR between auth methods and we're already done.
    return
  end

  if (conf.mtls_valid_period_check_enabled) then
    -- client_cert_valid_not_before: Timestamp (RFC 3339 date string format) before which the client certificate is not valid. 
    local mtlsNbfHeaderValue, mtlsNbfHeaderValueEpoch = getMTLSISO8601TimestampHeaderValue(conf.mtls_valid_nbf_header_name)

    if (mtlsNbfHeaderValueEpoch) then
      if (now(EPOCH_SEC)<mtlsNbfHeaderValueEpoch) then
        kong.log.err("certificate not yet valid ",mtlsNbfHeaderValue," [", mtlsNbfHeaderValueEpoch, "]")
        kong.response.exit(403, { message = "certificate not yet valid, " .. mtlsNbfHeaderValue })
      end
    else
      kong.log.err("no valid certificate not-before timestamp provided")
      kong.response.exit(403, { message = "no valid certificate not-before timestamp provided" })
    end

    -- client_cert_valid_not_after:  Timestamp (RFC 3339 date string format) after which the client certificate is not valid.
    local mtlsNafHeaderValue, mtlsNafHeaderValueEpoch = getMTLSISO8601TimestampHeaderValue(conf.mtls_valid_naf_header_name)

    if (mtlsNafHeaderValueEpoch ) then
      if (now(EPOCH_SEC)>mtlsNafHeaderValueEpoch) then
        kong.log.err("certificate no longer valid ",mtlsNafHeaderValue," [", mtlsNafHeaderValueEpoch, "]")
        kong.response.exit(403, { message = "certificate no longer valid, " .. mtlsNafHeaderValue })
      end
    else
      kong.log.err("no valid certificate not-after timestamp provided")
      kong.response.exit(403, { message = "no valid certificate not-after timestamp provided" })
    end
  end

  local mtlsSANHeaderValue = getMTLSSANHeaderValue(conf.mtls_san_header_base64_encoded,conf.mtls_san_header_name)
  setConsumerByMTLSAuthCredentials(mtlsSANHeaderValue, conf.anonymous)

  if (conf.stopwatch) then
    kong.log.info(PLUGIN_NAME .. " plugin stopwatch - access: " .. tostring(now(EPOCH_MSEC)-startTimeMS))
  end
end


return MTLSHeaderHandler
