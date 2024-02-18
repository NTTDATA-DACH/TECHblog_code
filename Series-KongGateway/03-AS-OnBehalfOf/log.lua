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

  name = "oauth2-on-behalf-of/log"
  author = Alexander Suchier, NTT DATA Deutschland SE
  description = "Kong module for logging"

--]]

local jwt = require "kong.plugins.oauth2-on-behalf-of.jwt"
local saml = require "kong.plugins.oauth2-on-behalf-of.saml"
local token = require "kong.plugins.oauth2-on-behalf-of.token"

local pl_stringx = require "pl.stringx"

local kong = kong

--[[ enable, if log chunking is desired
local chunk_utils = require 'kong.modules.chunk_utils'
local chunker = chunk_utils.chunker
--]]

local LOG_LEVEL_DEBUG = 'debug'
local LOG_REDACTED = 'REDACTED4SECURITY'

local log = {}


--[[
  Kong on debug logging?
  @return Gateway on debug logging (true/false)
--]]
local function debugLogging()
  local logLevel = kong.configuration.log_level
  return ((logLevel~=nil) and (string.lower(logLevel)==LOG_LEVEL_DEBUG))
end


--[[
  Kong on debug logging?
  @return Gateway on debug logging (true/false)
--]]
function log:debugging()
  return debugLogging()
end


--[[
  invalidate opaque token
  @param unsafeToken > the opaque token
  @return the secure token invalidated
--]]
local function opaqueInvalidate(unsafeToken)
  return pl_stringx.shorten(unsafeToken,10) .. LOG_REDACTED
end


--[[
  security aware token 
  @param unsafeToken > the security token
  @param tokenType > the type of the security token
  @return the security aware token (secure because unusable for replay attack)
--]]
local function securityAwareToken(unsafeToken,tokenType)
  local safeToken = ''

  -- shorten token for security reasons
  if (token:isTokenTypeOPAQUE(tokenType)) then
    safeToken = opaqueInvalidate(unsafeToken)
  end

  -- remove signature for security reasons
  if (token:isTokenTypeJWT(tokenType)) then
    safeToken = jwt:removeSignature(unsafeToken)
  end

  if ((token:isTokenTypeSAML1(tokenType)) or (token:isTokenTypeSAML2(tokenType))) then
    safeToken = saml:removeSignature(unsafeToken)
  end

  return safeToken
end


--[[
  token logging security aware
  @param logPrefix > log prefix
  @param unsafeToken > the security token
  @param tokenType > the type of the security token
  @return The security aware token (secure because unusable for replay attack)
--]]
function log:tokenLoggingSecurityAware(logPrefix,unsafeToken,tokenType)
  local logToken = ''

  if ((unsafeToken~=nil) and (tokenType~=nil)) then
    if (debugLogging()) then
      logToken = unsafeToken

      kong.log.debug(logPrefix,logToken)
      -- chunker.logChunks(kong.log.debug,logPrefix,logToken)
    else
      logToken = securityAwareToken(unsafeToken,tokenType)

      kong.log.notice(logPrefix,logToken)
      -- chunker.logChunks(kong.log.notice,logPrefix,logToken)
    end
  end

  return logToken
end


return log