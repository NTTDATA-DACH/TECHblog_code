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

  name = "oauth2-saml2-bearer/token"
  author = Alexander Suchier, NTT DATA Deutschland SE
  description = "Kong module for token processing"

--]]

local jwt = require "kong.plugins.oauth2-saml2-bearer.jwt"
local saml = require "kong.plugins.oauth2-saml2-bearer.saml"

local pl_stringx = require "pl.stringx"

local INTERNAL_SERVER_ERROR = 500

-- urn:ietf:params:oauth:token-type:jwt
local TOKEN_TYPE_JWT = "jwt"

-- urn:oasis:names:tc:SAML:1.0:assertion
-- urn:oasis:names:tc:SAML:1.1:assertion
local TOKEN_TYPE_SAML1 = "saml1"

-- urn:oasis:names:tc:SAML:2.0:assertion
local TOKEN_TYPE_SAML2 = "saml2"

-- urn does not exist
local TOKEN_TYPE_OPAQUE = "opaque"

local token = {}


--[[
  short form of token type without IETF namespace (urn:ietf:params:oauth:XXX)
  @param qualifiedTokenType > the full qualified IETF token namespace
  @return short token type
--]]
local function shortTokenType(qualifiedTokenType)
  local tokenType = ""

  if ((qualifiedTokenType==nil) or (string.len(qualifiedTokenType)==0)) then
     return nil, { status = INTERNAL_SERVER_ERROR, message = "no full qualified token" }
  end

  local tokenTypeParts = pl_stringx.split(qualifiedTokenType,':')

  if (tokenTypeParts) then
    tokenType = tokenTypeParts[#tokenTypeParts] 
  end

  return tokenType, nil
end


--[[
  do conformity check
  @param token > OPAQUE token
  @return true/false, error message
--]]
local function opaqueConformityCheck(opaqueToken)
  if (not(opaqueToken)) then
    return false, "no opaque token"
  end

  if (string.len(opaqueToken)<=10) then
    return false, "opaque token too short (<=10)"
  end

  return true, nil
end


--[[
  token type JWT
  @param tokenType > token type with full qualified namespace
  @return true/false
--]]
function token:isTokenTypeJWT(tokenType)
  local tinyTokenType, errorMsg = shortTokenType(tokenType)
  return (tinyTokenType==TOKEN_TYPE_JWT)
end


--[[
  token type SAML1
  @param tokenType > token type with full qualified namespace
  @return true/false
--]]
function token:isTokenTypeSAML1(tokenType)
  local tinyTokenType, errorMsg = shortTokenType(tokenType)
  return (tinyTokenType==TOKEN_TYPE_SAML1)
end


--[[
  token type SAML2
  @param tokenType > token type with full qualified namespace
  @return true/false
--]]
function token:isTokenTypeSAML2(tokenType)
  local tinyTokenType, errorMsg = shortTokenType(tokenType)
  return (tinyTokenType==TOKEN_TYPE_SAML2)
end


--[[
  token type OPAQUE
  @param tokenType > token type with full qualified namespace
  @return true/false
--]]
function token:isTokenTypeOPAQUE(tokenType)
  local tinyTokenType, errorMsg = shortTokenType(tokenType)
  return (tinyTokenType==TOKEN_TYPE_OPAQUE)
end


--[[
  conformity check
  @param uncheckedToken > token
  @param tokenType > token type with full qualified namespace
  @return true/false, error message
--]]
function token:conformityCheck(uncheckedToken,tokenType)
  local valid = false
  local errorMsg = nil

  local tinyTokenType = ""
  tinyTokenType, errorMsg = shortTokenType(tokenType)  

  if (tinyTokenType==TOKEN_TYPE_OPAQUE) then
    valid, errorMsg = opaqueConformityCheck(uncheckedToken)
  end

  if (tinyTokenType==TOKEN_TYPE_JWT) then
    valid, errorMsg = jwt:conformityCheck(uncheckedToken)
  end

  if ((tinyTokenType==TOKEN_TYPE_SAML1) or (tinyTokenType==TOKEN_TYPE_SAML2)) then
    valid, errorMsg = saml:conformityCheck(uncheckedToken)
  end

  return valid, errorMsg
end


return token
