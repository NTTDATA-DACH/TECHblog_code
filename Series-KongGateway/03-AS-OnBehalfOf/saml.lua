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

  name = "oauth2-on-behalf-of/saml"
  author = Alexander Suchier, NTT DATA Deutschland SE
  description = "Kong module for SAML processing"

  note:
  - saml parser: https://samltool.io/
  - xml processing tutorial: https://clear-code.github.io/xmlua/tutorial/

--]]

local base64 = require "kong.plugins.oauth2-on-behalf-of.base64"
local xml = require "xmlua.xml"

local INTERNAL_SERVER_ERROR = 500
local LOG_REDACTED = 'REDACTED4SECURITY'

local saml = {}


--[[
  decoded and parse-able SAML token
  @param token > SAML token
  @return decoded token, valid and parse-able SAML token, error message
--]]
local function parser(token)
  if ((token==nil) or (string.len(token)==0)) then
     return nil, { status = INTERNAL_SERVER_ERROR, message = "no SAML token to parse" }
  end

  local samlXML = base64:decode(token)

  if (samlXML) then
    local success, samlRes = pcall(xml.parse,samlXML)

    if (success) then
      return samlXML, samlRes, nil
    else
      return samlXML, nil, { status = 500, message = "invalid saml token [" .. samlRes .. "]" }
    end
  end

  return samlXML, nil, nil
end


--[[
  get SAML assertion id
  @param token > SAML token
  @return the assertion id of the SAML token
--]]
function saml:assertionId(token)
  local assertionId = nil

  local samlXML, samlDoc, samlErr = parser(token)

  if (samlDoc) then
    local assertionElement = samlDoc:root()
    assertionId = assertionElement.ID
  end

  return assertionId
end


--[[
  remove SAML token signature
  @param token > SAML token
  @return the secure token without signature
--]]
function saml:removeSignature(token)
  local tokenWithoutSignature= ""

  local samlXML, samlDoc, samlErr = parser(token)

  if (samlDoc) then
    local signatureNS = {
      {
        prefix = "signature",
        href = "http://www.w3.org/2000/09/xmldsig#",
      }
    }

    local signatureNoteSet = samlDoc:search("//signature:Signature",signatureNS)
    signatureNoteSet[1]:set_content("Signature " .. LOG_REDACTED)

    tokenWithoutSignature= base64:encode(samlDoc:to_xml())
  end

  return tokenWithoutSignature
end


--[[
  do conformity check
  @param token > SAML1 or SAML2 token
  @return true/false, error message
--]]
function saml:conformityCheck(token)
  local samlXML, samlDoc, samlErr = parser(token)

  if (samlErr) then
     return false, samlErr
  end

  return true, nil
end


return saml
