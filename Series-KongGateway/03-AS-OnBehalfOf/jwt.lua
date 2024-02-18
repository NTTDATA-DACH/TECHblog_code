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

  name = "oauth2-on-behalf-of/jwt"
  author = Alexander Suchier, NTT DATA Deutschland SE
  description = "Kong module for JWT processing"

--]]

local jwt_parser = require "kong.plugins.jwt.jwt_parser"

local pl_stringx = require "pl.stringx"

local HTTP_CODE_401_UNAUTHORIZED = 401
local INTERNAL_SERVER_ERROR = 500

local LOG_REDACTED = 'REDACTED4SECURITY'

local jwt = {}



--[[
  decoded and parse-able JWT token
  @param token > JWT token
  @return decoded token, valid and parse-able SAML token, error message
--]]
local function parser(token)
  if ((token==nil) or (string.len(token)==0)) then
     return nil, { status = INTERNAL_SERVER_ERROR, message = "no JWT token to parse" }
  end

  -- check on base64 parts existence <header_64>.<payload_64>.<signature_64>
  -- check base64 decoding validity of base64 parts <header.payload.signature>
  -- secured token must have header parameter alg which must be supported (HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384)
  local jwtToken, jwtTokenErr = jwt_parser:new(token)

  if (jwtTokenErr) then
    return false, { status = INTERNAL_SERVER_ERROR, message = "invalid jwt token [" .. jwtTokenErr .. "]" }
  end

  return jwtToken, nil
end


--[[
  get JWT token signature
  @param token > JWT token
  @return signature, error message
--]]
function jwt:signature(token)
  local parts = {}

  if ((token==nil) or (string.len(token)==0)) then
     return nil, { status = INTERNAL_SERVER_ERROR, message = "no JWT token" }
  end

  for part in token:gmatch("[^%.]+") do
    table.insert(parts,part)
  end

  -- part[3] contains the signature
  if (#parts~=3) then
      return nil, { status = HTTP_CODE_401_UNAUTHORIZED, message = "invalid jwt token [no signature]" }
  end

  return parts[3], nil
end


--[[
  get claim value
  @param token > JWT token
  @param claimName > claim name
  @return claim value, error message
--]]
function jwt:claimValue(token,claimName)
  local claimValue = nil

  if ((claimName==nil) or (string.len(claimName)==0)) then
     return nil, { status = INTERNAL_SERVER_ERROR, message = "no claim name to find in JWT" }
  end

  local jwtToken, jwtTokenErr = parser(token)

  if (jwtToken) then
    claimValue = jwtToken.claims[claimName]

    if (not(claimValue)) then
      return nil, { status = HTTP_CODE_401_UNAUTHORIZED, message = "no claim value " .. claimName .. " in JWT" }
    end
  else
    return nil, jwtTokenErr
  end

  return claimValue, nil
end


--[[
  remove JWT token signature
  @param token> JWT token
  @return secure token without signature
--]]
function jwt:removeSignature(token)
  local tokenWithoutSignature = ""

  local revToken = token:reverse()
  tokenWithoutSignature = token:sub(1,#revToken-revToken:find('.',1,true)) .. '.' .. LOG_REDACTED

  return tokenWithoutSignature
end


--[[
  syntactical check on JWT token
  @param token > JWT token
  @return true/false, error message
--]]
function jwt:syntaxCheck(token)

  if not (pl_stringx.count(token,'.')==2) then
    return false, { message = "token does not have exact three dot-delimited parts" }
  end

  return true, nil
end


--[[
  conformity check on access token
  @param token > access token
  @return true/false, error message
--]]
function jwt:conformityCheck(token)
  local jwtToken, jwtTokenErr = parser(token)

  if (jwtTokenErr) then
    return false, jwtTokenErr
  end

  return true, nil
end


return jwt
