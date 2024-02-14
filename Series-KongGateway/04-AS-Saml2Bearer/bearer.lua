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

  name = "oauth2-on-behalf-of/bearer"
  author = Alexander Suchier, NTT DATA Deutschland SE
  description = "Kong module for bearer processing"

--]]

local pl_stringx = require "pl.stringx"

local kong = kong

local BEARER_PREFIX = "Bearer "
local AUTHORIZATION = "Authorization"

local bearer = {}


--[[
  get request authorization header
  return authorization header, error message
--]]
local function authorizationHeader()
  -- get authorization header from request
  local authorization = kong.request.get_header(AUTHORIZATION)

  if (not(authorization)) then
    return nil, { message = "missing " .. AUTHORIZATION .. " header" }
  end

  return authorization, nil
end


--[[
  check whether the autorization header is of type bearer
  @param authorization > pure authorization header value
  @return true or false (bearer token or not bearer token)
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
  @param authorization > pure authorization header value
  @return true or false (valid bearer token structure)
--]]
local function isAuthorizationHeaderBearerValid(authorization)
  local isValidBearer = false

  if (authorization ~= nil) then
    if (not(isAuthorizationHeaderTypeBearer(authorization))) then
      return false, { message = "missing bearer prefix" }
    end

    if (not(pl_stringx.count(authorization,' ')==1)) then
      return false, { message = "token does only allow a space between bearer prefix and dot-delimited parts" }
    end

    -- minimum size of a bearer token depends on various factors, but I have not seen anything below 10 characters
    if ((string.len(authorization))<=(10+string.len(BEARER_PREFIX))) then
      return false, { message = "token could not be valid, too small" }
    end

    isValidBearer = true
  else
    return false, { message = "missing " .. AUTHORIZATION .. " header" }
  end

  return isValidBearer, nil
end


--[[
  get security token from request header and check structural integrity
  return bearer or error table
--]]
function bearer:token()
  -- get authorization header from request
  local authorization, authorizationErr= authorizationHeader()

  if (authorizationErr) then
    kong.log.err("Unauthorized; " .. authorizationErr.message)
    return nil, { status = 401, message = "Unauthorized; " .. authorizationErr.message }
  end

  local bearerValid, bearerValidErr = isAuthorizationHeaderTypeBearer(authorization)

  if (not(bearerValid)) then
    kong.log.err("Unauthorized; " .. AUTHORIZATION .. " is not type bearer; " .. bearerValidErr.message)
    return nil, { status = 401, message = "Unauthorized; " .. AUTHORIZATION .. " is not type bearer; " .. bearerValidErr.message }
  end

  -- check bearer token for structural validity
  local checkResult, checkErr = isAuthorizationHeaderBearerValid(authorization)

  if (checkErr) then
    kong.log.err("Unauthorized; " .. checkErr.message)
    return nil, { status = 401, message = "Unauthorized; " .. checkErr.message }
  end

  -- trim bearer prefix with sub (upper/lower case)
  local bearerToken = string.sub(authorization, string.len(BEARER_PREFIX)+1)

  return bearerToken, nil
end


--[[
  build bearer header
  @param token > token (SAML, JWT, opaque)
  @return bearer token
--]]
function bearer:buildBearerHeader(token)
  return BEARER_PREFIX .. token
end


return bearer
