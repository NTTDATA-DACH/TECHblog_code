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

  name = "oauth2-saml2-bearer/csrf"
  author = Alexander Suchier, NTT DATA Deutschland SE
  description = "Kong module for csrf processing"
  note:
  - learn about cookies: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies

--]]

local pl_pretty = require "pl.pretty"

local ngx_header = ngx.header
local kong = kong

local COOKIE = "Cookie"
local SET_COOKIE = "Set-Cookie"

local X_CSRF_TOKEN = "X-CSRF-Token"
local X_CSRF_TOKEN_FETCH = "Fetch"

local csrf = {}


--[[
  build client cookie
  @param cookies > client cookies table
  return table with single cookie keys/values
--]]
function buildCookie(cookies)
  local cookieStrings = {}

  for name, value in pairs(cookies) do
    table.insert(cookieStrings, string.format('%s=%s', name, value))
    kong.log.debug("set-cookie: ", name, ":", value)
  end

  return table.concat(cookieStrings, '; ')
end


--[[
  get x-csrf-token header
  return x-csrf-token header, error message
--]]
local function getXCSRFTokenHeader()
  -- get x-csrf-token header from response
  local xCSRFToken = ngx_header[X_CSRF_TOKEN]

  if (not(xCSRFToken)) then
    return nil, { message = "missing " .. X_CSRF_TOKEN .. " header" }
  end

  kong.log.debug("get ",X_CSRF_TOKEN," ", pl_pretty.write(xCSRFToken,"",false))

  return xCSRFToken, nil
end


--[[
  set x-csrf-token header
  @param xCSRFToken > x-csrf-token
  return x-csrf-token header
--]]
local function setXCSRFTokenHeader(xCSRFToken)
  -- set x-csrf-token header to request
  ngx.req.set_header(X_CSRF_TOKEN,xCSRFToken)

  kong.log.debug("set ",X_CSRF_TOKEN," ", xCSRFToken)

  return xCSRFToken
end


--[[
  get server set-cookie header
  return set-cookie header, error message
--]]
local function getSetCookieHeader()
  -- get set-cookie header from request
  local setCookie = ngx_header[SET_COOKIE]

  if (not(setCookie)) then
    return nil, { message = "missing " .. SET_COOKIE .. " header" }
  end

  kong.log.debug(SET_COOKIE," ", pl_pretty.write(setCookie,"",false))

  return setCookie, nil
end


--[[
  set server cookie header
  @param setCookie > fetched server set-cookie
  return cookie header
--]]
local function setCookieHeader(setCookie)
  -- set cookie header to request
  ngx.req.set_header(COOKIE,setCookie)

  kong.log.debug(COOKIE," ", pl_pretty.write(setCookie,"",false))

  return setCookie
end


--[[
  request CSRF response headers
--]]
function csrf:requestCSRFHeaders()
  kong.service.request.set_header(X_CSRF_TOKEN, X_CSRF_TOKEN_FETCH)
  kong.log.debug(X_CSRF_TOKEN, ": ", X_CSRF_TOKEN_FETCH)
end


--[[
  clear CSRF response headers
--]]
function csrf:clearCSRFHeaders()
  kong.response.clear_header(SET_COOKIE)
  kong.response.clear_header(X_CSRF_TOKEN)

  kong.log.debug("CSRF response headers cleared: ", SET_COOKIE, ", ", X_CSRF_TOKEN)
end


--[[
  get server x-csrf-token and set-cookie header
  @param access > access credential table
  return access table, error message
--]]
function csrf:getCSRFAccessCredentials(access)
  local accessErr = {}

  if (not(access)) then
    access={}
  end

  local xCSRFToken, xCSRFTokenErr = getXCSRFTokenHeader()
  access[X_CSRF_TOKEN] = xCSRFToken

  if (xCSRFTokenErr) then
    accessErr.xCSRFTokenErr = xCSRFTokenErr.message
  end

  local setCookie, setCookieErr = getSetCookieHeader()
  access[SET_COOKIE] = setCookie

  if (setCookieErr) then
    accessErr.setCookieErr = setCookieErr.message
  end

  return access, accessErr
end


--[[
  set client x-csrf-token and set-cookie header
  @param access > access credential table
  return access table, error message
--]]
function csrf:setCSRFAccessCredentials(access)
  local accessErr = {}

  if (access) then
    if (access[X_CSRF_TOKEN]) then
      setXCSRFTokenHeader(access[X_CSRF_TOKEN])
    else
      accessErr.xCSRFTokenErr = "no " .. X_CSRF_TOKEN
    end

    if (access[SET_COOKIE]) then
      setCookieHeader(access[SET_COOKIE])
    else
      accessErr.cookieErr = "no " .. SET_COOKIE
    end
  end

  return access, accessErr
end


--[[
  has client x-csrf-token and set-cookie credentials
  @param access > access credential table
  return true/false
--]]
function csrf:hasCSRFAccessCredentials(access)
  local hasCredentials = false

  if (access) then
    if ((access[X_CSRF_TOKEN]~=nil) and (access[SET_COOKIE]~=nil)) then
      hasCredentials = true
    end

    kong.log.debug("hasCredentials: ", hasCredentials)
  end

  return hasCredentials
end


--[[
  check whether the access err table has an error message
  @accessErr > access error
  return true/false
--]]
function csrf:isAccessErr(accessErr)
  if ((accessErr==nil) or ((type(accessErr)=="table") and (next(accessErr)==nil))) then
    return false
  end

  return true
end


return csrf