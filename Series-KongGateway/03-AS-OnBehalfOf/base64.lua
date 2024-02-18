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

  name = "oauth2-on-behalf-of/base64"
  author = Alexander Suchier, NTT DATA Deutschland SE
  description = "Kong module for base64 encoding"

--]]

local ngxEncode = ngx.encode_base64
local ngxDecode = ngx.decode_base64

local base64 = {}


--[[
  base 64 encoding based on ngx functions
  @param input > string to base64 encode
  @return base64 encoded string
--]]
function base64:encode(input)
  local result = ngxEncode(input, true)
  result = result:gsub("+", "-"):gsub("/", "_")

  return result
end


--[[
  base 64 decode based on ngx functions
  @param input > string to base64 decode
  @return base64 decoded string
--]]
function base64:decode(input)
  local remainder = #input % 4

  if remainder > 0 then
    local padlen = 4 - remainder
    input = input .. string.rep("=", padlen)
  end

  input = input:gsub("-", "+"):gsub("_", "/")
  return ngxDecode(input)
end


return base64