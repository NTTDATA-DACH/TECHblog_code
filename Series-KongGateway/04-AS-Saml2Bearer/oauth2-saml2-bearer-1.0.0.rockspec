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

  name = "oauth2-saml2-bearer/rockspec"
  author = Alexander Suchier, NTT DATA Deutschland SE
  description = "Kong plugin handler to retrieve access tokens via OAuth 2.0 SAML2 bearer flow"

  note:
  - RFC 7522: https://datatracker.ietf.org/doc/html/rfc7522

--]]

package = "oauth2-saml2-bearer"
version = "1.0.0"
supported_platforms = {"linux", "macosx"}
source = {
  url = "",
  tag = ""
}
description = {
  summary = "OAuth2 SAML2 bearer Flow",
  license = "Apache 2.0",
  maintainer = "Alexander Suchier, NTT DATA Deutschland SE", 
  detailed = [[
      saml2-bearer plugin.
  ]],
}
dependencies = {
  "lua ~> 5.1"
}
build = {
  type = "builtin",
  modules = {
    ["kong.plugins.oauth2-saml2-bearer.base64"] = "kong/plugin/oauth2-saml2-bearer/base64.lua",
    ["kong.plugins.oauth2-saml2-bearer.bearer"] = "kong/plugin/oauth2-saml2-bearer/bearer.lua",
    ["kong.plugins.oauth2-saml2-bearer.csrf"] = "kong/plugin/oauth2-saml2-bearer/csrf.lua",
    ["kong.plugins.oauth2-saml2-bearer.handler"] = "kong/plugin/oauth2-saml2-bearer/handler.lua",
    ["kong.plugins.oauth2-saml2-bearer.jwt"] = "kong/plugin/oauth2-saml2-bearer/jwt.lua",
    ["kong.plugins.oauth2-saml2-bearer.log"] = "kong/plugin/oauth2-saml2-bearer/log.lua",
    ["kong.plugins.oauth2-saml2-bearer.saml"] = "kong/plugin/oauth2-saml2-bearer/saml.lua",
    ["kong.plugins.oauth2-saml2-bearer.schema"] = "kong/plugin/oauth2-saml2-bearer/schema.lua",
    ["kong.plugins.oauth2-saml2-bearer.token"] = "kong/plugin/oauth2-saml2-bearer/token.lua"
  }
}
