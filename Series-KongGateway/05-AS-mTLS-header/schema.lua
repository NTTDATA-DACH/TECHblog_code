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

  name = "mtls-header/schema"
  author = Alexander Suchier, NTT DATA Deutschland SE
  description = "Kong plugin handler to set the consumer based on mTLS SAN header"

  note:
  - Penlight date module is deprecated: https://github.com/lunarmodules/Penlight/issues/285
    Recommendation for a Date library: https://github.com/daurnimator/luatz (is also used Kong internally)

--]]

local typedefs = require "kong.db.schema.typedefs"

return {
  name = "mtls-header",

  fields = {
    {
      consumer = typedefs.no_consumer
    },
    {
      protocols = typedefs.protocols_http
    },
    {
      config = {
        type = "record",
        fields = {
          -- the 'fields' array is the top-level entry with fields defined by Kong
          { anonymous = { type = "string", default = "anonymous", required = false, description = "An optional string (consumer UUID or username) value to use as an anonymous consumer if authentication fails. Defaults to anonymous." }, },
          { mtls_san_header_base64_encoded = { type = "boolean", default = true, required = false, description = "Activate, if the SAN header contains a base64-encoded value. Defaults to true." }, },
          { mtls_san_header_name = { type = "string", default = "X-Client-Cert-DNSName-SANs", required = true, description = "SAN (subject alternative name) header name with DNS tagging from perimeter security. Defaults to X-Client-Cert-DNSName-SANs." } },
          { mtls_valid_period_check_enabled = { type = "boolean", default = true, required = false, description = "Activate, if the period of validity should be checked. Defaults to true." }, },
          { mtls_valid_nbf_header_name = { type = "string", default = "X-Client-Cert-Valid-Not-Before", required = false, description = "Not-Before timestamp header name from perimeter security (indicating the start of validity). Defaults to X-Client-Cert-Valid-Not-Before." } },
          { mtls_valid_naf_header_name = { type = "string", default = "X-Client-Cert-Valid-Not-After", required = false, description = "Not-After timestamp header name from perimeter security (indicating the expiry time of validity). Defaults to X-Client-Cert-Valid-Not-After." } },
          { stopwatch = { type = "boolean", default = false, required = false, description = "Activate, if runtime of the plugin should be be measured (msec). Defaults to false." } },
        },
      },
    },
  },
}

