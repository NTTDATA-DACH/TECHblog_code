/*
Disclaimer:
NTT DATA Deutschland SE gives no assurances regarding the suitability and usability of the code snippet provided here. The code snippet is provided
without warranty of any kind and may be used in any identical or edited form. Accordingly, NTT DATA Deutschland SE hereby excludes all warranties
and guarantees with respect to the code snippet, including all explicit, implied or statutory warranties and guarantees of merchantability, fitness
for purpose, title and non-infringement. In no event shall NTT DATA Deutschland SE be liable for any direct, indirect and/or consequential damages
and/or any damages whatsoever.

Haftungsausschluss:
Die NTT DATA Deutschland SE gibt keine Zusicherungen hinsichtlich der Eignung und Verwendbarkeit des hier zur Verfügung gestellten Codeschnipsels.
Der Codeschnipsel wird ohne Gewährleistung jeglicher Art bereitgestellt und kann beliebig identisch bzw. bearbeitet genutzt werden. Entsprechend
schließt die NTT DATA Deutschland SE hiermit sämtliche Gewährleistungen und Garantien in Bezug auf den Codeschnipsel aus, einschließlich sämtlicher
ausdrücklicher, konkludenter oder gesetzlicher Gewährleistungen und Garantien in Bezug auf Handelsüblichkeit, Eignung und Eigentum und Verletzung
von Rechten Dritter. In keinem Fall ist die NTT DATA Deutschland SE für direkte, indirekte Schäden und /oder Folgeschäden und / oder Schäden
welcher Art auch immer haftbar zu machen.
*/

package com.nttdata.dachtechblog;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;

import jakarta.ws.rs.core.MediaType;
import org.eclipse.microprofile.config.Config;

@Path("/secrets")
public class SecretsResource {

    @Inject
    Config config;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Secrets secrets() {
        Secrets secrets = new Secrets(config.getValue("secretvalue", String.class));
        return secrets;
    }
}
