#!/usr/bin/env bash

#
# Disclaimer:
# NTT DATA Deutschland SE gives no assurances regarding the suitability and usability of the code snippet provided here. The code snippet is provided
# without warranty of any kind and may be used in any identical or edited form. Accordingly, NTT DATA Deutschland SE hereby excludes all warranties 
# and guarantees with respect to the code snippet, including all explicit, implied or statutory warranties and guarantees of merchantability, fitness
# for purpose, title and non-infringement. In no event shall NTT DATA Deutschland SE be liable for any direct, indirect and/or consequential damages
# and/or any damages whatsoever.
#
# Haftungsausschluss:
# Die NTT DATA Deutschland SE gibt keine Zusicherungen hinsichtlich der Eignung und Verwendbarkeit des hier zur Verfügung gestellten Codeschnipsels.
# Der Codeschnipsel wird ohne Gewährleistung jeglicher Art bereitgestellt und kann beliebig identisch bzw. bearbeitet genutzt werden. Entsprechend
# schließt die NTT DATA Deutschland SE hiermit sämtliche Gewährleistungen und Garantien in Bezug auf den Codeschnipsel aus, einschließlich sämtlicher
# ausdrücklicher, konkludenter oder gesetzlicher Gewährleistungen und Garantien in Bezug auf Handelsüblichkeit, Eignung und Eigentum und Verletzung
# von Rechten Dritter. In keinem Fall ist die NTT DATA Deutschland SE für direkte, indirekte Schäden und /oder Folgeschäden und / oder Schäden
# welcher Art auch immer haftbar zu machen.
#

if [ $# -lt 1 ] ; then
    echo -n "Enter Secret Value: "
    read -s VALUE
else 
    VALUE=$1
fi
 
SECRET_NAME=secrets-demo
TARGET_NAMESPACE=nttdata-dach-techblog-secrets-demo
CONTROLLER_NAMESPACE=default

OS=$(uname -a)

if [[ "${OS}" =~ ^MINGW.* ]] ; then
    KUBESEAL='/c/Program Files/Go/go/bin/kubeseal.exe'
    #KUBESEAL=~/projects/github/sealed-secrets/kubeseal
else
    KUBESEAL=${GOPATH}/bin/kubeseal
fi

kubectl create secret generic ${SECRET_NAME} --dry-run=client --from-literal=secretvalue="${VALUE}" -o yaml | \
    "${KUBESEAL}" --namespace=${TARGET_NAMESPACE} --controller-name=sealed-secrets --controller-namespace=${CONTROLLER_NAMESPACE} --format=yaml \
    > src/main/k8s/sealed_secrets/04_sealed_secret.yaml
