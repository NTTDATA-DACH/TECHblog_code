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

# Add the HELM repository for sealed secrets
# --force-update: avoid error, if repo had been added before
helm repo add --force-update external-secrets https://charts.external-secrets.io

# Install the sealed secrets operator if not installed

kubectl -n external-secrets get deployment.apps/external-secrets 
if [ $? -ne 0 ] ; then
    echo "Installing external secrets operator via helm"
    helm install external-secrets external-secrets/external-secrets -n external-secrets --create-namespace
    echo "wait a little bit for the external secrets operator to become ready"
    sleep 60
else 
    echo "external secrets operator already present"
fi

echo "Creating Namespace"
kubectl apply -f src/main/k8s/standard/00_namespace.yaml

echo "Installing External Secret Store"
kubectl apply -f src/main/k8s/external_secrets/03_external_secret_store.yaml

echo "Installing External Secret Resource"
kubectl apply -f src/main/k8s/external_secrets/04_external_secret_resource.yaml

echo "Installing Application"
kubectl apply -f src/main/k8s/standard/02_deployment.yaml




