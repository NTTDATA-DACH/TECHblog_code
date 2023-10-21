# Secrets-Demo 

This folder contains the sample code for the for NTT DATA DACH tech blog article "Secrets Handling in Kubernetes"

## Pre-Requisites

* make (recommended)
* [Java 17](https://adoptium.net/de/temurin/archive/?version=17)
* [Apache Maven](https://maven.apache.org/download.cgi)
* Kubernetes Cluster: e.g. [Rancher Desktop](https://rancherdesktop.io/)
* bash (Linux, MacOS) or git-bash (part of [git](https://git-scm.com/) for Windows)

For the "sealed secrets" demo, [kubeseal](https://github.com/bitnami-labs/sealed-secrets#installation-from-source) needs to be installed.

### Installations

#### Linux

Depending on the Linux distribution the packages which contains the tools may differ. Please refer to the documentation of the respective tool.

#### Windows
Many of the required utilities (like make) can be installed with [Chocolatey](https://chocolatey.org/)

```bash
choco install make
```

### Demos

#### Standard

```bash
make deploy_std
```

#### Sealed Secrets

```bash
make deploy_sealed
```

#### External Secrets Operator

```bash
make deploy_eso
```

### Port Forwarding and testing

To test the deployed demo, start the port-forwarding like this

```bash
./start_port_forwarding.sh
```

The script will start the port-forwarding as a background process and print the PID, so that it can be stopped later just by

```bash
kill <pid>
```

Where &lt;pid&gt; needs to be replaced with the PID which was printed by the start_port_forwarding.sh script.

When the port forwarding has started, the REST endpoint can be called with curl:

```bash
curl http://localhost:8080/secrets
```
