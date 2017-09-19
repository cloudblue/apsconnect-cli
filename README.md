<p align="center">
	<img src="https://raw.githubusercontent.com/ingrammicro/apsconnect-cli/master/assets/logo.png" alt="logo"/>
</p>

# apsconnect-cli
_A command line tool for APS connector installation on Odin Automation in the relaxed way._

![pyversions](https://img.shields.io/pypi/pyversions/apsconnectcli.svg) [![Build Status](https://img.shields.io/travis/ingrammicro/apsconnect-cli/master.svg)](https://travis-ci.org/ingrammicro/apsconnect-cli) [![PyPi Status](https://img.shields.io/pypi/v/apsconnectcli.svg)](https://pypi.python.org/pypi/apsconnectcli)


## How to install
```
pip install apsconnectcli
```

### How to setup a kubernetes cluster
[Read a good step-by-step instruction by JetStack team](https://github.com/jetstack/kube-lego/tree/master/examples/nginx)

## Usage

#### 1 Connect your kubernetes (k8s) cluster

```
apsconnect init-cluster --cluster-endpoint CLUSTER_ENDPOINT \
                        --user USER --pwd PWD --ca-cert CA_CERT_FILE
```

```
⇒  apsconnect init-cluster k8s.cluster.host k8s-admin password ./my-k8s-cert.pem
Connectivity with k8s cluster api [ok]
k8s cluster version - v1.5.6
Config saved [/Users/allexx/.kube/config]
```

#### 2 Connect your Odin Automation Hub

```
apsconnect init-hub --hub-host HUB_HOST [--user USER] [--pwd PWD] \
                    [--use-tls USE_TLS] [--port PORT] [--aps-host APS_HOST] \
                    [--aps-port APS_PORT] [--use-tls-aps USE_TLS_APS]
```
```
⇒  apsconnect init-hub oa-hub-hostname
Connectivity with hub RPC API [ok]
Hub version oa-7.1-2188
Connectivity with hub APS API [ok]
Config saved [/Users/allexx/.aps_config]
```

#### 3. Install connector-backend in the k8s cluster

```
apsconnect install-backend --name NAME --image IMAGE --config-file CONFIG_FILE --hostname HOST \
                          [--healthcheck-path HEALTHCHECK_PATH] [--root-path ROOT_PATH] \
                          [--namespace NAMESPACE] [--replicas REPLICAS] [--tls-secret-name TLS_SECRET_NAME] \
                          [--force FORCE]
```

```
⇒  apsconnect install-backend connector_name image hostname config_file
Loading config file: /Users/allexx/config_file
Connect https://xxx [ok]
Create config [ok]
Create deployment [ok]
Create service [ok]
Create ingress [ok]
Checking service availability
.
Expose service [ok]
Connector backend - https://xxx
[Success]
```

#### 4. Install connector-frontend in Odin Automation Hub

```
apsconnect install-frontend --source SOURCE --oauth-key OAUTH_KEY --oauth-secret OAUTH_SECRET \
				            --backend-url BACKEND_URL [--settings-file SETTINGS_FILE] \
				            [--network = public ]
```
```
⇒  apsconnect install-frontend package.aps.zip application-3-v1-687fd3e99eb 639a0c2bf3ab461aaf74a5c622d1fa34 --backend-url http://127.197.49.26/
Importing connector http://aps.odin.com/app/connector
Connector http://aps.odin.com/app/connector imported with id=206 [ok]
Resource types creation [ok]
Service template "connector" created with id=16 [ok]
```

_Note that `--network proxy` enables support of outbound proxy. [More details](https://doc.apsstandard.org/7.1/concepts/backend/connectors/proxy/#setting-external-application-instance)_
## Misc

#### Check utility version
```
⇒ apsconnect version
apsconnect-cli v.1.6.11 built with love.
```

#### Generate Oauth credentials with helper command
```
apsconnect generate-oauth [--namespace]
```
```
⇒  apsconnect generate-oauth test
OAuh key: test-c77e25b1d6974a87b2ff7f58092d6007
Secret:   14089074ca9a4abd80ba45a19baae693
```

_Note that `--source` gets http(s):// or filepath argument._

#### Validate the k8s cluster and grab some useful data
```
⇒ apsconnect check-backend
Connect https://xxx [ok]
Service nginx-ingress-controller IP x.x.x.x
```

#### Enable APS Development mode
Allows using non-TLS connector-backend URL and [other features for debug](http://doc.apsstandard.org/2.2/process/test/tools/mn/#development-mode).
```
⇒ apsconnect aps-devel-mode
APS Development mode ENABLED
```
Disable mode with `--disable`.
```
⇒ apsconnect aps-devel-mode --disable
APS Development mode DISABLED.
```