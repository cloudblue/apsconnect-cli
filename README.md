<p align="center">
	<img src="https://raw.githubusercontent.com/ingrammicro/apsconnect-cli/master/assets/logo.png" alt="logo"/>
</p>

# apsconnect-cli
_A command line tool for APS connector installation on Odin Automation in the relaxed way._

![pyversions](https://img.shields.io/pypi/pyversions/apsconnectcli.svg) [![Build Status](https://img.shields.io/travis/ingrammicro/apsconnect-cli/master.svg)](https://travis-ci.org/ingrammicro/apsconnect-cli) [![PyPi Status](https://img.shields.io/pypi/v/apsconnectcli.svg)](https://pypi.python.org/pypi/apsconnectcli)


## How to install
APSConnect CLI tool is compatible with all recent Python releases of 2.7, 3.4, 3.5 and 3.6 versions.
Typically, all you need is just PyPI client, like [pip](https://pypi.python.org/pypi/pip):
```
pip install apsconnectcli
```

### Python releases before 2.7.9 (like CentOS 7.2)
CentOS 7.2 provide outdated Python 2.7.5 release, so you'll need an additional step to make it work properly:

1. Update the setuptools package
    ```
    pip install -U setuptools
    ```
1. Install backport of ssl.match_hostname()
    ```
    pip install -U backports.ssl-match-hostname
    ```
1. Install APSConnect CLI tool forcing requirements update
    ```
    pip install -U apsconnectcli
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
APSConnect-cli v.1.7.11
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
APSConnect-cli v.1.7.11
Connectivity with hub RPC API [ok]
Hub version oa-7.1-3256
Connectivity with hub APS API [ok]
Config saved [/Users/allexx/.aps_config]
```

#### 3. Install connector-backend in the k8s cluster

```
apsconnect install-backend --name NAME --image IMAGE --config-file CONFIG_FILE --hostname HOSTNAME \
                          [--healthcheck-path HEALTHCHECK_PATH] [--root-path ROOT_PATH] \
                          [--namespace NAMESPACE] [--replicas REPLICAS] [--tls-secret-name TLS_SECRET_NAME] \
                          [--force FORCE]
```
`Hostname` is the address to access your connector.

`Tls-secret-name` is the name of the certificate in Ingress for the specified hostname.
If the certificate doesn't exist, you can install [kube-lego](https://github.com/jetstack/kube-lego) to request and renew certificates automatically.

```
⇒  apsconnect install-backend connector_name image hostname config_file
APSConnect-cli v.1.7.11
Loading config file: /Users/allexx/config_file
Connect https://xxx [ok]
Create config [ok]
Create deployment [ok]
Create service [ok]
Create ingress [ok]
Checking service availability
..
Expose service [ok]
Checking connector backend availability
.....
Check connector backend host [ok]
Connector backend - https://xxx
[Success]
```

#### 4. Install connector-frontend in Odin Automation Hub

```
apsconnect install-frontend --source SOURCE --oauth-key OAUTH_KEY --oauth-secret OAUTH_SECRET \
				            --backend-url BACKEND_URL [--settings SETTINGS_FILE] \
				            [--network = proxy] [--hub-id HUB_ID] [--instance-only = false]
```
```
⇒  apsconnect install-frontend package.aps.zip application-3-v1-687fd3e99eb 639a0c2bf3ab461aaf74a5c622d1fa34 --backend-url http://127.197.49.26/
APSConnect-cli v.1.7.11
Importing connector http://aps.odin.com/app/connector
Connector http://aps.odin.com/app/connector imported with id=206 [ok]
Resource types creation [ok]
Service template "connector" created with id=16 [ok]
Limits for Service template "16" are applied [ok]
```

The `--settings` parameter is normally not required, it should point to a file containing data in JSON format that will be mixed in to application instance create API request.
Can be used to provide custom application instance global settings.

Use `--instance-only` flag if you wish to skip resource types and service templates creation.

**WARNING** Due to limitations of Operations Automation API importing large (more than a few megabytes) packages from local source might fail.
Use HTTP link as source for such packages.

## Misc

#### Check utility version
```
⇒ apsconnect version
apsconnect-cli v.1.7.11 built with love.
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
