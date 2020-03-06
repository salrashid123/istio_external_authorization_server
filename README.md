# External Authorization Server with Istio


Tutorial to setup an external authorization server for istio.  In this setup, the `ingresss-gateway` will first send the inbound request headers to another istio service which check the header values submitted by the remote user/client.  If the header values passes some criteria, the external authorization server will instruct the authorization server to proceed with the request upstream.

The check criteria can be anything (kerberos ticket, custom JWT) but in this example, it is the simple presence of the header value match as defined in configuration.

In this setup, it is important to ensure the authorization server is always (and exclusively) called by the ingress gateway and that the upstream services must accept the custom JWT token issued by the authorization server.

To that end, this configuration sets up `mTLS`, `RBAC` and `ORIGIN` authentication.  RBAC ensures service->service traffic flows between the gateway, authorization server and the upstream systems.   Each upstream service will only allow `ORIGIN` JWT tokens issued by the authorization server.


![images/istio-extauthz.svg](images/istio-extauthz.svg)

This tutorial is a continuation of the [istio helloworld](https://github.com/salrashid123/istio_helloworld) application.

### References

- [Envoy External Authorization](https://www.envoyproxy.io/docs/envoy/latest/api-v2/config/filter/http/ext_authz/v2/ext_authz.proto)
  - [Envoy External Authorization server (envoy.ext_authz) HelloWorld](https://github.com/salrashid123/envoy_external_authz)
- [Istio Security](https://istio.io/docs/concepts/security/)


### Setup

The following setup uses a Google Cloud Platform GKE cluster and Service Accounts certificates to issue the custom JWT tokens by the authorization server.  We are using GCP service accounts for the authhorization server JWTs simply because each service account on GCP has a convenient public JWK url for validation.


#### Set Environment Variables

On any GCP project, setup env vars and service accounts


```bash
export PROJECT_ID=`gcloud config get-value core/project`
export PROJECT_NUMBER=`gcloud projects describe $PROJECT_ID --format="value(projectNumber)"`
export SA_NAME=ext-authz-server

export SERVICE_ACCOUNT_EMAIL=$SA_NAME@$PROJECT_ID.iam.gserviceaccount.com
```

#### Create Service Account

```bash
gcloud iam service-accounts create $SA_NAME --display-name "Ext-Authz Server Service Account"
gcloud iam service-accounts keys  create svc_account.p12 --iam-account=$SA_NAME@$PROJECT_ID.iam.gserviceaccount.com --key-file-type=p12
```

The output should show the keyID (note this down)

 note the KeyID (eg)  `created key [7359f4d1a9a049b15d972b803c476f03cdd16957] of type [p12] as [svc_account.p12]`

Convert the key to PEM, remove the passphrase and then to base64

```bash
openssl pkcs12 -in svc_account.p12  -nocerts -nodes -passin pass:notasecret | openssl rsa -out private.pem
base64 -w 0 private.pem && echo
```

Note down the base64 encoded form of the key, we will need this and the KeyID later when defining the `ConfigMap` and `Secret` for the authorization server.

### Build and push images

You can use the following prebuilt containers for this tutorial if you want to. 

If you would rather build and stage your own, the `Dockerfile` for each container is provided in this repo.   

The images we will use here has the following endpoints enabled:

* `salrashid123/svc`: Frontend service
  - `/version`:  Displays a static "version" number for the image.  If using `salrashid123/svc:1` then the version is `1`. If using `salrashid123/svc:2` the version is `2`
  - `/backendz`:  Makes an HTTP Ret call to the backend service's `/backend` and `/headerz` endpoints.

* `salrashid123/besvc`: Backend Service
  - `/headerz`: Displays the http headers
  - `/backend`: Displays the pod name

* `salrashid123/ext-authz-server`: External Authorization gRPC Server
  - gRPC Authorization server running in namespace `authz-ns` as service `authz`
  - Authorization server reads an environment variable that lists the set of authorized (eg `authzallowedusers: "alice,bob"`)
    This server will read the "Authorization: Bearer <username>" header value from the incoming request to determine the username 


To build your own, create a public dockerhub images with the names specified below:

- Build External Aututhorization Server
```bash
cd authz_server/
docker build -t salrashid123/ext-authz-server .
docker push salrashid123/ext-authz-server
```
- Build Frontend
```
cd frontend 
docker build  --build-arg VER=1 -t salrashid123/svc:1 .
docker build  --build-arg VER=2 -t salrashid123/svc:2 .
docker push salrashid123/svc:1
docker push salrashid123/svc:2
```

- Build Backend
```
cd backend
docker build  --build-arg VER=1 -t salrashid123/besvc:1 .
docker build  --build-arg VER=1 -t salrashid123/besvc:2 .

docker push salrashid123/besvc:1
docker push salrashid123/besvc:2
```

### Create Cluster and install Istio

Create a GKE cluster (do not enable the istio addon GKE provides; we will install istio 1.5 manually)

```bash
gcloud container  clusters create istio-1 --machine-type "n1-standard-2" --zone us-central1-a  --num-nodes 4 --enable-ip-alias

gcloud container clusters get-credentials istio-1 --zone us-central1-a

kubectl create clusterrolebinding cluster-admin-binding --clusterrole=cluster-admin --user=$(gcloud config get-value core/account)

kubectl create ns istio-system
```

### Download and install istio 1.5+

As of `3/6/20`, [1.5.0](https://github.com/istio/istio/releases/tag/1.5.0-beta.4
) is in beta so we will do this the hard way.  I'll update this tutorial when 1.5 is released.

```bash
export ISTIO_VERSION=1.5.0-beta.4

https://github.com/istio/istio/releases/download/1.5.0-beta.4/istio-1.5.0-beta.4-linux.tar.gz
https://github.com/istio/istio/releases/download/1.5.0-beta.4/istioctl-1.5.0-beta.4-linux.tar.gz

 wget https://github.com/istio/istio/releases/download/$ISTIO_VERSION/istio-$ISTIO_VERSION-linux.tar.gz 
 tar xvf istio-$ISTIO_VERSION-linux.tar.gz 
 rm istio-$ISTIO_VERSION-linux.tar.gz 

 wget https://github.com/istio/istio/releases/download/$ISTIO_VERSION/istioctl-$ISTIO_VERSION-linux.tar.gz
  tar xvf istioctl-$ISTIO_VERSION-linux.tar.gz
 rm istioctl-$ISTIO_VERSION-linux.tar.gz

 wget https://storage.googleapis.com/kubernetes-helm/helm-v2.11.0-linux-amd64.tar.gz
 tar xf helm-v2.11.0-linux-amd64.tar.gz
 rm helm-v2.11.0-linux-amd64.tar.gz

 export PATH=`pwd`:`pwd`/linux-amd64/:$PATH

cd istio-$ISTIO_VERSION

istioctl manifest apply --set profile=demo \
   --set values.global.controlPlaneSecurityEnabled=true \
   --set values.global.mtls.enabled=true  \
   --set values.sidecarInjectorWebhook.enabled=true

kubectl label namespace default istio-injection=enabled
```

After all the services are in running mode, get the `GATEWAY_IP`

```bash
kubectl get no,po,rc,svc,ing,deployment -n istio-system

kubectl get svc istio-ingressgateway -n istio-system

export GATEWAY_IP=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
echo $GATEWAY_IP
```


### Deploy application

Deploy the baseline application without the external authorization server

```bash
kubectl apply -f app-deployment.yaml

$ kubectl get po,svc
NAME                         READY   STATUS    RESTARTS   AGE
pod/be-v1-84c45dcd84-2rwwm   2/2     Running   0          14s
pod/be-v2-64d9cf5fb4-p4c6b   2/2     Running   0          14s
pod/svc1-7fb765b454-kmsmw    2/2     Running   0          15s
pod/svc2-bbdbf49f4-r9fc2     2/2     Running   0          15s

NAME                 TYPE        CLUSTER-IP    EXTERNAL-IP   PORT(S)    AGE
service/be           ClusterIP   10.0.17.193   <none>        8080/TCP   15s
service/kubernetes   ClusterIP   10.0.16.1     <none>        443/TCP    20h
service/svc1         ClusterIP   10.0.22.126   <none>        8080/TCP   15s
service/svc2         ClusterIP   10.0.29.28    <none>        8080/TCP   15s
```

### Deploy Istio Gateway and services

```
kubectl apply -f istio-lb-certs.yaml
   (wait for maybe 10s)
kubectl apply -f istio-ingress-gateway.yaml
kubectl apply -f istio-app-config.yaml
```

### Send Traffic

Verify traffic for the frontend and backend services.  (we're using [jq](https://stedolan.github.io/jq/download/) to help parse the response)

```bash
# Access the frontend for svc1,svc2
curl -s --cacert certs/CA_crt.pem --resolve svc1.example.com:443:$GATEWAY_IP  https://svc1.example.com/version
curl -s --cacert certs/CA_crt.pem --resolve svc2.example.com:443:$GATEWAY_IP  https://svc2.example.com/version

# Access the backend through svc1,svc2
curl -s --cacert certs/CA_crt.pem --resolve svc1.example.com:443:$GATEWAY_IP  https://svc1.example.com/backendz | jq '.'
curl -s --cacert certs/CA_crt.pem --resolve svc2.example.com:443:$GATEWAY_IP  https://svc2.example.com/backendz
```

If you would rather run this in a loop:

```bash
 for i in {1..1000}; do curl -s --cacert certs/CA_crt.pem --resolve svc1.example.com:443:$GATEWAY_IP  https://svc1.example.com/version; sleep 1; done
```

##### Kiali Dashboard

If you want, launch the kiali dashboard (default password is `admin/admin`).  In a new window, run:

```
istioctl dashboard kiali
```
![images/default-traffic.png](images/default-traffic.png)

### Generate Authz config

Edit `ext_authz_filter.yaml` and apply the  `keyID` and output of the `base64` encoded PEM from the first stp

```yaml
---
apiVersion: v1
data:
  key.pem: b65encoded_pem_here
kind: Secret
metadata:
  name: svc-secret
  namespace: authz-ns
type: Opaque
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: authz-config
  namespace: authz-ns
data:
  authzallowedusers: "alice,bob"
  authzserverkeyid: "keyId_here"  <<<<<<<<<
  authzissuer: "SERVICE_ACCOUNT_EMAIL"  <<<<<<<<<
---
## ingress --> svc1
apiVersion: authentication.istio.io/v1alpha1
kind: Policy
metadata:
  name: svc1-authz-server-policy
  namespace: default
spec:
  targets:
  - name: svc1
  peers:
  - mtls: {}  
  origins:
  - jwt:
      issuer: "SERVICE_ACCOUNT_EMAIL" <<<<<<<<< 
      audiences:
      - "http://svc1.default.svc.cluster.local:8080/"    
      jwksUri: "https://www.googleapis.com/service_accounts/v1/jwk/SERVICE_ACCOUNT_EMAIL"  <<<<<<<<<          
  principalBinding: USE_ORIGIN
---
## ingress --> svc2
apiVersion: authentication.istio.io/v1alpha1
kind: Policy
metadata:
  name: svc2-authz-server-policy
  namespace: default
spec:
  targets:
  - name: svc2
  peers:
  - mtls: {}  
  origins:
  - jwt:
      issuer: "SERVICE_ACCOUNT_EMAIL" <<<<<<<<< 
      audiences:
      - "http://svc2.default.svc.cluster.local:8080/"      
      jwksUri: "https://www.googleapis.com/service_accounts/v1/jwk/SERVICE_ACCOUNT_EMAIL"  <<<<<<<<<           
  principalBinding: USE_ORIGIN
```

### Apply Authz config

Now apply the authz config

```bash
kubectl apply -f ext_authz_filter.yaml
```

The static/demo configuration here uses two users (`alice`, `bob`), two frontend services (`svc1`,`svc2`) one backend service with two labled versions (`be`, `version=v1`,`version=v2`).

The following conditions are coded into the authorization server:

- If the authorization server sees `alice`, it issues a JWT token with `svc1` as the target
- If the authorization server sees `bob`, it issues a JWT token with `svc2` as the target


```golang
			var aud string
			if token == "alice" {
				aud = "http://svc1.default.svc.cluster.local:8080/"
			} else if token == "bob" {
				aud = "http://svc2.default.svc.cluster.local:8080/"
			} else {
				aud = ""
			}
```

The net effect of that is `alice` can view `svc1`, `bob` can view `svc2` using `ORIGIN` authentication.

As Alice:

```bash
USER=alice

curl -s \
  --cacert certs/CA_crt.pem  --resolve svc1.example.com:443:$GATEWAY_IP \
  -H "Authorization: Bearer $USER" \
  -w " %{http_code}\n"  \
   https://svc1.example.com/version

>>>  1 200


curl -s \
  --cacert certs/CA_crt.pem  --resolve svc2.example.com:443:$GATEWAY_IP \
  -H "Authorization: Bearer $USER" \
  -w " %{http_code}\n"  \
   https://svc2.example.com/version

>>> Origin authentication failed. 401
```

As Bob:

```bash
USER=bob

curl -s \
  --cacert certs/CA_crt.pem  --resolve svc1.example.com:443:$GATEWAY_IP \
  -H "Authorization: Bearer $USER" \
  -w " %{http_code}\n"  \
   https://svc1.example.com/version

>>> Origin authentication failed. 401

curl -s \
  --cacert certs/CA_crt.pem  --resolve svc2.example.com:443:$GATEWAY_IP \
  -H "Authorization: Bearer $USER" \
  -w " %{http_code}\n"  \
   https://svc2.example.com/version

>>> 2 200
```

![images/authz_ns_flow_fe.png](images/authz_ns_flow_fe.png)

>> note, it seems the traffic from the gateway to the authorization server isn't correctly detected to be associated with the ingress-gateway (maybe a bug or some label is missing)

The configuration also defines Authorization policies on the service->service traffic.  Specifically, only `svc1` is allwed to connect to the backend service.  Since this is an Authorization call, the out put will be RBAC based error

```bash
USER=alice

curl -s \
  --cacert certs/CA_crt.pem  --resolve svc1.example.com:443:$GATEWAY_IP \
  -H "Authorization: Bearer $USER" \
  -w " %{http_code}\n"  \
   https://svc1.example.com/backendz | jq '.'


USER=bob

curl -s \
  --cacert certs/CA_crt.pem  --resolve svc2.example.com:443:$GATEWAY_IP \
  -H "Authorization: Bearer $USER" \
  -w " %{http_code}\n"  \
   https://svc2.example.com/backendz
```

Sample output

```bash
curl -s \
  --cacert certs/CA_crt.pem  --resolve svc1.example.com:443:$GATEWAY_IP \
  -H "Authorization: Bearer $USER" \
  -w " %{http_code}\n"  \
   https://svc1.example.com/backendz | jq '.'

[
  {
    "url": "http://be.default.svc.cluster.local:8080/backend",
    "body": "pod: [be-v1-84c45dcd84-2rwwm]    node: [gke-istio-1-default-pool-58e77124-1xw9]",
    "statusCode": 200
  },
  {
    "url": "http://be.default.svc.cluster.local:8080/headerz",
    "body": "{\"host\":\"be.default.svc.cluster.local:8080\",\"x-forwarded-proto\":\"http\",\"x-request-id\":\"71a8673a-7564-9edf-959d-9bc3fe00d5e0\",\"content-length\":\"0\",\"x-forwarded-client-cert\":\"By=spiffe://cluster.local/ns/default/sa/be-sa;Hash=00cba00d9f194c22ad08291149c6e54735767feaa6dc145a797d8adcc76195fa;Subject=\\\"\\\";URI=spiffe://cluster.local/ns/default/sa/svc1-sa\",\"x-b3-traceid\":\"12dcae5da349e6172dc7979181f7ec76\",\"x-b3-spanid\":\"2639cb184038b697\",\"x-b3-parentspanid\":\"2dc7979181f7ec76\",\"x-b3-sampled\":\"1\"}",
    "statusCode": 200
  }
]

USER=bob
curl -s \
  --cacert certs/CA_crt.pem  --resolve svc2.example.com:443:$GATEWAY_IP \
  -H "Authorization: Bearer $USER" \
  -w " %{http_code}\n"  \
   https://svc2.example.com/backendz  | jq '.'

[
  {
    "url": "http://be.default.svc.cluster.local:8080/backend",
    "body": "RBAC: access denied",
    "statusCode": 403
  },
  {
    "url": "http://be.default.svc.cluster.local:8080/headerz",
    "body": "RBAC: access denied",
    "statusCode": 403
  }
]
```

![images/authz_ns_flow_fe.png](images/authz_ns_flow_fe.png)


If you would rather run these tests in a loop
```bash
 for i in {1..1000}; do curl -s \
  --cacert certs/CA_crt.pem  --resolve svc1.example.com:443:$GATEWAY_IP \
  -H "Authorization: Bearer $USER" \
  -w " %{http_code}\n"  \
   https://svc1.example.com/version; sleep 1; done
```

---

At this point, the system is setup to to always use mTLS, ORIGIN and PEER authentication plus RBAC.

The external server is attached to the ingress gateway but you could also attach it to a sidecar for an endpoint.  In this mode, the authorization decision is done not at the ingress gateway but locally on a service's sidecar.  To use that mode, define the `EnvoyFilter` workloadLabel and listenerType. eg:

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: svc1-authz-filter
  namespace: default
spec:
  workloadLabels:
    app: svc1
  filters:
  - listenerMatch:
      listenerType: SIDECAR_INBOUND
      listenerProtocol: HTTP 
    insertPosition:
      index: FIRST           
    filterName: envoy.ext_authz
    filterType: HTTP
    filterConfig:
      grpc_service:
        envoy_grpc:
          cluster_name: patched.authz.authz-ns.svc.cluster.local  
```

If you do this, you will have to setup PEER policies that allow the service to connect and use the authorization server.


### Debugging

You can debug issues using these resources

- [Debugging Envoy and Istio](https://istio.io/docs/ops/diagnostic-tools/proxy-cmd/)
- [Security Problems](https://istio.io/docs/ops/common-problems/security-issues/)

To set the log level higher and inspect a pod's logs:

```bash
istioctl manifest apply --set values.global.proxy.accessLogFile="/dev/stdout"
```

- Ingress pod

```bash
INGRESS_POD_NAME=$(kubectl get po -n istio-system | grep ingressgateway\- | awk '{print$1}'); echo ${INGRESS_POD_NAME};

kubectl exec -ti $INGRESS_POD_NAME -n istio-syste -- /bin/bash
istioctl proxy-config log  $INGRESS_POD_NAME --level debug
kubectl logs -f --tail=0 $INGRESS_POD_NAME -n istio-system
istioctl dashboard envoy $INGRESS_POD_NAME.istio-system
istioctl experimental  authz check  $INGRESS_POD_NAME.istio-system
```
- Authz pod

```bash
AUTHZ_POD_NAME=$(kubectl get po -n authz-ns | grep authz\- | awk '{print$1}'); echo ${AUTHZ_POD_NAME};
istioctl proxy-config log  $AUTHZ_POD_NAME -n authz-ns  --level debug
kubectl logs -f --tail=0 $AUTHZ_POD_NAME -c authz-container -n  authz-ns
istioctl dashboard envoy $AUTHZ_POD_NAME.authnz-ns
istioctl experimental  authz check $AUTHZ_POD_NAME.authz-ns
```


