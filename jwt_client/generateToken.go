package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"time"

	"golang.org/x/net/context"

	"golang.org/x/oauth2/google"

	"github.com/coreos/go-oidc"
	"github.com/golang/glog"
	"golang.org/x/oauth2/jws"
)

/*
   Sample test client that generates a Google OIDC token or a self-signed JWT

   To use, download a google serviceAccount JSON file

   for OIDC:
   go run generateToken.go --mode=oidc --key=/path/to/svc_account.json --aud=http://foo.bar --jwkUrl=https://www.googleapis.com/oauth2/v3/certs --issuer=https://accounts.google.com --v=10 -alsologtostderr

   for JWT:
   SVC_ACCOUNT_EMAIL=`cat /home/srashid/gcp_misc/certs/mineral-minutia-820-83b3ce7dcddb.json | jq -r '.client_email'`
   export $SVC_ACCOUNT_EMAIL
   go run generateToken.go --mode=jwt --key=/path/to/svc_account.json --aud=http://foo.bar --jwkUrl=https://www.googleapis.com/service_accounts/v1/jwk/$SVC_ACCOUNT_EMAIL --issuer=$SVC_ACCOUNT_EMAIL --v=10 -alsologtostderr

*/

const (
	metadataIdentityDocURL = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity"
)

var (
	cfg = &genConfig{}
)

type genConfig struct {
	flmode   string
	flkey    string
	flaud    string
	flissuer string
	fljwkUrl string
}

func getIDTokenFromServiceAccount(ctx context.Context, svcAccountkey string, audience string) (string, error) {
	data, err := ioutil.ReadFile(svcAccountkey)
	if err != nil {
		return "", err
	}

	conf, err := google.JWTConfigFromJSON(data, "")
	if err != nil {
		return "", err
	}

	header := &jws.Header{
		Algorithm: "RS256",
		Typ:       "JWT",
		KeyID:     conf.PrivateKeyID,
	}

	privateClaims := map[string]interface{}{"target_audience": audience}
	iat := time.Now()
	exp := iat.Add(time.Hour)

	payload := &jws.ClaimSet{
		Iss:           conf.Email,
		Iat:           iat.Unix(),
		Exp:           exp.Unix(),
		Aud:           "https://www.googleapis.com/oauth2/v4/token",
		PrivateClaims: privateClaims,
	}

	key := conf.PrivateKey
	block, _ := pem.Decode(key)
	if block != nil {
		key = block.Bytes
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		parsedKey, err = x509.ParsePKCS1PrivateKey(key)
		if err != nil {
			return "", err
		}
	}
	parsed, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		log.Fatal("private key is invalid")
	}

	token, err := jws.Encode(header, payload, parsed)
	if err != nil {
		return "", err
	}

	d := url.Values{}
	d.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	d.Add("assertion", token)

	client := &http.Client{}
	req, err := http.NewRequest("POST", "https://www.googleapis.com/oauth2/v4/token", strings.NewReader(d.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var y map[string]interface{}
	err = json.Unmarshal([]byte(body), &y)
	if err != nil {
		return "", err
	}
	return y["id_token"].(string), nil
}

func getIDTokenFromComputeEngine(ctx context.Context, audience string) (string, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", metadataIdentityDocURL+"?audience="+audience, nil)
	req.Header.Add("Metadata-Flavor", "Google")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	bodyString := string(bodyBytes)
	return bodyString, nil
}

func verifyGoogleIDToken(ctx context.Context, jwkUrl string, aud string, issuer string, token string) (bool, error) {

	keySet := oidc.NewRemoteKeySet(ctx, jwkUrl)

	// https://github.com/coreos/go-oidc/blob/master/verify.go#L36
	var config = &oidc.Config{
		SkipClientIDCheck: false,
		ClientID:          aud,
	}
	verifier := oidc.NewVerifier(issuer, keySet, config)
	idt, err := verifier.Verify(ctx, token)
	if err != nil {
		return false, err
	}
	glog.V(2).Infof("Verified id_token with Issuer %v: ", idt.Issuer)
	return true, nil
}

func getJWTTokenFromServiceAccount(ctx context.Context, svcAccountkey string, audience string) (string, error) {
	data, err := ioutil.ReadFile(svcAccountkey)
	if err != nil {
		return "", err
	}

	conf, err := google.JWTConfigFromJSON(data, "")
	if err != nil {
		return "", err
	}

	header := &jws.Header{
		Algorithm: "RS256",
		Typ:       "JWT",
		KeyID:     conf.PrivateKeyID,
	}

	privateClaims := map[string]interface{}{"some_claim": "some_value"}
	iat := time.Now()
	exp := iat.Add(time.Hour)

	payload := &jws.ClaimSet{
		Iss:           conf.Email,
		Iat:           iat.Unix(),
		Exp:           exp.Unix(),
		Aud:           audience,
		PrivateClaims: privateClaims,
	}

	key := conf.PrivateKey
	block, _ := pem.Decode(key)
	if block != nil {
		key = block.Bytes
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		parsedKey, err = x509.ParsePKCS1PrivateKey(key)
		if err != nil {
			return "", err
		}
	}
	parsed, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		log.Fatal("private key is invalid")
	}

	token, err := jws.Encode(header, payload, parsed)
	if err != nil {
		return "", err
	}
	return token, nil
}

func init() {
	flag.StringVar(&cfg.flmode, "mode", "oidc", "(required) mode  (oidc|jwt) ")
	flag.StringVar(&cfg.flkey, "key", "", "(required) privateKey")
	flag.StringVar(&cfg.flaud, "aud", "", "(required) audience")
	flag.StringVar(&cfg.flissuer, "issuer", "https://accounts.google.com", "issuer")
	flag.StringVar(&cfg.fljwkUrl, "jwkUrl", "https://www.googleapis.com/oauth2/v3/certs", "JWK url to verify")

	flag.Parse()

	argError := func(s string, v ...interface{}) {
		glog.V(2).Infof("Invalid Argument error: "+s, v...)
		os.Exit(-1)
	}

	if cfg.flmode != "oidc" && cfg.flmode != "jwt" {
		argError("-mode must be either oidc or jwt")
	}

	if cfg.flkey == "" {
		argError("-key not specified")
	}

	if cfg.flaud == "" {
		argError("-aud not specified")
	}

}

func main() {

	ctx := context.Background()

	if cfg.flmode == "oidc" {
		// For Service Account
		idToken, err := getIDTokenFromServiceAccount(ctx, cfg.flkey, cfg.flaud)

		if err != nil {
			glog.Fatalf("%v", err)
		}

		fmt.Printf("%s\n", idToken)

		verified, err := verifyGoogleIDToken(ctx, cfg.fljwkUrl, cfg.flaud, cfg.flissuer, idToken)
		if err != nil {
			log.Fatalf("%v", err)
		}
		glog.V(2).Infof("Verify %v", verified)
	} else if cfg.flmode == "jwt" {

		idToken, err := getJWTTokenFromServiceAccount(ctx, cfg.flkey, cfg.flaud)

		if err != nil {
			glog.Fatalf("%v", err)
		}

		fmt.Printf("%s\n", idToken)

		verified, err := verifyGoogleIDToken(ctx, cfg.fljwkUrl, cfg.flaud, cfg.flissuer, idToken)
		if err != nil {
			log.Fatalf("%v", err)
		}
		glog.V(2).Infof("Verify %v", verified)
	}

}
