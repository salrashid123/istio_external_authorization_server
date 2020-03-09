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
   Sample test client that generates a Google OIDC token.
   To use, download a google serviceAccount JSON file
   https://github.com/salrashid123/google_id_token
   go run generateToken.go --key=your-sa.json --aud=http://foo.bar --v=10 -alsologtostderr
*/

const (
	googleRootCertURL      = "https://www.googleapis.com/oauth2/v3/certs"
	metadataIdentityDocURL = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity"
)

var (
	cfg = &genConfig{}
)

type genConfig struct {
	flkey string
	flaud string
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

func verifyGoogleIDToken(ctx context.Context, aud string, token string) (bool, error) {

	keySet := oidc.NewRemoteKeySet(ctx, googleRootCertURL)

	// https://github.com/coreos/go-oidc/blob/master/verify.go#L36
	var config = &oidc.Config{
		SkipClientIDCheck: false,
		ClientID:          aud,
	}
	verifier := oidc.NewVerifier("https://accounts.google.com", keySet, config)

	idt, err := verifier.Verify(ctx, token)
	if err != nil {
		return false, err
	}
	log.Printf("Verified id_token with Issuer %v: ", idt.Issuer)
	return true, nil
}

func init() {
	flag.StringVar(&cfg.flkey, "key", "", "(required) privateKey")
	flag.StringVar(&cfg.flaud, "aud", "", "(required) audience")

	flag.Parse()

	argError := func(s string, v ...interface{}) {
		glog.V(2).Infof("Invalid Argument error: "+s, v...)
		os.Exit(-1)
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

	// For Service Account
	idToken, err := getIDTokenFromServiceAccount(ctx, cfg.flkey, cfg.flaud)

	if err != nil {
		glog.Fatalf("%v", err)
	}

	fmt.Printf("%s\n", idToken)
	// verified, err := verifyGoogleIDToken(ctx, cfg.flaud, idToken)
	// if err != nil {
	// 	log.Fatalf("%v", err)
	// }
	// glog.V(2).Infof("Verify %v", verified)

}
