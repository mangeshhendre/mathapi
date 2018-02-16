package jwtclient

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
)

// Client is the basic struct for this client.
type Client struct {
	authkey    string
	authsecret string
	url        string
	insecure   bool
	token      *jwt.Token
}

// New takes a config struct, and returns a client struct.
func New(cfg *Config) (*Client, error) {

	client := Client{
		insecure:   cfg.Insecure,
		authkey:    cfg.AuthKey,
		authsecret: cfg.AuthSecret,
		url:        cfg.URL,
	}

	return &client, nil

}

// Authenticate is a jwt wrapper that returns the JWT token to be used on subsequent calls.
func (c *Client) Authenticate() (err error) {

	// Setup the request
	request, err := http.NewRequest("GET", c.url, nil)
	if err != nil {
		return
	}

	// Set our auth parameters.
	request.SetBasicAuth(c.authkey, c.authsecret)

	// Get a config to override potential SSL stuff.
	tlsConfig := &tls.Config{}

	// If we are insecure, then so be it.
	if c.insecure {
		tlsConfig.InsecureSkipVerify = true
	}

	// Create the transport
	tr := &http.Transport{TLSClientConfig: tlsConfig}

	// Create a client using that transport.
	client := &http.Client{Transport: tr}

	// Make the request
	webResponse, err := client.Do(request)
	if err != nil {
		return
	}

	defer webResponse.Body.Close()

	switch webResponse.StatusCode {
	case http.StatusOK:
		break
	case http.StatusUnauthorized:
		return fmt.Errorf("server returned unauthorized http code: %d", http.StatusUnauthorized)
	case http.StatusInternalServerError:
		return fmt.Errorf("server returned Internal Server Error code: %d", http.StatusInternalServerError)
	default:
		return fmt.Errorf("unexpected code received: %s", webResponse.Status)
	}

	// Get the body
	buffer := &bytes.Buffer{}
	io.Copy(buffer, webResponse.Body)

	// token, err := jwt.Parse(buffer.String(), c.KeyFunc)
	// A token is always returned.
	token, _ := jwt.Parse(buffer.String(), nil)

	err = token.Claims.Valid()
	if err == nil {
		c.token = token
	}

	return nil
}

// StillValid checks to see if the token we have is still valid.
func (c *Client) StillValid() bool {
	if c.token == nil {
		return false
	}

	err := c.token.Claims.Valid()
	if err == nil {
		return true
	}

	return false
}

// RetrieveToken checks to see if the token we have is still valid, re-authenticates if necessary and returns the token.
func (c *Client) RetrieveToken() (string, error) {

	// Is our token still valid?
	if c.StillValid() {
		return c.token.Raw, nil
	}

	// Must re-authenticate
	err := c.Authenticate()
	if err != nil {
		return "", fmt.Errorf("unable to authenticate: %s", err)
	}

	return c.token.Raw, nil
}

// KeyFuncFromPEMBytes returns a closure which in turn returns the public part of the JWT certificate from a file.
func KeyFuncFromPEMBytes(pemBytes []byte) (jwt.Keyfunc, error) {

	// Decode the certificate
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("unable to decode pem encoded certificate")
	}

	pub, err := x509.ParseCertificate(block.Bytes)
	// pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER encoded public key: " + err.Error())
	}

	return func(t *jwt.Token) (interface{}, error) {
		return pub.PublicKey, nil
	}, nil
}

// KeyFuncFromPEMFile returns a closure which in turn returns the public part of the JWT certificate from a file.
func KeyFuncFromPEMFile(fileLocation string) (jwt.Keyfunc, error) {

	pemFile, err := os.Open(fileLocation)
	if err != nil {
		return nil, fmt.Errorf("Unable to open file \"%s\", error: %s", fileLocation, err)
	}

	defer pemFile.Close()

	pemBytes := bytes.NewBuffer(nil)

	_, err = io.Copy(pemBytes, pemFile)
	if err != nil {
		return nil, fmt.Errorf("Unable to read file \"%s\", error: %s", fileLocation, err)
	}

	return KeyFuncFromPEMBytes(pemBytes.Bytes())

}

func KeyFuncFromCertDir(directory string) (jwt.Keyfunc, error) {
	certMap, err := PEMDirToCertMap(directory)
	if err != nil {
		return nil, err
	}
	return func(t *jwt.Token) (interface{}, error) {
		plainClaims, ok := t.Claims.(jwt.MapClaims)
		if !ok {
			return nil, fmt.Errorf("unable to determine issuer")
		}
		issuer := plainClaims["iss"].(string)
		cert, ok := certMap[issuer]
		if !ok {
			return nil, fmt.Errorf("No key found for issuer: %s", issuer)
		}
		return cert.PublicKey, nil
	}, nil
}

// PemBytesToKey turns a set of PEM bytes into a x509 certificate
func PEMBytesToCert(pemBytes []byte) (*x509.Certificate, error) {
	// Decode the certificate
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("unable to decode pem encoded certificate")
	}

	pub, err := x509.ParseCertificate(block.Bytes)
	// pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER encoded public key: " + err.Error())
	}
	return pub, nil
}

// PEMFileToCert turns a file location into a certificate.
func PEMFileToCert(fileLocation string) (*x509.Certificate, error) {
	pemBytes, err := ioutil.ReadFile(fileLocation)
	if err != nil {
		return nil, fmt.Errorf("unable to read file \"%s\", error: %v", fileLocation, err)
	}

	cert, err := PEMBytesToCert(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("cannot convert file to certificate: File: \"%s\", error: %v", fileLocation, err)
	}
	return cert, nil
}

// PEMDirToCertMap takes a directory as input and turns it into a map of certificates.
func PEMDirToCertMap(directory string) (map[string]*x509.Certificate, error) {
	files, err := ioutil.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("unable to process directory \"%s\", error: %v", directory, err)
	}

	pemMap := make(map[string]*x509.Certificate)

	for _, file := range files {
		issuer := path.Base(strings.TrimSuffix(file.Name(), path.Ext(file.Name())))
		cert, err := PEMFileToCert(path.Join(directory, file.Name()))
		if err != nil {
			log.Printf("Error reading in file: %s", err)
			continue
		}
		pemMap[issuer] = cert
	}
	return pemMap, nil
}
