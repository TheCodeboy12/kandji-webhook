package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/smallstep/certificates/webhook"
	"github.com/smallstep/webhooks/pkg/server"
)

var (
	certFile         = os.Getenv("WEBHOOK_CERT_PATH")
	keyFile          = os.Getenv("WEBHOOK_KEY_PATH")
	clientCAs        = []string{os.Getenv("CLIENT_CA_CERT_PATH")}
	address          = os.Getenv("WEBHOOK_LISTEN_ADDR")
	webhookId        = os.Getenv("WEBHOOK_SHARED_ID")
	webhookSecret    = os.Getenv("WEBHOOK_SHARED_SECRET")
	kandjiApiKey     = os.Getenv("KANDJI_API_KEY")
	kandjiApiBaseUrl = os.Getenv("KANDJI_API_URL")
)

// For demonstration only. Do not hardcode or commit actual webhook secrets.
var webhookIDsToSecrets = map[string]server.Secret{
	webhookId: server.Secret{
		Signing: webhookSecret,
	},
}

func main() {
	caCertPool := x509.NewCertPool()

	for _, clientCA := range clientCAs {
		caCert, err := os.ReadFile(clientCA)
		if err != nil {
			log.Panic(err)
		}
		caCertPool.AppendCertsFromPEM(caCert)
	}

	s := http.Server{
		Addr: address,
		TLSConfig: &tls.Config{
			ClientCAs:  caCertPool,
			ClientAuth: tls.RequireAndVerifyClientCert,
		},
	}

	h := &server.Handler{
		Secrets: webhookIDsToSecrets,
		LookupX509: func(key string, csr *webhook.X509CertificateRequest) (any, bool, error) {
			// item, ok := db[key]
			item, ok, err := server.FindKandjiDevice(key, kandjiApiKey, kandjiApiBaseUrl)
			return item, ok, err
		},
		LookupSSH: func(key string, cr *webhook.SSHCertificateRequest) (any, bool, error) {
			item, ok, err := server.FindKandjiDevice(key, kandjiApiKey, kandjiApiBaseUrl)
			return item, ok, err
		},
		// AllowX509: func(cert *webhook.X509Certificate) (bool, error) {
		// 	cn := cert.Subject.CommonName
		// 	_, ok := db[cn]
		// 	return ok, nil
		// },
		// AllowSSH: func(cert *webhook.SSHCertificate) (bool, error) {
		// 	return true, nil
		// },
	}
	http.HandleFunc("/", h.EnrichX509)
	http.HandleFunc("/ssh/", h.EnrichSSH)
	// http.HandleFunc("/auth/", h.Authorize)
	// http.HandleFunc("/auth-ssh/", h.AuthorizeSSH)

	fmt.Printf("Listening on %s\n", s.Addr)
	err := s.ListenAndServeTLS(certFile, keyFile)
	log.Fatal(err)
}
