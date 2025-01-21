package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kingpin/v2"
	cfocsp "github.com/cloudflare/cfssl/ocsp"

	"ocspcrl/internal/ocsp_source"
)

type responder struct {
	certificatePath string
	keyPath         string
}

type crlSourceFile struct {
	path string
}

type addresses struct {
	ocsp string
	crl  string
}

type configuration struct {
	responder     *responder
	caCrtPath     string
	crlSourceType string
	crlSourceFile *crlSourceFile
	addresses     *addresses
}

func main() {
	config := &configuration{
		responder:     &responder{},
		crlSourceFile: &crlSourceFile{},
		addresses:     &addresses{},
	}
	app := kingpin.New("ocspcrl", "OCSP responder / CRL server")
	app.HelpFlag.Short('h')
	app.Flag("responder.certificate-path", "Path to the responder certificate").Envar("RESPONDER_CERTIFICATE_PATH").Required().ExistingFileVar(&config.responder.certificatePath)
	app.Flag("responder.key-path", "Path to the responder key").Envar("RESPONDER_KEY_PATH").Required().ExistingFileVar(&config.responder.keyPath)
	app.Flag("ca-crt-path", "Path to the CA certificate").Envar("CA_CRL_PATH").Required().ExistingFileVar(&config.caCrtPath)
	app.Flag("crl-source-type", "Type of CRL source").Envar("CRL_SOURCE").Default("file").EnumVar(&config.crlSourceType, "file")
	app.Flag("source.file.path", "Path to the CRL file").Envar("SOURCE_FILE_PATH").ExistingFileVar(&config.crlSourceFile.path)
	app.Flag("ocsp.listen-address", "Address for ocsp endpoint").Envar("OCSP_LISTEN_ADDRESS").Default(":8080").StringVar(&config.addresses.ocsp)
	app.Flag("crl.listen-address", "Address for crl endpoint").Envar("CRL_LISTEN_ADDRESS").Default(":8081").StringVar(&config.addresses.crl)
	kingpin.MustParse(app.Parse(os.Args[1:]))

	responderKeyPair, loadResponderKeyPairError := tls.LoadX509KeyPair(config.responder.certificatePath, config.responder.keyPath)
	if loadResponderKeyPairError != nil {
		panic(loadResponderKeyPairError)
	}

	caCrtContent, openCaCrtError := os.ReadFile(config.caCrtPath)
	if openCaCrtError != nil {
		panic(openCaCrtError)
	}
	block, rest := pem.Decode(caCrtContent)
	if len(rest) > 0 {
		panic("failed to decode ca certificate")
	}
	caCertificate, loadCaCertificateError := x509.ParseCertificate(block.Bytes)
	if loadCaCertificateError != nil {
		panic(loadCaCertificateError)
	}

	source := ocsp_source.NewCrlSource(caCertificate, responderKeyPair)
	loadCrlError := source.LoadCrlFromFile(config.crlSourceFile.path)
	if loadCrlError != nil {
		panic(loadCrlError)
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	responder := cfocsp.NewResponder(source, nil)
	listenError := http.ListenAndServe(config.addresses.ocsp, responder)
	if listenError != nil {
		panic(listenError)
	}

	// TODO: Implement CRL server
}
