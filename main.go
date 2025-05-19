package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kingpin/v2"
	cfocsp "github.com/cloudflare/cfssl/ocsp"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"ocspcrl/internal/metrics"
	"ocspcrl/internal/ocsp_source"
)

type loadCrlFunction func() error

func loadCrlFromFile(path string) (*x509.RevocationList, error) {
	crlContent, openCrlError := os.ReadFile(path)
	if openCrlError != nil {
		return nil, openCrlError
	}

	// if the file contains a pem block, decode it
	// otherwise, assume it is a DER encoded CRL
	crlBlock := &pem.Block{}
	if bytes.Contains(crlContent, []byte("BEGIN")) {
		block, rest := pem.Decode(crlContent)
		if len(rest) > 0 {
			return nil, fmt.Errorf("failed to decode crl")
		}
		crlBlock = block
	} else {
		crlBlock = &pem.Block{Type: "X509 CRL", Bytes: crlContent}
	}

	crl, parseCrlError := x509.ParseRevocationList(crlBlock.Bytes)
	if parseCrlError != nil {
		return nil, parseCrlError
	}
	return crl, nil
}

func reloadCrlWorker(signal chan os.Signal, loadCrlFunc loadCrlFunction) {
	defer log.Println("reload crl worker stopped")
	for {
		select {
		case _, ok := <-signal:
			if !ok {
				return
			}
			loadCrlError := loadCrlFunc()
			if loadCrlError != nil {
				log.Printf("failed to reload crl: %v", loadCrlError)
			} else {
				log.Println("reloaded crl")
			}
		}
	}
}

type responder struct {
	certificatePath string
	keyPath         string
}

type crlSourceFile struct {
	path string
}

type configuration struct {
	responder                *responder
	caCrtPath                string
	crlSourceType            string
	crlSourceFile            *crlSourceFile
	applicationListenAddress string
	metricsListenAddress     string
}

func main() {
	log.SetFlags(log.Lshortfile)
	config := &configuration{
		responder:     &responder{},
		crlSourceFile: &crlSourceFile{},
	}
	app := kingpin.New("ocspcrl", "OCSP responder / CRL server")
	app.HelpFlag.Short('h')
	app.Flag("responder.certificate-path", "Path to the responder certificate").Envar("RESPONDER_CERTIFICATE_PATH").Required().ExistingFileVar(&config.responder.certificatePath)
	app.Flag("responder.key-path", "Path to the responder key").Envar("RESPONDER_KEY_PATH").Required().ExistingFileVar(&config.responder.keyPath)
	app.Flag("ca-crt-path", "Path to the CA certificate").Envar("CA_CRT_PATH").Required().ExistingFileVar(&config.caCrtPath)
	app.Flag("crl-source-type", "Type of CRL source").Envar("CRL_SOURCE").Default("file").EnumVar(&config.crlSourceType, "file")
	app.Flag("source.file.path", "Path to the CRL file").Envar("SOURCE_FILE_PATH").ExistingFileVar(&config.crlSourceFile.path)
	app.Flag("web.listen-address", "Address for application endpoint").Envar("WEB_LISTEN_ADDRESS").Default(":8080").StringVar(&config.applicationListenAddress)
	app.Flag("metrics.listen-address", "Address for metrics endpoint").Envar("METRICS_LISTEN_ADDRESS").Default("[::1]:8081").StringVar(&config.metricsListenAddress)
	kingpin.MustParse(app.Parse(os.Args[1:]))

	responderKeyPair, loadResponderKeyPairError := tls.LoadX509KeyPair(config.responder.certificatePath, config.responder.keyPath)
	if loadResponderKeyPairError != nil {
		log.Fatalf("failed to load responder key pair: %v", loadResponderKeyPairError)
	}

	caCrtContent, openCaCrtError := os.ReadFile(config.caCrtPath)
	if openCaCrtError != nil {
		log.Fatalf("failed to open ca certificate: %v", openCaCrtError)
	}
	block, rest := pem.Decode(caCrtContent)
	if len(rest) > 0 {
		log.Fatalln("failed to decode ca certificate")
	}
	caCertificate, loadCaCertificateError := x509.ParseCertificate(block.Bytes)
	if loadCaCertificateError != nil {
		log.Fatalf("failed to parse ca certificate: %v", loadCaCertificateError)
	}

	if !bytes.Equal(caCertificate.RawSubject, responderKeyPair.Leaf.RawIssuer) {
		log.Fatalf("responder certificate issuer does not match ca certificate subject; %+q != %+q", caCertificate.Subject.String(), responderKeyPair.Leaf.Issuer.String())
	}

	source := ocsp_source.NewCrlSource(caCertificate, responderKeyPair)

	crl := &x509.RevocationList{}

	loadCrl := func() error {
		curlCandidate, loadCrlError := loadCrlFromFile(config.crlSourceFile.path)
		if loadCrlError != nil {
			return loadCrlError
		}
		metrics.CrlEntries.Set(float64(len(curlCandidate.RevokedCertificateEntries)))
		source.UseCrl(*curlCandidate)
		crl = curlCandidate
		return nil
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	// initial load of the CRL
	if loadCrlError := loadCrl(); loadCrlError != nil {
		log.Fatalf("failed to load crl: %v", loadCrlError)
	}

	// on HUP reload the CRL
	hupChan := make(chan os.Signal, 1)
	signal.Notify(hupChan, syscall.SIGHUP)
	go reloadCrlWorker(hupChan, loadCrl)

	responder := cfocsp.NewResponder(source, nil)

	applicationRouter := http.NewServeMux()
	applicationRouter.Handle("/ocsp", responder)
	applicationRouter.Handle("/ocsp/", http.StripPrefix("/ocsp/", responder))
	applicationRouter.HandleFunc("/crl", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Write(crl.Raw)
	})
	applicationRouter.HandleFunc("/crl.pem", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		pem.Encode(w, &pem.Block{Type: "X509 CRL", Bytes: crl.Raw})
	})

	applicationServer := &http.Server{Addr: config.applicationListenAddress, Handler: metrics.Middleware(applicationRouter)}
	metricsSever := &http.Server{Addr: config.metricsListenAddress, Handler: promhttp.Handler()}

	applicationServerClosed := make(chan any)
	metricsServerClosed := make(chan any)
	go func() {
		log.Printf("starting application server on %+q", config.applicationListenAddress)
		if listenError := applicationServer.ListenAndServe(); listenError != nil {
			log.Printf("application error: %v", listenError)
		}
		close(applicationServerClosed)
	}()
	go func() {
		log.Printf("starting metrics server on %+q", config.metricsListenAddress)
		if listenError := metricsSever.ListenAndServe(); listenError != nil {
			log.Printf("metrics error: %v", listenError)
		}
		close(metricsServerClosed)
	}()

	<-signalChan
	close(hupChan)
	applicationServer.Shutdown(nil)
	metricsSever.Shutdown(nil)
	<-applicationServerClosed
	<-metricsServerClosed
}
