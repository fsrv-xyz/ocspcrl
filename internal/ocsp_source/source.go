package ocsp_source

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

type CrlSource struct {
	caCertificate        *x509.Certificate
	responderCertificate *x509.Certificate
	responderKey         crypto.Signer
	crl                  *x509.RevocationList
}

func NewCrlSource(caCertificate *x509.Certificate, responderKeyPair tls.Certificate) *CrlSource {
	return &CrlSource{
		caCertificate:        caCertificate,
		responderCertificate: responderKeyPair.Leaf,
		responderKey:         responderKeyPair.PrivateKey.(crypto.Signer),
	}
}

func (source *CrlSource) UseCrl(crl *x509.RevocationList) {
	source.crl = crl
}

func (source *CrlSource) Response(request *ocsp.Request) ([]byte, http.Header, error) {
	var buildResponseError error
	var response []byte

	for _, entry := range source.crl.RevokedCertificateEntries {
		// if the serial number is not the one we are looking for, skip
		if entry.SerialNumber.Cmp(request.SerialNumber) != 0 {
			continue
		}
		response, buildResponseError = source.buildRevokedResponse(entry.SerialNumber, entry.RevocationTime)
		break
	}
	if len(response) == 0 {
		response, buildResponseError = source.buildOkResponse(request.SerialNumber)
	}
	if buildResponseError != nil {
		return func() []byte { rsp, _ := source.buildServerErrorResponse(); return rsp }(), nil, buildResponseError
	}

	return response, nil, nil
}

func (source *CrlSource) buildRevokedResponse(serialNumber *big.Int, revocationTime time.Time) ([]byte, error) {
	return source.buildResponse(ocsp.Response{
		SerialNumber:     serialNumber,
		Status:           ocsp.Revoked,
		ThisUpdate:       time.Now(),
		Certificate:      source.responderCertificate,
		RevokedAt:        revocationTime,
		RevocationReason: ocsp.Unspecified,
	})
}

func (source *CrlSource) buildOkResponse(serialNumber *big.Int) (ocspResponse []byte, err error) {
	return source.buildResponse(ocsp.Response{
		SerialNumber: serialNumber,
		Status:       ocsp.Good,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(time.Hour),
		Certificate:  source.responderCertificate,
	})
}

func (source *CrlSource) buildServerErrorResponse() (ocspResponse []byte, err error) {
	return source.buildResponse(ocsp.Response{
		Status:     ocsp.ServerFailed,
		ThisUpdate: time.Now(),
	})
}

func (source *CrlSource) buildResponse(template ocsp.Response) (ocspResponse []byte, err error) {
	ocspResponse, err = ocsp.CreateResponse(
		source.caCertificate,
		source.responderCertificate,
		template,
		source.responderKey)
	return
}
