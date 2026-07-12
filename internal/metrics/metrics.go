package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

const (
	labelPath   = "path"
	labelStatus = "status"
	labelResult = "result"
)

// OCSP response status label values for OcspResponses.
const (
	OcspStatusGood        = "good"
	OcspStatusRevoked     = "revoked"
	OcspStatusServerError = "server_failed"
)

// CRL reload result label values for CrlReloads.
const (
	ReloadResultSuccess = "success"
	ReloadResultError   = "error"
)

var (
	totalRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Number of get requests.",
	}, []string{labelPath})

	responseStatus = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "http_response_status",
		Help: "Status of HTTP response",
	}, []string{labelPath, labelStatus})

	httpDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "http_response_time_seconds",
		Help:    "Duration of HTTP requests.",
		Buckets: prometheus.ExponentialBuckets(0.0001, 2, 10),
	}, []string{labelPath})

	CrlEntries = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "ocspcrl",
		Name:      "crl_entries_total",
		Help:      "Number of entries in the CRL",
	})

	CrlThisUpdate = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "ocspcrl",
		Name:      "crl_this_update_timestamp_seconds",
		Help:      "Timestamp of the CRL's thisUpdate field (Unix seconds)",
	})

	CrlNextUpdate = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "ocspcrl",
		Name:      "crl_next_update_timestamp_seconds",
		Help:      "Timestamp of the CRL's nextUpdate field (Unix seconds)",
	})

	CrlNumber = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "ocspcrl",
		Name:      "crl_number",
		Help:      "Sequence number of the CRL",
	})

	CrlLastReload = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "ocspcrl",
		Name:      "crl_last_reload_timestamp_seconds",
		Help:      "Timestamp of the last successful CRL reload (Unix seconds)",
	})

	CrlReloads = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "ocspcrl",
		Name:      "crl_reloads_total",
		Help:      "Number of CRL reload attempts by result",
	}, []string{labelResult})

	OcspResponses = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "ocspcrl",
		Name:      "ocsp_responses_total",
		Help:      "Number of OCSP responses by status",
	}, []string{labelStatus})

	ResponderCertNotAfter = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "ocspcrl",
		Name:      "responder_cert_not_after_timestamp_seconds",
		Help:      "Expiry (notAfter) of the OCSP responder certificate (Unix seconds)",
	})

	CaCertNotAfter = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "ocspcrl",
		Name:      "ca_cert_not_after_timestamp_seconds",
		Help:      "Expiry (notAfter) of the CA certificate (Unix seconds)",
	})
)

func init() {
	prometheus.MustRegister(totalRequests)
	prometheus.MustRegister(responseStatus)
	prometheus.MustRegister(httpDuration)
	prometheus.MustRegister(CrlEntries)
	prometheus.MustRegister(CrlThisUpdate)
	prometheus.MustRegister(CrlNextUpdate)
	prometheus.MustRegister(CrlNumber)
	prometheus.MustRegister(CrlLastReload)
	prometheus.MustRegister(CrlReloads)
	prometheus.MustRegister(OcspResponses)
	prometheus.MustRegister(ResponderCertNotAfter)
	prometheus.MustRegister(CaCertNotAfter)
}
