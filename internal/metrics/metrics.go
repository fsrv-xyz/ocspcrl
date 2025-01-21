package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

const (
	labelPath   = "path"
	labelStatus = "status"
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
)

func init() {
	prometheus.MustRegister(totalRequests)
	prometheus.MustRegister(responseStatus)
	prometheus.MustRegister(httpDuration)
	prometheus.MustRegister(CrlEntries)
}
