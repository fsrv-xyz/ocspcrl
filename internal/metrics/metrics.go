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
		Name: "response_status",
		Help: "Status of HTTP response",
	}, []string{labelPath, labelStatus})

	httpDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "http_response_time_seconds",
		Help:    "Duration of HTTP requests.",
		Buckets: prometheus.DefBuckets,
	}, []string{labelPath})
)

func init() {
	prometheus.MustRegister(totalRequests)
	prometheus.MustRegister(responseStatus)
	prometheus.MustRegister(httpDuration)
}
