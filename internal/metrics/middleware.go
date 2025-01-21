package metrics

import (
	"log"
	"net/http"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		timer := prometheus.NewTimer(httpDuration.With(prometheus.Labels{
			labelPath: path,
		}))
		rw := newResponseWriter(w)
		next.ServeHTTP(rw, r)
		if rw.statusCode == 0 {
			rw.WriteHeader(http.StatusOK)
		}
		statusCode := rw.statusCode

		responseStatus.With(prometheus.Labels{
			labelPath:   path,
			labelStatus: strconv.Itoa(statusCode),
		}).Inc()
		totalRequests.With(prometheus.Labels{
			labelPath: path,
		}).Inc()

		log.Printf("%s %s %s %d %s", r.RemoteAddr, r.Method, r.URL.Path, statusCode, timer.ObserveDuration())
	})
}
