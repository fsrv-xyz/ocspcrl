package metrics

import (
	"net/http"
)

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{w, http.StatusOK}
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	if code != http.StatusOK {
		rw.ResponseWriter.WriteHeader(code)
	}
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}
