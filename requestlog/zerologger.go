package requestlog

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog/log"
)

func Zerologger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		start := time.Now()
		defer func() {
			log.Trace().
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Str("from", r.RemoteAddr).
				Dur("duration", time.Since(start)).
				Int("status", ww.Status()).
				Msg("request finished")
		}()
		next.ServeHTTP(ww, r)
	})

}
