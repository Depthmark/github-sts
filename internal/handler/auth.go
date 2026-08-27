package handler

import (
	"crypto/subtle"
	"net/http"
	"strconv"
	"strings"
)

// OptionalBearerAuth requires a matching Bearer token when authToken is
// non-empty. Credential comparison is constant-time to prevent timing-oracle
// recovery of the configured token byte-by-byte.
func OptionalBearerAuth(authToken, realm string, next http.Handler) http.Handler {
	if authToken == "" {
		return next
	}

	expected := []byte(authToken)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, credential, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		// subtle.ConstantTimeCompare returns 0 when the lengths differ,
		// without leaking which prefix bytes match. The expected length is
		// fixed per deployment and is not treated as secret.
		if !ok || !strings.EqualFold(scheme, "Bearer") || subtle.ConstantTimeCompare([]byte(credential), expected) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer realm="+strconv.Quote(realm))
			writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}
