package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestHTTPHealthCheck(t *testing.T) {
	router := setupRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health-check", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "OK", w.Body.String())
}

func TestHTTPLoginInfoWithoutCookie(t *testing.T) {
	router := setupRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/login/info", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, 401, w.Code)
}

func TestHTTPLoginInfoInvalidToken(t *testing.T) {
	router := setupRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/login/info", nil)

	req.AddCookie(
		&http.Cookie{
			Name:     "carenaggio_auth_token",
			Value:    "token",
			MaxAge:   10,
			Expires:  time.Now().Add(time.Second * 1),
			Path:     "/",
			Domain:   "carenaggio.local",
			HttpOnly: true,
			SameSite: http.SameSiteNoneMode,
			Secure:   true,
		},
	)

	router.ServeHTTP(w, req)

	assert.Equal(t, 400, w.Code)
}
