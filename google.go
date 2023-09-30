/*
Copyright 2023 Christos Triantafyllidis <christos.triantafyllidis@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type GoogleWebConfig struct {
	ClientId                string `json:"client_id"`
	ProjectId               string `json:"project_id"`
	AuthUri                 string `json:"auth_uri"`
	TokenUri                string `json:"token_uri"`
	AuthProviderX509CertUrl string `json:"auth_provider_x509_cert_url"`
	ClientSecret            string `json:"client_secret"`
}

type GoogleConfig struct {
	Web GoogleWebConfig `json:"web"`
}

func GoogleOAuthConfig() oauth2.Config {
	var oauth2_config oauth2.Config
	baseURL, found := os.LookupEnv("BASE_URL")
	if !found {
		baseURL = "http://localhost:8080"
	}

	if google_enabled {
		oauth2_config.ClientID = google_config.Web.ClientId
		oauth2_config.ClientSecret = google_config.Web.ClientSecret
		oauth2_config.RedirectURL = baseURL + "/login/google/callback"
		oauth2_config.Scopes = []string{"openid", "profile", "email"}
		oauth2_config.Endpoint = google.Endpoint
	}
	return oauth2_config
}

var google_enabled, google_config = GoogleLoadConfig()
var google_oauth_config = GoogleOAuthConfig()

func GoogleLoadConfig() (bool, GoogleConfig) {
	var payload GoogleConfig
	content, err := os.ReadFile("./auth-configs/google.json")
	if err != nil {
		return false, payload
	}

	err = json.Unmarshal(content, &payload)
	if err != nil {
		return false, payload
	}

	return true, payload
}

func httpLoginGoogle(c *gin.Context) {
	state_bytes := make([]byte, 64)
	rand.Read(state_bytes)
	state := base64.URLEncoding.EncodeToString(state_bytes)
	c.SetCookie("oauth_state", state, 600, "/", c.Request.URL.Host, true, true)
	c.SetCookie("return_to", c.Request.URL.Query().Get("return_to"), 600, "/", c.Request.URL.Host, true, true)
	url := google_oauth_config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	c.Redirect(http.StatusFound, url)
}

func httpLoginGoogleCallback(c *gin.Context) {
	state_cookie, _ := c.Cookie("oauth_state")
	if c.Request.FormValue("state") != state_cookie {
		c.Redirect(http.StatusTemporaryRedirect, "/")
		return
	}

	code := c.Request.URL.Query().Get("code")
	token, err := google_oauth_config.Exchange(c.Request.Context(), code)
	if err != nil {
		c.Error(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	client := google_oauth_config.Client(c.Request.Context(), token)

	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		c.Error(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var userInfo struct {
		Email string `json:"email"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		c.Error(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	loginInfo := LoginInfo{
		Username: userInfo.Email,
		Type:     "google",
	}
	Authenticate(c, loginInfo)
}
