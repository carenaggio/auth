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
	"time"

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

func GoogleLogin(writer http.ResponseWriter, request *http.Request) {
	state_bytes := make([]byte, 64)
	rand.Read(state_bytes)
	state := base64.URLEncoding.EncodeToString(state_bytes)
	state_cookie := http.Cookie{Name: "oauth_state", Value: state, Expires: time.Now().Add(10 * time.Minute)}
	http.SetCookie(writer, &state_cookie)

	return_url_cookie := http.Cookie{Name: "oauth_return_url", Value: request.URL.Query().Get("return_to"), Expires: time.Now().Add(10 * time.Minute)}
	http.SetCookie(writer, &return_url_cookie)

	url := google_oauth_config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(writer, request, url, http.StatusFound)
}

func GoogleLoginCallback(writer http.ResponseWriter, request *http.Request) {
	state_cookie, _ := request.Cookie("oauth_state")

	if request.FormValue("state") != state_cookie.Value {
		http.Redirect(writer, request, "/", http.StatusTemporaryRedirect)
		return
	}

	code := request.URL.Query().Get("code")
	token, err := google_oauth_config.Exchange(request.Context(), code)
	if err != nil {
		http.Error(writer, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	// Use the 'token' to make API requests on behalf of the user.
	client := google_oauth_config.Client(request.Context(), token)

	// Get the user's profile information.
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		http.Error(writer, "Failed to fetch user profile", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	// Parse the JSON response to get user information.
	var userInfo struct {
		Email string `json:"email"`
		// Add other fields you need from the user's profile here
	}

	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		http.Error(writer, "Failed to parse user profile", http.StatusInternalServerError)
		return
	}

	loginInfo := LoginInfo{
		Username: userInfo.Email,
		Type:     "google",
	}
	Authenticate(writer, request, loginInfo)
}
