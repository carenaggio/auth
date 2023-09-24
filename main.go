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
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var sessionDuration = 10 * time.Minute
var jwtKey = []byte{}

type LoginInfo struct {
	Username string `json:"username"`
	Type     string `json:"type"`
}

type Claims struct {
	Username           string `json:"username"`
	AuthenticationType string `json:"authentication_type"`
	jwt.RegisteredClaims
}

func Authenticate(writer http.ResponseWriter, request *http.Request, loginInfo LoginInfo) {
	expirationTime := time.Now().Add(sessionDuration)

	claims := Claims{
		Username:           loginInfo.Username,
		AuthenticationType: loginInfo.Type,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			Issuer:    "carenaggio",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	auth_cookie := http.Cookie{Name: "carenaggio_auth_token", Value: tokenString, Expires: expirationTime, Path: "/"}
	http.SetCookie(writer, &auth_cookie)

	return_to_cookie, _ := request.Cookie("oauth_return_url")
	if return_to_cookie.Value == "" {
		http.Redirect(writer, request, "/", http.StatusFound)
	} else {
		http.Redirect(writer, request, return_to_cookie.Value, http.StatusFound)
	}

}

func HealthCheck(writer http.ResponseWriter, request *http.Request) {
	writer.Write([]byte("OK"))
}

func main() {
	jwtKeyStr, found := os.LookupEnv("JWT_KEY")
	if !found {
		log.Println("The JWT_KEY enviornment variable is required to be set")
		return
	}
	jwtKey = []byte(jwtKeyStr)

	http.HandleFunc("/health-check", HealthCheck)

	if google_enabled {
		log.Println("Enabling google endpoints.")
		http.HandleFunc("/login/google", GoogleLogin)
		http.HandleFunc("/login/google/callback", GoogleLoginCallback)
	}

	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Println("There was an error listening on port :8080", err)
	}

}
