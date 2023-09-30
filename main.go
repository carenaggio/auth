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

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var sessionDuration = 600
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

func Authenticate(c *gin.Context, loginInfo LoginInfo) {
	expirationTime := time.Now().Add(time.Duration(sessionDuration))

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
		c.Error(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.SetCookie("carenaggio_auth_token", tokenString, sessionDuration, "/", c.Request.URL.Host, true, true)

	return_to_cookie, err := c.Cookie("return_to")
	if err != nil {
		return_to_cookie = ""
	}
	if return_to_cookie == "" {
		c.Redirect(http.StatusFound, "/")
	} else {
		c.Redirect(http.StatusFound, return_to_cookie)
	}

}

func httpHealthCheck(c *gin.Context) {
	c.Writer.Write([]byte("OK"))
}

func main() {
	jwtKeyStr, found := os.LookupEnv("JWT_KEY")
	if !found {
		log.Println("The JWT_KEY enviornment variable is required to be set")
		return
	}
	jwtKey = []byte(jwtKeyStr)

	r := gin.Default()
	r.GET("/health-check", httpHealthCheck)

	if google_enabled {
		log.Println("Enabling google endpoints.")
		r.GET("/login/google", httpLoginGoogle)
		r.GET("/login/google/callback", httpLoginGoogleCallback)
	}

	r.Run()
}
