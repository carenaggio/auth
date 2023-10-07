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
	"fmt"
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

func Authenticate(c *gin.Context, loginInfo LoginInfo, returnTo string) {
	expirationTime := time.Now().Add(time.Duration(sessionDuration) * time.Second)
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

	c.SetCookie("carenaggio_auth_token", tokenString, sessionDuration, "/", c.Request.URL.Host, false, true)
	if returnTo == "" {
		c.Redirect(http.StatusFound, "/")
	} else {
		c.Redirect(http.StatusFound, returnTo)
	}

}

func httpHealthCheck(c *gin.Context) {
	c.Writer.Write([]byte("OK"))
}

func httpLoginInfo(c *gin.Context) {
	tknStr, err := c.Cookie("carenaggio_auth_token")
	if err != nil {
		c.Error(err)
		if err == http.ErrNoCookie {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		c.Error(err)
		if err == jwt.ErrSignatureInvalid {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	if !tkn.Valid {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	c.Writer.Write([]byte(fmt.Sprintf("Welcome %s! %s", claims.Username, claims)))
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
	r.GET("/login/info", httpLoginInfo)

	if google_enabled {
		log.Println("Enabling google endpoints.")
		r.GET("/login/google", httpLoginGoogle)
		r.GET("/login/google/callback", httpLoginGoogleCallback)
	}

	if hermes_enabled {
		log.Println("Enabling hermes endpoints.")
		r.GET("/login/hermes/public_key", httpLoginHermesPublicKey)
		r.POST("/login/hermes/login", httpLoginHermesLogin)
	}

	r.Run()
}
