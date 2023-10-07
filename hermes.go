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
	"bytes"
	"encoding/json"
	"net/http"
	"os"

	"github.com/carenaggio/libs/crypt"
	"github.com/gin-gonic/gin"
)

var hermes_enabled, hermes_config = HermesLoadConfig()

type HermesConfig struct {
	BaseURL string `json:"base_url"`
}

func HermesLoadConfig() (bool, HermesConfig) {
	var payload HermesConfig
	content, err := os.ReadFile("./auth-configs/hermes.json")
	if err != nil {
		return false, payload
	}

	err = json.Unmarshal(content, &payload)
	if err != nil {
		return false, payload
	}

	return true, payload
}

func httpLoginHermesPublicKey(c *gin.Context) {
	var resp *http.Response
	var err error

	var jsonPublicKey struct {
		PublicKey []byte `json:"public_key,omitempty"`
	}

	if resp, err = http.Get(hermes_config.BaseURL + "/public_key"); err != nil {
		c.Error(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if err = json.NewDecoder(resp.Body).Decode(&jsonPublicKey); err != nil {
		c.Error(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, jsonPublicKey)
}

func httpLoginHermesLogin(c *gin.Context) {
	var loginPayload crypt.SignedMessage
	var backendPayload []byte
	var err error
	c.SetCookie("test", "works", sessionDuration, "/", c.Request.URL.Host, false, false)

	// Sanitize the input, we only want to pass the login payload to the backend
	if err = c.BindJSON(&loginPayload); err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Login Failed"})
		return
	}

	if backendPayload, err = json.Marshal(loginPayload); err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Login Failed"})
		return
	}

	resp, err := http.Post(hermes_config.BaseURL+"/login", "application/json", bytes.NewBuffer(backendPayload))
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Login Failed"})
		return
	}
	defer resp.Body.Close()

	data := make(map[string]string)
	if err = json.NewDecoder(resp.Body).Decode(&data); err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Login Failed"})
		return
	}

	if login, login_exists := data["login"]; !login_exists || login != "OK" {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Login Failed"})
		return
	}

	system, system_exists := data["system"]
	if !system_exists {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Login Failed"})
		return
	}

	loginInfo := LoginInfo{
		Username: system,
		Type:     "hermes",
	}

	Authenticate(c, loginInfo, "/login/info")
}
