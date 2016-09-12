package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"
)

const baseURL = "https://appws.runtastic.com"
const connectTimeout = 10 * time.Second

var headers = map[string]string{
	"Content-Type": "application/json",
	"X-App-Key":    "at.runtastic.runtastic.pro",
	"X-Auth-Token": "8e6cad82a70fe7ffa2102d5a0c1bb8a780e331c9",
	"X-Date":       "2016.09.12 14:34:40",
}

type loginRequest struct {
	Email                string   `json:"email"`
	AdditionalAttributes []string `json:"additionalAttributes"`
	Password             string   `json:"password"`
}

type authenticatedUser struct {
	UserID      string `json:"userId"`
	AccessToken string `json:"accessToken"`
	Uidt        string `json:"uidt"`
}

func login(email, password string) (*authenticatedUser, error) {
	body := new(bytes.Buffer)

	err := json.NewEncoder(body).Encode(loginRequest{
		Email:                email,
		AdditionalAttributes: []string{"accessToken"},
		Password:             password,
	})

	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, baseURL+"/webapps/services/auth/login", body)

	if err != nil {
		return nil, err
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{Timeout: connectTimeout}
	resp, err := client.Do(req)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status)
	}

	var user authenticatedUser
	decoder := json.NewDecoder(resp.Body)

	if err := decoder.Decode(&user); err != nil {
		return nil, err
	}

	return &user, nil
}

func main() {
	user, err := login("metalnem@mijailovic.net", "")

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(user.AccessToken)
}
