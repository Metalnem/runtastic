package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"
)

const (
	appKey     = "com.runtastic.windows.pushup.pro"
	appSecret  = "H55779eb12238015988c9badf27cf5b5f11faff341ea9722b8d178290323477f"
	baseURL    = "https://appws.runtastic.com"
	timeFormat = "2006-01-02 15:04:05"
	timeout    = 10 * time.Second
)

type loginRequest struct {
	Email      string   `json:"email"`
	Attributes []string `json:"additionalAttributes"`
	Password   string   `json:"password"`
}

type authenticatedUser struct {
	UserID      string `json:"userId"`
	AccessToken string `json:"accessToken"`
	Uidt        string `json:"uidt"`
}

func buildAuthToken(t time.Time) string {
	s := fmt.Sprintf("--%s--%s--%s--", appKey, appSecret, t.Format(timeFormat))
	hash := sha1.Sum([]byte(s))

	return hex.EncodeToString(hash[:])
}

func login(email, password string) (*authenticatedUser, error) {
	b, err := json.Marshal(loginRequest{
		Email:      email,
		Attributes: []string{"accessToken"},
		Password:   password,
	})

	if err != nil {
		return nil, err
	}

	body := bytes.NewReader(b)
	req, err := http.NewRequest(http.MethodPost, baseURL+"/webapps/services/auth/login", body)

	if err != nil {
		return nil, err
	}

	t := time.Now()
	authToken := buildAuthToken(t)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-App-Key", appKey)
	req.Header.Set("X-Date", t.Format(timeFormat))
	req.Header.Set("X-Auth-Token", authToken)

	client := &http.Client{Timeout: timeout}
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
