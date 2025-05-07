package Autenticacao

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type KeycloakConfig struct {
	KeycloakURL  string
	Realm        string
	ClientID     string
	ClientSecret string
}

type config[T any] struct {
	KeycloakConfig KeycloakConfig
	EndpointURLs   map[string]string
}

func (c *config[T]) GetUserInformation(username string) ([]T, error) {

	req, err := http.NewRequest("GET", c.EndpointURLs["getUser"]+username, nil)

	token, err := c.getAdminToken()

	req.Header.Add("Authorization", "Bearer "+token)

	client := &http.Client{}

	resp, err := client.Do(req)

	if err != nil {
		return nil, fmt.Errorf("failed to creat request: %w", err)
	}

	i, err := getbody(resp)

	if err != nil {
		return nil, fmt.Errorf("failed to fetch user information: %w", err)
	}

	fmt.Printf("JSON recebido: %s\n", string(i))

	var users []T
	err = json.Unmarshal(i, &users)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal user information: %w", err)
	}

	return users, nil
}

func (c *config[T]) AddUser(user T) (string, error) {

	jsonData, err := json.Marshal(user)

	if err != nil {

		return "", fmt.Errorf("failed to marshal user data: %w", err)
	}

	req, err := http.NewRequest("POST", c.EndpointURLs["user"], bytes.NewBuffer(jsonData))

	resp, err := c.connection(req)

	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	location := resp.Header.Get("Location")

	if location == "" {
		return "", fmt.Errorf("failed to get created user ID")
	}

	return location, nil
}

func (c *config[T]) connection(req *http.Request) (resp *http.Response, err error) {

	token, err := c.getAdminToken()

	req.Header.Set("Content-Type", "application/json")

	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}

	resp, err = client.Do(req)

	if err != nil {

		return nil, fmt.Errorf("request failed: %w", err)
	}

	body, err := getbody(resp)

	println(string(body))

	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return resp, nil
}

func getbody(resp *http.Response) ([]byte, error) {

	defer func(Body io.ReadCloser) {

		err := Body.Close()

		if err != nil {

			log.Fatal()

		}

	}(resp.Body)

	body, err := io.ReadAll(resp.Body)

	if err != nil {

		return nil, fmt.Errorf("failed to read response: %w", err)

	}
	if !isSuccessStatusCode(resp.StatusCode) {
		return nil, fmt.Errorf("operation failed (status %d): %s", resp.StatusCode, string(body))
	}

	return body, nil
}

func isSuccessStatusCode(statusCode int) bool {
	successCodes := map[int]bool{
		http.StatusOK:        true,
		http.StatusCreated:   true,
		http.StatusNoContent: true,
	}
	return successCodes[statusCode]
}

func (c *config[T]) getAdminToken() (string, error) {

	tokenEndpoint := c.EndpointURLs["token"]

	formData := url.Values{
		"client_id":     []string{c.KeycloakConfig.ClientID},
		"client_secret": []string{c.KeycloakConfig.ClientSecret},
		"grant_type":    []string{"client_credentials"},
	}

	resp, err := http.Post(

		tokenEndpoint,

		"application/x-www-form-urlencoded",

		strings.NewReader(formData.Encode()),
	)

	if err != nil {

		return "", fmt.Errorf("token request failed: %w", err)

	}

	i, err := getbody(resp)

	if err != nil {
		return "", fmt.Errorf("failed to get token: %w", err)
	}

	var tokenResponse struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.Unmarshal(i, &tokenResponse); err != nil {

		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	return tokenResponse.AccessToken, nil
}

func (c *config[T]) SendEmail(location string) error {

	req, err := http.NewRequest("PUT", location+"/reset-password-email", nil)

	if err != nil {
		return fmt.Errorf("failed to create email request: %w", err)
	}

	_, err = c.connection(req)

	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

type Keycloak[T any] interface {
	AddUser(user T) (string, error)
	SendEmail(location string) error
	GetUserInformation(username string) ([]T, error)
}

func NewKeycloak[T any](cfg KeycloakConfig) Keycloak[T] {

	endpoints := map[string]string{
		"user":    fmt.Sprintf("%s/admin/realms/%s/users", cfg.KeycloakURL, cfg.Realm),
		"token":   fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", cfg.KeycloakURL, cfg.Realm),
		"getUser": fmt.Sprintf("%s/admin/realms/%s/users?username=", cfg.KeycloakURL, cfg.Realm),
	}

	return &config[T]{
		KeycloakConfig: cfg,
		EndpointURLs:   endpoints,
	}
}
