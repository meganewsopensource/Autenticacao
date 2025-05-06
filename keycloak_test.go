package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestUser represents a sample user struct for testing
type TestUser struct {
	Username string `json:"username"`
	Email    string `json:"email"`
}

func TestAddUser(t *testing.T) {
	tests := []struct {
		name           string
		mockResponse   *http.Response
		expectedError  bool
		expectedResult string
	}{
		{
			name: "successful user creation",
			mockResponse: &http.Response{
				StatusCode: http.StatusCreated,
				Header:     map[string][]string{"Location": {"/users/123"}},
				Body:       io.NopCloser(bytes.NewBufferString("")),
			},
			expectedError:  false,
			expectedResult: "/users/123",
		},
		{
			name: "failed user creation - bad request",
			mockResponse: &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(bytes.NewBufferString(`{"error": "invalid user"}`)),
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.mockResponse.StatusCode)
				for k, v := range tt.mockResponse.Header {
					w.Header()[k] = v
				}
				io.Copy(w, tt.mockResponse.Body)
			}))
			defer server.Close()

			// Create test config
			cfg := KeycloakConfig{
				KeycloakURL:  server.URL,
				Realm:        "test-realm",
				ClientID:     "test-client",
				ClientSecret: "test-secret",
			}

			kc := NewKeycloak[TestUser](cfg)

			// Test AddUser
			result, err := kc.AddUser(TestUser{
				Username: "testuser",
				Email:    "test@example.com",
			})

			if tt.expectedError && err == nil {
				t.Errorf("Expected error but got none")
			}

			if !tt.expectedError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if !tt.expectedError && result != tt.expectedResult {
				t.Errorf("Expected result %s, got %s", tt.expectedResult, result)
			}
		})
	}
}

func TestGetAdminToken(t *testing.T) {
	tests := []struct {
		name          string
		mockResponse  *http.Response
		expectedError bool
		expectedToken string
	}{
		{
			name: "successful token request",
			mockResponse: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"access_token": "test-token", "expires_in": 300}`)),
			},
			expectedError: false,
			expectedToken: "test-token",
		},
		{
			name: "failed token request - invalid credentials",
			mockResponse: &http.Response{
				StatusCode: http.StatusUnauthorized,
				Body:       io.NopCloser(bytes.NewBufferString(`{"error": "invalid_client"}`)),
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.mockResponse.StatusCode)
				io.Copy(w, tt.mockResponse.Body)
			}))
			defer server.Close()

			// Create test config
			cfg := KeycloakConfig{
				KeycloakURL:  server.URL,
				Realm:        "test-realm",
				ClientID:     "test-client",
				ClientSecret: "test-secret",
			}

			kc := NewKeycloak[TestUser](cfg).(*config[TestUser])

			// Test getAdminToken
			token, err := kc.getAdminToken()

			if tt.expectedError && err == nil {
				t.Errorf("Expected error but got none")
			}

			if !tt.expectedError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if !tt.expectedError && token != tt.expectedToken {
				t.Errorf("Expected token %s, got %s", tt.expectedToken, token)
			}
		})
	}
}

func TestSendEmail(t *testing.T) {
	tests := []struct {
		name          string
		mockResponse  *http.Response
		expectedError bool
	}{
		{
			name: "successful email send",
			mockResponse: &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       io.NopCloser(bytes.NewBufferString("")),
			},
			expectedError: false,
		},
		{
			name: "failed email send - user not found",
			mockResponse: &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(bytes.NewBufferString(`{"error": "user not found"}`)),
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.mockResponse.StatusCode)
				io.Copy(w, tt.mockResponse.Body)
			}))
			defer server.Close()

			// Create test config
			cfg := KeycloakConfig{
				KeycloakURL:  server.URL,
				Realm:        "test-realm",
				ClientID:     "test-client",
				ClientSecret: "test-secret",
			}

			kc := NewKeycloak[TestUser](cfg)

			// Test SendEmail
			err := kc.SendEmail(server.URL + "/users/123")

			if tt.expectedError && err == nil {
				t.Errorf("Expected error but got none")
			}

			if !tt.expectedError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestConnection(t *testing.T) {
	t.Run("successful connection with auth", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader != "Bearer test-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cfg := KeycloakConfig{
			KeycloakURL:  server.URL,
			Realm:        "test-realm",
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		}

		kc := NewKeycloak[TestUser](cfg).(*config[TestUser])

		req, _ := http.NewRequest("GET", server.URL, nil)
		_, err := kc.connection(req)

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
	})
}
