package Autenticacao

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
				Body:       io.NopCloser(bytes.NewBufferString("casa")),
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
		{
			name: "ok must location empty",
			mockResponse: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"error": "invalid user"}`)),
			},
			expectedError: true,
		},
		{
			name: "jason data",
			mockResponse: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"error": "invalid user"}`)),
			},
			expectedError: true,
		},
		{
			name: "request erro",
			mockResponse: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"error": "invalid user"}`)),
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

				w.Header().Set("Location", tt.mockResponse.Header.Get("Location"))
				w.WriteHeader(tt.mockResponse.StatusCode)
				_, err := io.Copy(w, tt.mockResponse.Body)
				if err != nil {
					log.Fatal("Erro config ")
				}
			}))
			defer server.Close()

			cfg := KeycloakConfig{
				KeycloakURL:  server.URL,
				Realm:        "test-realm",
				ClientID:     "test-client",
				ClientSecret: "test-secret",
			}

			kc := NewKeycloak[TestUser](cfg)

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

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.mockResponse.StatusCode)
				_, err := io.Copy(w, tt.mockResponse.Body)
				if err != nil {
					return
				}
			}))
			defer server.Close()

			cfg := KeycloakConfig{
				KeycloakURL:  server.URL,
				Realm:        "test-realm",
				ClientID:     "test-client",
				ClientSecret: "test-secret",
			}

			kc := NewKeycloak[TestUser](cfg).(*config[TestUser])

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
				_, err := io.Copy(w, tt.mockResponse.Body)
				if err != nil {
					return
				}
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
				w.WriteHeader(http.StatusOK)
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

type user struct {
	field1 string
	field2 int
}

func TestJson(t *testing.T) {
	t.Run("successful connection with auth", func(t *testing.T) {

		cfg := KeycloakConfig{
			KeycloakURL:  "key.com",
			Realm:        "test-realm",
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		}

		kc := NewKeycloak[user](cfg)

		_, err := kc.AddUser(user{
			field1: "{{{{",
			field2: 0,
		})

		if err == nil {
			t.Errorf("Unexpected error: %v", err)
		}
	})
}

func TestGetUserInformation(t *testing.T) {

	type TestUser struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
	}

	tests := []struct {
		name          string
		mockResponse  *http.Response
		expectedError bool
		expectedUsers []TestUser
	}{
		{
			name: "successful user fetch",
			mockResponse: &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(bytes.NewBufferString(`[
                    {"id": "123", "username": "user1", "email": "user1@test.com"},
                    {"id": "456", "username": "user2", "email": "user2@test.com"}
                ]`)),
			},
			expectedError: false,
			expectedUsers: []TestUser{
				{ID: "123", Username: "user1", Email: "user1@test.com"},
				{ID: "456", Username: "user2", Email: "user2@test.com"},
			},
		},
		{
			name: "no users found",
			mockResponse: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`[]`)),
			},
			expectedError: false,
			expectedUsers: []TestUser{},
		},
		{
			name: "bad request",
			mockResponse: &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(bytes.NewBufferString(`{"error": "invalid request"}`)),
			},
			expectedError: true,
		},
		{
			name: "invalid json",
			mockResponse: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`invalid json`)),
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

				switch r.URL.Path {

				case "/realms/test-realm/protocol/openid-connect/token":

					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{
            "access_token": "mock-token",
            "expires_in": 300
        }`))

				case "/admin/realms/test-realm/users":

					w.WriteHeader(tt.mockResponse.StatusCode)

					_, err := io.Copy(w, tt.mockResponse.Body)

					if err != nil {

						t.Errorf("Failed to write response: %v", err)

					}

				default:
					w.WriteHeader(http.StatusNotFound)
				}
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

			users, err := kc.GetUserInformation("testuser")

			if tt.expectedError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if len(users) != len(tt.expectedUsers) {
				t.Errorf("Expected %d users, got %d", len(tt.expectedUsers), len(users))
				return
			}

			for i, user := range users {
				if user != tt.expectedUsers[i] {
					t.Errorf("Expected user %v, got %v", tt.expectedUsers[i], user)
				}
			}
		})
	}
}
