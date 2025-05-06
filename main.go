package main

import "log"

type User struct {
	Username  string `json:"username"`
	Email     string `json:"email"`
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
	Enabled   bool   `json:"enabled"`
}

func main() {

	user := User{
		Username:  "bendego8",
		Email:     "amanda-conceicao@tuamaeaquelaursa.com",
		FirstName: "bendego8",
		LastName:  "bendego8",
		Enabled:   true,
	}

	var keycloak = NewKeycloak[User](KeycloakConfig{
		KeycloakURL:  "https://keycloak.bendego.tech",
		Realm:        "bendego",
		ClientID:     "app",
		ClientSecret: "BY9FmweB1R5QgO4hquS42HnEGupPh4Tq",
	})

	addUser, err := keycloak.AddUser(user)
	if err != nil {
		log.Fatal(err)
	}
	println(addUser)
	err = keycloak.SendEmail(addUser)
	if err != nil {
		log.Fatal(err)
	}
}
