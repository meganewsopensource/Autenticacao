# Authentication

Library for creating users in Keycloak

 * Creates users

 * Sends a confirmation email for password setup

##Example
~~~go

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
		KeycloakURL:  "https://mykeycloak.com",  
		Realm:        "myrealm",  
		ClientID:     "myappip",  
		ClientSecret: "myclientsecrt",  
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
~~~
