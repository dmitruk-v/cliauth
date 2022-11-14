package main

import (
	"fmt"
	"log"

	"github.com/dmitruk-v/cliauth/v0"
)

func main() {
	user, err := cliauth.NewAuthenticator().Run()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(user)
}
