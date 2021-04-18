package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/getchill-app/http/client"
	"github.com/keys-pub/keys/api"
)

func main() {
	account := flag.String("account", os.Getenv("ACCOUNT_KEY"), "Account key")
	email := flag.String("email", "", "Email")
	flag.Parse()

	accountKey, err := api.DecodeKey(*account, "")
	if err != nil {
		log.Fatal(err)
	}

	cl, err := client.New("https://getchill.app/")
	if err != nil {
		log.Fatal(err)
	}

	if err := cl.AccountRegisterInvite(context.TODO(), accountKey.AsEdX25519(), *email); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Invited for registration.\n")
}
