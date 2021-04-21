package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/getchill-app/http/client"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/api"
	"github.com/keys-pub/keys/tsutil"
)

func main() {
	email := flag.String("email", "", "Email to register")
	code := flag.String("code", "", "Registration code")
	username := flag.String("username", "", "Username")
	flag.Parse()

	cl, err := client.New("https://getchill.app/")
	if err != nil {
		log.Fatal(err)
	}

	if *code == "" {
		fmt.Printf("Registering %s...\n", *email)
		if err := cl.AccountRegister(context.TODO(), *email); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Account registered, look for code in your email.\n")
	} else {
		accountKey := keys.GenerateEdX25519Key()
		key := api.NewKey(accountKey).Created(tsutil.NowMillis())
		out, err := api.EncodeKey(key, "")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Generated account key:\n%s\n", out)

		if err := cl.AccountCreate(context.TODO(), accountKey, *email, *code); err != nil {
			log.Fatal(err)
		}
		if err := cl.AccountSetUsername(context.TODO(), accountKey, *username); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Account created.\n")
	}
}
