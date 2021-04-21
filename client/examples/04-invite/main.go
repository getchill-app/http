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
	org := flag.String("org", os.Getenv("ORG_KEY"), "Org key")
	email := flag.String("email", "", "Email")
	flag.Parse()

	accountKey, err := api.DecodeKey(*account, "")
	if err != nil {
		log.Fatal(err)
	}
	orgKey, err := api.DecodeKey(*org, "")
	if err != nil {
		log.Fatal(err)
	}

	cl, err := client.New("https://getchill.app/")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Looking up key for %s...\n", *email)
	lookup, err := cl.UserLookup(context.TODO(), *email, accountKey.AsEdX25519())
	if err != nil {
		log.Fatal(err)
	}
	if lookup == nil {
		log.Fatalf("email not found")
	}
	fmt.Printf("Found key %s\n", lookup.KID)

	fmt.Printf("Completing invite...")
	if err := cl.OrgInvite(context.TODO(), orgKey.AsEdX25519(), lookup.KID, accountKey.AsEdX25519()); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Invite complete.\n")
}
