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
	team := flag.String("team", os.Getenv("TEAM_KEY"), "Team key")
	email := flag.String("email", "", "Email")
	flag.Parse()

	accountKey, err := api.DecodeKey(*account, "")
	if err != nil {
		log.Fatal(err)
	}
	teamKey, err := api.DecodeKey(*team, "")
	if err != nil {
		log.Fatal(err)
	}

	cl, err := client.New("https://getchill.app/")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Looking up key for %s...\n", *email)
	lookup, err := cl.UserLookup(context.TODO(), "email", *email, accountKey.AsEdX25519())
	if err != nil {
		log.Fatal(err)
	}
	if lookup == nil {
		log.Fatalf("email not found")
	}
	fmt.Printf("Found key %s\n", lookup.KID)

	fmt.Printf("Completing invite...")
	if err := cl.TeamInvite(context.TODO(), teamKey.AsEdX25519(), lookup.KID, accountKey.AsEdX25519()); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Invite complete.\n")
}
