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

	if err := cl.AccountInvite(context.TODO(), accountKey.AsEdX25519(), *email); err != nil {
		log.Fatal(err)
	}

	phrase, err := cl.TeamInvite(context.TODO(), teamKey.AsEdX25519(), accountKey.AsEdX25519())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Invited with code:\n%s.\n", phrase)
}
