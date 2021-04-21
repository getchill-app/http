package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/getchill-app/http/client"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/api"
	"github.com/keys-pub/keys/tsutil"
)

func main() {
	account := flag.String("account", os.Getenv("ACCOUNT_KEY"), "Account key")
	team := flag.String("team", os.Getenv("TEAM_KEY"), "Team key")
	flag.Parse()

	accountKey, err := api.DecodeKey(*account, "")
	if err != nil {
		log.Fatal(err)
	}
	var teamKey *api.Key
	if *team != "" {
		k, err := api.DecodeKey(*team, "")
		if err != nil {
			log.Fatal(err)
		}
		teamKey = k
	} else {
		teamKey = api.NewKey(keys.GenerateEdX25519Key()).Created(tsutil.NowMillis())
		out, err := api.EncodeKey(teamKey, "")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Generated team key:\n%s\n", out)
	}

	cl, err := client.New("https://getchill.app/")
	if err != nil {
		log.Fatal(err)
	}

	if err := cl.TeamCreate(context.TODO(), teamKey.AsEdX25519(), accountKey.AsEdX25519()); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Team created.\n")
}
