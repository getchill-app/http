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
	flag.Parse()

	accountKey, err := api.DecodeKey(*account, "")
	if err != nil {
		log.Fatal(err)
	}

	cl, err := client.New("https://getchill.app/")
	if err != nil {
		log.Fatal(err)
	}

	orgKey := keys.GenerateEdX25519Key()
	key := api.NewKey(orgKey).Created(tsutil.NowMillis())
	out, err := api.EncodeKey(key, "")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Generated org key:\n%s\n", out)

	if err := cl.OrgCreate(context.TODO(), orgKey, accountKey.AsEdX25519()); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Org created.\n")
}
