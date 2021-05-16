module github.com/getchill-app/http/server

go 1.16

require (
	github.com/alta/protopatch v0.3.3 // indirect
	github.com/badoux/checkmail v1.2.1
	github.com/davecgh/go-spew v1.1.1
	github.com/getchill-app/http/api v0.0.0-20210515202516-f6305dc12308
	github.com/getchill-app/keyring v0.0.0-20210510182950-cf0123330ce2
	github.com/getchill-app/ws/api v0.0.0-20210515202614-2e7dadf92402
	github.com/keys-pub/keys v0.1.22-0.20210428191820-49dfbda60f85
	github.com/keys-pub/keys-ext/firestore v0.0.0-20210402220629-6f43cbf06c54
	github.com/labstack/echo/v4 v4.2.2
	github.com/lib/pq v1.9.0 // indirect
	github.com/mattn/go-colorable v0.1.8 // indirect
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.0
	github.com/vmihailenco/msgpack/v4 v4.3.12
	golang.org/x/sys v0.0.0-20210331175145-43e1dd70ce54 // indirect
	google.golang.org/api v0.43.0
)

// replace github.com/keys-pub/keys => ../../../keys.pub/keys

// replace github.com/getchill-app/http/api => ../api

// replace github.com/getchill-app/ws/api => ../../ws/api
