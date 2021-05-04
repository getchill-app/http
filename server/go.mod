module github.com/getchill-app/http/server

go 1.16

require (
	github.com/badoux/checkmail v1.2.1
	github.com/davecgh/go-spew v1.1.1
	github.com/getchill-app/http/api v0.0.0-20210504010216-724792fd62e1
	github.com/getchill-app/ws/api v0.0.0-20210504010258-9e1738caa70d
	github.com/keys-pub/keys v0.1.22-0.20210417135906-1bd8b8cf63b7
	github.com/keys-pub/keys-ext/firestore v0.0.0-20210402220629-6f43cbf06c54
	github.com/keys-pub/vault v0.0.0-20210403222024-d7c66fea4997
	github.com/labstack/echo/v4 v4.2.2
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.0
	github.com/vmihailenco/msgpack/v4 v4.3.12
	google.golang.org/api v0.43.0
)

// replace github.com/keys-pub/keys => ../../../keys.pub/keys

// replace github.com/getchill-app/http/api => ../api

// replace github.com/getchill-app/ws/api => ../../ws/api
