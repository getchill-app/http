module github.com/getchill-app/http/server

go 1.16

require (
	github.com/badoux/checkmail v1.2.1
	github.com/davecgh/go-spew v1.1.1
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/getchill-app/http/api v0.0.0-20210412221521-09fe0ac8b72b
	github.com/keys-pub/keys v0.1.22-0.20210412214905-995329cc5e85
	github.com/keys-pub/keys-ext/firestore v0.0.0-20210402220629-6f43cbf06c54
	github.com/keys-pub/keys-ext/ws/api v0.0.0-20210402011710-71dc6eac40c7
	github.com/keys-pub/vault v0.0.0-20210403222024-d7c66fea4997
	github.com/labstack/echo/v4 v4.2.2
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.0
	github.com/vmihailenco/msgpack/v4 v4.3.12
	google.golang.org/api v0.43.0
)

replace github.com/getchill-app/http/api => ../api
