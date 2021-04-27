module github.com/getchill-app/http/client

go 1.16

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/getchill-app/http/api v0.0.0-20210421162410-7537d4a9bf83
	github.com/getchill-app/http/server v0.0.0-20210412222146-088571f8d3a6
	github.com/keys-pub/keys v0.1.22-0.20210417180828-29a388ae126a
	github.com/keys-pub/vault v0.0.0-20210403222024-d7c66fea4997
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.0
	github.com/vmihailenco/msgpack/v4 v4.3.12
)

replace github.com/keys-pub/keys => ../../../keys.pub/keys

replace github.com/keys-pub/vault => ../../../keys.pub/vault

replace github.com/getchill-app/http/api => ../api

replace github.com/getchill-app/http/server => ../server
