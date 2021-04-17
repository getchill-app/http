module github.com/getchill-app/http/client

go 1.16

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/getchill-app/http/api v0.0.0-20210416132649-f0d62cd56fe7
	github.com/getchill-app/http/server v0.0.0-20210412222146-088571f8d3a6
	github.com/keys-pub/keys v0.1.22-0.20210412214905-995329cc5e85
	github.com/keys-pub/vault v0.0.0-20210403222024-d7c66fea4997
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.0
	github.com/vmihailenco/msgpack v4.0.4+incompatible
)

replace github.com/keys-pub/keys => ../../../keys.pub/keys

replace github.com/getchill-app/http/api => ../api

replace github.com/getchill-app/http/server => ../server
