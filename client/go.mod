module github.com/getchill-app/http/client

go 1.16

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/getchill-app/http/api v0.0.0-20210428165120-2df51644660d
	github.com/getchill-app/http/server v0.0.0-20210412222146-088571f8d3a6
	github.com/getchill-app/keyring v0.0.0-20210430214439-c21449557217
	github.com/keys-pub/keys v0.1.22-0.20210428191820-49dfbda60f85
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.0
	github.com/vmihailenco/msgpack/v4 v4.3.12
)

replace github.com/keys-pub/keys => ../../../keys.pub/keys

replace github.com/getchill-app/http/api => ../api

replace github.com/getchill-app/http/server => ../server

replace github.com/getchill-app/ws/api => ../../ws/api
