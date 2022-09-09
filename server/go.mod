module github.com/fdurand/sshd-support/server

go 1.17

require (
	github.com/kr/pty v1.1.8
	golang.org/x/crypto v0.0.0-20220829220503-c86fa9a7ed90
)

require (
	github.com/creack/pty v1.1.7 // indirect
	golang.org/x/sys v0.0.0-20210615035016-665e8c7367d1 // indirect
)

replace golang.org/x/crypto => github.com/rmohr/crypto v0.0.0-20211203105847-e4ed9664ac54
