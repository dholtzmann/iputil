iputil
========

[Go](http://golang.org) utility for IP addresses.

- Get an IP address from headers. (reverse proxy or load balancer [Nginx, etc.])
	- Headers: [X-Forwarded-For] [X-Real-IP].
- Get an IP address version (IPv4 or IPv6).
- Check if an IPv4 address is in a private subnet.

## Example

```golang
import (
	"github.com/dholtzmann/iputil"
)

func something(w http.ResponseWriter, r *http.Request) {
	ip, err := iputil.GetIPAdressFromHeader(r)
	if err != nil {
		panic(err)
	}

	ip = ip // do something with ip...
}
```

## Installation

```bash
go get -u github.com/dholtzmann/iputil
```
