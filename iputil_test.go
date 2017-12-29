package iputil

import (
	"testing"
	"net"
	"net/http"
	"net/http/httptest"
	"io/ioutil"
)

// helper function
func serveAndRequest(t *testing.T, h http.Handler) (string) {
	ts := httptest.NewServer(h)
	defer ts.Close()
	res, err := http.Get(ts.URL)
	if err != nil {
		t.Errorf("Error doing http.Get() request: [%s]", err)
	}
	resBody, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Errorf("Error reading http request body: [%s]", err)
	}
	return string(resBody)
}

// unexported functions
func Test_inRange(t *testing.T) {
	r := ipRange{
		start: net.ParseIP("10.0.0.0"),
		end:   net.ParseIP("10.255.255.255"),
	}
	
	if !inRange(r, net.ParseIP("10.1.1.1")) {
		t.Errorf("inRange(): Should return true.")
	}
}

func Test_isPrivateSubnetIPv4(t *testing.T) {
	var list = []string{
		"10.3.4.7",
		"100.64.2.2",
		"172.18.1.1",
		"192.0.0.5",
		"192.168.2.2",
		"198.18.3.3",
	}
	for _, l := range list {
		if !isPrivateSubnetIPv4(net.ParseIP(l)) {
			t.Errorf("isPrivateSubnetIPv4(): Should return true [%s]", l)
		}
	}
}

// exported functions
func Test_GetIPAddressVersion(t *testing.T) {
	type IPVer struct {
		ip string
		ver uint32
	}

	var list = []IPVer{
		{"192.0.2.1", IPV4},
		{"127.0.0.1", IPV4},
		{"0.0.0.0", IPV4},
		{"255.255.255.255", IPV4},
		{"1.2.3.4", IPV4},
		{"2001:db8::68", IPV6},
		{"::1", IPV6},
		{"2001:db8:0000:1:1:1:1:1", IPV6},
	}

	for _, l := range list {
		ver, err := GetIPAddressVersion(l.ip)

		if ver != l.ver {
			t.Errorf("GetIPAddressVersion('%s'): Returned[%d]. Expected: %d", l.ip, ver, l.ver)
		}

		if err != nil {
			t.Errorf("GetIPAddressVersion('%s'): Error: %s", l.ip, err)
		}
	}

	// test for error
	ver, err := GetIPAddressVersion("wst")

	if ver != 0 {
		t.Errorf("Expected error! GetIPAddressVersion('wst'): Version: %d", ver)
	}
	if err == nil {
		t.Errorf("Expected error! GetIPAddressVersion('wst'): Error: %s", err)
	}
}

func Test_GetIPAdressFromHeader(t *testing.T) {
	fn := func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("X-Forwarded-For", "1.2.3.4")
		r.Header.Set("X-Real-Ip", "1.2.3.4")

		ip, err := GetIPAdressFromHeader(r)
		if err != nil {
			t.Errorf("Unexpected error: [%s]", err)
		}
		if ip != "1.2.3.4" {
			t.Errorf("IP address does not match expected! Returned[%s]", ip)
		}
	}

	serveAndRequest(t, http.HandlerFunc(fn))
}

func Test_GetIPAdressDirect(t *testing.T) {
	fn := func(w http.ResponseWriter, r *http.Request) {
		ip, err := GetIPAdressDirect(r)
		if err != nil {
			t.Errorf("Unexpected error: [%s]", err)
		}
		if ip != "127.0.0.1" {
			t.Errorf("IP address does not match expected! Returned[%s]", ip)
		}
	}

	serveAndRequest(t, http.HandlerFunc(fn))
}
