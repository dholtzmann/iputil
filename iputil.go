/*
	Some code taken from:
	https://husobee.github.io/golang/ip-address/2015/12/17/remote-ip-go.html

	Get IP address from headers, used with a reverse proxy or load balancer (Nginx, etc.) and directly.
*/

package iputil

import (
	"bytes"
	"net"
	"net/http"
	"strings"
	"fmt"
)

const IPV4 = 1
const IPV6 = 2

var ErrHeadersNotFound = fmt.Errorf("Headers [X-Forwarded-For] [X-Real-IP] not found")
var ErrBadIPFormat = fmt.Errorf("Bad string format for IP Address")
var ErrUnknown = fmt.Errorf("Unknown error")

//ipRange - a structure that holds the start and end of a range of ip addresses
type ipRange struct {
	start net.IP
	end net.IP
}

// inRange - check to see if a given ip address is within a range given
func inRange(r ipRange, ipAddress net.IP) (bool) {
	// strcmp type byte comparison
	if bytes.Compare(ipAddress, r.start) >= 0 && bytes.Compare(ipAddress, r.end) < 0 {
		return true
	}
	return false
}

// isPrivateSubnetIPv4 - check to see if this ip is in a private subnet (IPv4)
func isPrivateSubnetIPv4(ipAddress net.IP) (bool) {
	var privateRangesIPv4 = []ipRange{
		ipRange{
			start: net.ParseIP("10.0.0.0"),
			end:   net.ParseIP("10.255.255.255"),
		},
		ipRange{
			start: net.ParseIP("100.64.0.0"),
			end:   net.ParseIP("100.127.255.255"),
		},
		ipRange{
			start: net.ParseIP("172.16.0.0"),
			end:   net.ParseIP("172.31.255.255"),
		},
		ipRange{
			start: net.ParseIP("192.0.0.0"),
			end:   net.ParseIP("192.0.0.255"),
		},
		ipRange{
			start: net.ParseIP("192.168.0.0"),
			end:   net.ParseIP("192.168.255.255"),
		},
		ipRange{
			start: net.ParseIP("198.18.0.0"),
			end:   net.ParseIP("198.19.255.255"),
		},
	}

	if ipCheck := ipAddress.To4(); ipCheck != nil {
		// iterate over all our ranges
		for _, r := range privateRangesIPv4 {
			// check if this ip is in a private range
			if inRange(r, ipAddress){
				return true
			}
		}
	}
	return false
}

func GetIPAdressFromHeader(r *http.Request) (string, error) {
	if r.Header.Get("X-Forwarded-For") == "" && r.Header.Get("X-Real-Ip") == "" { // case insensitive
		return "", ErrHeadersNotFound
	}

	for _, h := range []string{"X-Forwarded-For", "X-Real-Ip"} {
		addresses := strings.Split(r.Header.Get(h), ",")
		// march from right to left until we get a public address
		// that will be the address right before our proxy.
		for i := len(addresses) -1 ; i >= 0; i-- {
			ip := strings.TrimSpace(addresses[i])
			// header can contain spaces too, strip those out.
			realIP := net.ParseIP(ip)

			if realIP.DefaultMask() != nil { // IPv4
				if !realIP.IsGlobalUnicast() || isPrivateSubnetIPv4(realIP) {
					// bad address, go to next
					continue
				}
			} else { // IPv6
			}


			return ip, nil
		}
	}
	return "", ErrUnknown
}

func GetIPAddressVersion(host string) (uint32, error){
	userIP := net.ParseIP(host)
	if userIP == nil {
		return 0, ErrBadIPFormat
	}

	if userIP.DefaultMask() != nil {
		return IPV4, nil
	} else {
		return IPV6, nil
	}
}

func GetIPAdressDirect(r *http.Request) (string, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", fmt.Errorf("req.RemoteAddr [%q] is not in string format [IP:port]\n", r.RemoteAddr)
	}

	userIP := net.ParseIP(host)
	if userIP == nil {
		return "", fmt.Errorf("req.RemoteAddr [%q] is not in string format [IP:port]\n", r.RemoteAddr)
	}

	return host, nil
}

/*
https://gist.github.com/ammario/649d4c0da650162efd404af23e25b86b

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

*/
