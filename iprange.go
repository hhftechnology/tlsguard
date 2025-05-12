package tlsguard

import (
	"errors"
	"fmt"
	"net"
	"net/http"
)

// RuleIPRange implements a rule that matches client IP addresses.
type RuleIPRange struct {
	Ranges       []string `json:"ranges"`
	AddInterface bool     `json:"addInterface,omitempty"`

	// Internal
	allowedCidrs []*net.IPNet
}

// Init initializes the rule.
func (r *RuleIPRange) Init() error {
	netCidrs := make([]*net.IPNet, 0, len(r.Ranges))

	fmt.Printf("Ranges: %v", r.Ranges)
	for _, cidr := range r.Ranges {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid cidr: %s %w", cidr, err)
		}
		netCidrs = append(netCidrs, ipNet)
	}
	if r.AddInterface {
		interfaceCidrs, neterr := scanInterfaces()
		if neterr != nil {
			return neterr
		}
		netCidrs = append(netCidrs, interfaceCidrs...)
	}

	r.allowedCidrs = netCidrs

	fmt.Println("Allowed CIDRs: ", r.allowedCidrs)

	if len(r.allowedCidrs) == 0 {
		return errors.New("no ranges provided")
	}

	return nil
}

// Match checks if the client IP matches any of the allowed ranges.
func (r *RuleIPRange) Match(req *http.Request) bool {
	realIP := req.Header.Get("X-Real-Ip")
	if realIP == "" {
		realIP = req.Header.Get("X-Forwarded-For")
	}
	allowed, cidr := r.isIPInRange(realIP)
	if allowed {
		req.Header.Set("X-TLSGuard-Cidr", cidr)
	}

	return allowed
}

// isIPInRange checks if an IP is in any of the allowed ranges.
func (r *RuleIPRange) isIPInRange(ip string) (bool, string) {
	realIP := net.ParseIP(ip)
	if realIP == nil {
		return false, ""
	}

	for _, cidr := range r.allowedCidrs {
		if cidr.Contains(realIP) {
			return true, cidr.String()
		}
	}
	return false, ""
}