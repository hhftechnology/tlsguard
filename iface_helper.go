package tlsguard

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
)

// scanInterfaces returns CIDR ranges for network interfaces.
func scanInterfaces() ([]*net.IPNet, error) {
	netCidrs := make([]*net.IPNet, 0)
	ifaceName, err := getDefaultGatewayInterface()
	if err != nil {
		return nil, fmt.Errorf("failed to get default gateway interface: %w", err)
	}
	fmt.Println("Default Gateway Interface: ", ifaceName)
	
	ipv4Ranges, err := getIPv4AddressRanges(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get ipv4 address ranges: %w", err)
	}
	fmt.Println("IPv4 Address Ranges: ", ipv4Ranges)
	
	for _, ipRange := range ipv4Ranges {
		_, ipNet, iperr := net.ParseCIDR(ipRange)
		if iperr != nil {
			return nil, fmt.Errorf("invalid cidr: %s", ipRange)
		}
		netCidrs = append(netCidrs, ipNet)
	}
	
	ipv6Ranges, err := getIPv6AddressRanges(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get ipv6 address ranges: %w", err)
	}
	fmt.Println("IPv6 Address Ranges: ", ipv6Ranges)
	
	for _, ipRange := range ipv6Ranges {
		_, ipNet, err := net.ParseCIDR(ipRange)
		if err != nil {
			return nil, fmt.Errorf("invalid cidr: %s", ipRange)
		}
		netCidrs = append(netCidrs, ipNet)
	}

	return netCidrs, nil
}

// getDefaultGatewayInterface returns the name of the default gateway interface.
func getDefaultGatewayInterface() (string, error) {
	// Read the /proc/net/route file
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", err 

	}

	// Parse the file to find the default gateway interface
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) > 0 && fields[1] == "00000000" && fields[7] == "00000000" {
			// Found the default gateway, extract the interface name
			ifaceName := fields[0]
			return ifaceName, nil
		}
	}

	return "", errors.New("default gateway interface not found")
}

// getIPv4AddressRanges returns IPv4 address ranges for the specified interface.
func getIPv4AddressRanges(ifaceName string) ([]string, error) {
	var ipv4Ranges []string
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		if iface.Name == ifaceName {
			addrs, err := iface.Addrs()
			if err != nil {
				return nil, err
			}

			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}

				if ip.To4() != nil {
					mask, ok := addr.(*net.IPNet)
					if ok && mask.IP.To4() != nil {
						ones, _ := mask.Mask.Size()
						ipRange := fmt.Sprintf("%s/%v", ip, ones)
						ipv4Ranges = append(ipv4Ranges, ipRange)
					}
				}
			}
		}
	}

	return ipv4Ranges, nil
}

// getIPv6AddressRanges returns IPv6 address ranges for the specified interface.
func getIPv6AddressRanges(ifaceName string) ([]string, error) {
	var ipv6Ranges []string
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		if iface.Name == ifaceName {
			addrs, err := iface.Addrs()
			if err != nil {
				return nil, err
			}

			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}

				if ip.To4() == nil {
					mask, ok := addr.(*net.IPNet)
					if ok && ip.To16() != nil {
						ones, _ := mask.Mask.Size()
						ipRange := fmt.Sprintf("%s/%v", ip, ones)
						ipv6Ranges = append(ipv6Ranges, ipRange)
					}
				}
			}
		}
	}

	return ipv6Ranges, nil
}