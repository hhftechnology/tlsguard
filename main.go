// Package tlsguard is a Traefik plugin that combines certificate-based user authentication
// with IP whitelisting for comprehensive access control.
package tlsguard

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"text/template"
	"time"
)

// TLSGuard is the main plugin struct.
type TLSGuard struct {
	next           http.Handler
	name           string
	config         *Config
	matchers       *RuleConfig
	updateMutex    sync.Mutex
	requestHeaders map[string]*template.Template
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// New creates a new TLSGuard plugin instance.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Initialize rule configuration if rules are present
	var matchers *RuleConfig
	var err error
	
	if len(config.Rules) > 0 {
		matchers, err = NewRuleConfig(config)
		if err != nil {
			return nil, err
		}
		
		err = matchers.Init()
		if err != nil {
			return nil, err
		}
	}
	
	// Initialize request header templates
	templates := make(map[string]*template.Template, len(config.RequestHeaders))
	for headerName, headerTemplate := range config.RequestHeaders {
		tmpl, err := template.New(headerName).Delims("[[", "]]").Parse(headerTemplate)
		if err != nil {
			return nil, err // Return error to prevent middleware creation
		}
		templates[headerName] = tmpl
	}

	return &TLSGuard{
		next:           next,
		name:           name,
		config:         config,
		matchers:       matchers,
		requestHeaders: templates,
	}, nil
}

// ServeHTTP implements the http.Handler interface.
func (tg *TLSGuard) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Check for TLS client certificate
	if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
		cert := req.TLS.PeerCertificates[0]
		
		// Try user authentication first
		username, ok := tg.findUserByCert(cert)
		if ok {
			// Set username header if configured
			if tg.config.UsernameHeader != "" {
				req.Header.Set(tg.config.UsernameHeader, username)
			}
			
			// Add certificate headers
			tg.addCertHeaders(req, cert)
			
			// Continue to next handler
			tg.next.ServeHTTP(rw, req)
			return
		}
		
		// Certificate present but user not found
		req.Header.Set("X-TLSGuard-Cert-SN", cert.SerialNumber.String())
		req.Header.Set("X-TLSGuard-Cert-CN", cert.Subject.CommonName)
		tg.addCertHeaders(req, cert)
	} else {
		// No certificate provided
		req.Header.Set("X-TLSGuard-Cert-SN", "NoCert")
	}
	
	// If no valid user certificate or no rules defined, check if rules allow access
	if tg.matchers != nil {
		allowed := tg.matchers.Match(req)
		if !allowed {
			// Check if config needs an update
			if tg.matchers.NextUpdate != nil && tg.matchers.NextUpdate.Before(time.Now()) {
				err := tg.updateConfig()
				if err != nil {
					fmt.Printf("error updating config: %v", err)
				}
				allowed = tg.matchers.Match(req)
			}
			
			if !allowed {
				http.Error(rw, "Forbidden", http.StatusForbidden)
				return
			}
		}
	} else if req.TLS == nil || len(req.TLS.PeerCertificates) == 0 {
		// No certificate, no rules, not allowed
		http.Error(rw, "TLS client certificate is required for authentication", http.StatusForbidden)
		return
	}
	
	// Add additional headers if defined
	tg.addRequestHeaders(req)
	
	// Update config if required
	tg.updateConfigIfRequired()
	
	// Continue to next handler
	tg.next.ServeHTTP(rw, req)
}

// findUserByCert attempts to find a user based on the certificate.
func (tg *TLSGuard) findUserByCert(cert *x509.Certificate) (string, bool) {
	// Check for no users configured case
	if tg.config.Users == nil || len(tg.config.Users) == 0 {
		return "", false
	}
	
	// Check Common Name
	username, ok := tg.findUserByID(cert.Subject.CommonName)
	if ok {
		return username, true
	}

	// Check DNS names
	for _, dnsName := range cert.DNSNames {
		username, ok = tg.findUserByID(dnsName)
		if ok {
			return username, true
		}
	}

	// Check email addresses
	for _, email := range cert.EmailAddresses {
		username, ok = tg.findUserByID(email)
		if ok {
			return username, true
		}
	}

	return "", false
}

// findUserByID checks if a user ID exists in the configured users map.
func (tg *TLSGuard) findUserByID(userID string) (string, bool) {
	// Check if ID is empty
	if userID == "" {
		return "", false
	}

	// Check if user is in users config
	username, ok := tg.config.Users[userID]
	if !ok {
		return "", false
	}

	// Fallback to user ID if username is empty
	if username == "" {
		username = userID
	}

	return username, true
}

// addCertHeaders adds certificate information to request headers.
func (tg *TLSGuard) addCertHeaders(req *http.Request, cert *x509.Certificate) {
	// Add certificate headers
	req.Header.Set("X-TLSGuard-Cert-SN", cert.SerialNumber.String())
	req.Header.Set("X-TLSGuard-Cert-CN", cert.Subject.CommonName)
	
	// Add additional headers if defined as requestHeaders
	for headerName, tmpl := range tg.requestHeaders {
		var tplOutput strings.Builder
		err := tmpl.Execute(&tplOutput, map[string]interface{}{
			"Cert": cert,
			"Req":  req,
		})
		if err != nil {
			fmt.Printf("Error executing template for header %s: %v\n", headerName, err)
			continue // Skip this header if there's an error
		}
		req.Header.Set(headerName, tplOutput.String())
	}
}

// addRequestHeaders adds template-based headers to the request.
func (tg *TLSGuard) addRequestHeaders(req *http.Request) {
	for headerName, tmpl := range tg.requestHeaders {
		var tplOutput strings.Builder
		err := tmpl.Execute(&tplOutput, map[string]interface{}{
			"Req": req,
		})
		if err != nil {
			fmt.Printf("Error executing template for header %s: %v\n", headerName, err)
			continue
		}
		req.Header.Set(headerName, tplOutput.String())
	}
}

// updateConfigIfRequired checks and updates the configuration if needed.
func (tg *TLSGuard) updateConfigIfRequired() {
	if tg.matchers != nil && tg.matchers.NextUpdate != nil && tg.matchers.NextUpdate.Before(time.Now()) {
		go func() {
			err := tg.updateConfig()
			if err != nil {
				fmt.Printf("could not update config %v\n", err)
			}
		}()
	}
}

// updateConfig refreshes the rule configuration.
func (tg *TLSGuard) updateConfig() error {
	tg.updateMutex.Lock()
	defer tg.updateMutex.Unlock()

	if tg.matchers == nil || tg.matchers.NextUpdate == nil || tg.matchers.NextUpdate.After(time.Now()) {
		return nil
	}

	newMatchers, err := NewRuleConfig(tg.config)
	if err != nil {
		fmt.Println("Error updating matchers: ", err)
		return err
	}
	err = newMatchers.Init()
	if err != nil {
		fmt.Println("Error updating matchers: ", err)
		return err
	}
	tg.matchers = newMatchers
	return nil
}