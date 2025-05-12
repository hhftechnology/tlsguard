
<div align="center" width="100%">
    <h1> TLSGuard - Comprehensive Authentication Plugin for Traefik v3</h1>
    <img width="auto" src=".assets/banner.png">
    <a target="_blank" href="https://GitHub.com/hhftechnology/tlsguard/graphs/contributors/"><img src="https://img.shields.io/github/contributors/hhftechnology/tlsguard.svg" /></a><br>
    <a target="_blank" href="https://GitHub.com/hhftechnology/tlsguard/commits/"><img src="https://img.shields.io/github/last-commit/hhftechnology/tlsguard.svg" /></a>
    <a target="_blank" href="https://GitHub.com/hhftechnology/tlsguard/issues/"><img src="https://img.shields.io/github/issues/hhftechnology/tlsguard.svg" /></a>
    <a target="_blank" href="https://github.com/hhftechnology/tlsguard/issues?q=is%3Aissue+is%3Aclosed"><img src="https://img.shields.io/github/issues-closed/hhftechnology/tlsguard.svg" /></a><br>
        <a target="_blank" href="https://github.com/hhftechnology/tlsguard/stargazers"><img src="https://img.shields.io/github/stars/hhftechnology/tlsguard.svg?style=social&label=Star" /></a>
    <a target="_blank" href="https://github.com/hhftechnology/tlsguard/network/members"><img src="https://img.shields.io/github/forks/hhftechnology/tlsguard.svg?style=social&label=Fork" /></a>
    <a target="_blank" href="https://github.com/hhftechnology/tlsguard/watchers"><img src="https://img.shields.io/github/watchers/hhftechnology/tlsguard.svg?style=social&label=Watch" /></a><br>
</div>

<div align="center" width="100%">
    <p>TLSGuard is a powerful authentication plugin for Traefik that combines certificate-based user authentication with IP whitelisting and rule-based access control, providing flexible and robust security for your services.</p>
    <a target="_blank" href="https://github.com/hhftechnology/tlsguard"><img src="https://img.shields.io/badge/maintainer-hhftechnology-orange" /></a>
</div>

## 📝 Forums

[See the forums for further discussion here](https://forum.hhf.technology/)


## Features

- **Certificate-based User Authentication**: Authenticate users based on the Common Name, DNS Names, and Email Addresses of their TLS client certificates
- **IP Whitelisting**: Allow access based on client IP address ranges when no valid certificate is provided
- **Rule-based Access Control**: Combine rules with logical operators (AllOf, AnyOf, NoneOf)
- **Header-based Authentication**: Define rules to match specific HTTP headers
- **External Data Sources**: Load configuration from external APIs or files
- **Automatic Network Detection**: Automatically include local network ranges
- **Custom Request Headers**: Add custom headers to requests based on certificate information
- **Periodic Configuration Refresh**: Update rules from external sources at configurable intervals

## Installation

### Using Traefik Pilot (Plugin Catalog)

1. Enable the Traefik Pilot feature in your Traefik configuration
2. Add the plugin to your Traefik static configuration:

```yaml
# traefik.yml
experimental:
  plugins:
    tlsguard:
      moduleName: github.com/hhftechnology/tlsguard
      version: v1.0.0
```

### Local Development

1. Clone the repository:
   ```bash
   git clone https://github.com/hhftechnology/tlsguard.git
   ```

2. Use local plugin in Traefik configuration:
   ```yaml
   # traefik.yml
   experimental:
     localPlugins:
       tlsguard:
         moduleName: github.com/hhftechnology/tlsguard
   ```

## Configuration

TLSGuard provides a flexible configuration model that can be tailored to your specific security requirements.

### User Authentication

The plugin can authenticate users based on certificate attributes and add the username as a request header.

```yaml
# User authentication based on certificates
usernameHeader: "User"  # Header to add with username
users:  
  alice: alice        # Common Name "alice" maps to username "alice"
  bob1: bob           # Common Name "bob1" maps to username "bob"
  charlie@example.org: charlie  # Email "charlie@example.org" maps to username "charlie"
```

The authentication flow checks these certificate fields in order:
1. Subject Common Name
2. Subject Alternative Names (DNS Names)
3. Subject Alternative Names (Email Addresses)

### Rule Types

If no valid certificate is presented (or if you want additional restrictions even with certificates), the plugin supports the following rule types:

#### AllOf

This rule matches if all sub-rules match (logical AND):

```yaml
rules:
  - type: allOf
    rules:
      - type: ipRange
        ranges: ["192.168.1.0/24"]
      - type: header
        headers:
          User-Agent: ".*Firefox.*"
```

#### AnyOf

This rule matches if any sub-rule matches (logical OR):

```yaml
rules:
  - type: anyOf
    rules:
      - type: ipRange
        ranges: ["192.168.1.0/24"]
      - type: header
        headers:
          User-Agent: ".*Firefox.*"
```

#### NoneOf

This rule matches if no sub-rule matches (logical NOT):

```yaml
rules:
  - type: noneOf
    rules:
      - type: ipRange
        ranges: ["192.168.1.0/24"]
      - type: header
        headers:
          User-Agent: ".*Firefox.*"
```

#### IPRange

This rule matches if the client IP is in any of the specified ranges:

```yaml
rules:
  - type: ipRange
    ranges:
      - 192.168.1.0/24
      - 10.0.0.0/8
    addInterface: true  # Add local network ranges
```

The `addInterface` option automatically adds the IP ranges of the network interfaces with the default route on the system. This is useful when running in containers or on systems with dynamic IP assignments.

#### Header

This rule matches if request headers match the specified patterns (using regular expressions):

```yaml
rules:
  - type: header
    headers:
      User-Agent: ".*Chrome.*"
      Accept-Language: "en-US,en;q=0.5"
```

All specified headers must match their patterns for the rule to match.

### External Data

TLSGuard supports loading configuration from external sources, which is particularly useful for dynamic environments:

```yaml
externalData:
  url: https://api.example.com/config
  dataKey: data  # Key in the JSON response containing the relevant data
  skipTlsVerify: false  # Set to true to skip TLS certificate verification
  headers:
    Authorization: "Bearer [[ file \"/path/to/token\" ]]"
    Content-Type: "application/json"
```

The external data is fetched when the plugin is initialized and can be used in rule templates.

### Template Functions

TLSGuard supports the following template functions in configuration values:

- `[[ file "/path/to/file" ]]`: Replace with the contents of the specified file
- `[[ env "ENVIRONMENT_VARIABLE" ]]`: Replace with the value of the specified environment variable
- `[[ .data.someField ]]`: Replace with a field from the external data source

Templates are enclosed in `[[` and `]]` delimiters.

### Custom Request Headers

Add custom headers to requests based on certificate information:

```yaml
requestHeaders:
  X-Cert-Mail: "[[.Cert.Subject.CommonName]]@example.com"
  X-Cert-Issuer: "[[.Cert.Issuer.CommonName]]"
  X-User-Context: "role=admin,org=[[.Cert.Subject.Organization]]"
```

The following variables are available in the templates:
- `Cert`: The client certificate (when available)
- `Req`: The HTTP request

### Automatic Configuration Refresh

TLSGuard can periodically refresh its configuration from external sources:

```yaml
refreshInterval: 30m  # Valid time units: s, m, h
```

This is especially useful for dynamic environments where IP whitelists or other rules change frequently.

## Complete Example

Here's a complete example for Traefik dynamic configuration:

```yaml
http:
  middlewares:
    tlsguard:
      plugin:
        tlsguard:
          # User authentication
          usernameHeader: "User"
          users:
            alice: alice
            alice1: alice  # Multiple certificates for the same user
            bob1: bob
            charlie@example.org: charlie
          
          # Custom headers
          requestHeaders:
            X-Cert-Mail: "[[.Cert.Subject.CommonName]]@example.com"
            X-Cert-Organization: "[[.Cert.Subject.Organization]]"
          
          # Configuration refresh
          refreshInterval: 30m
          
          # External data source
          externalData:
            url: https://config-api.example.com/whitelist
            dataKey: data
            skipTlsVerify: false
            headers:
              Authorization: "Bearer [[ file \"/secrets/api-token\" ]]"
              Content-Type: "application/json"
          
          # Rule-based access control
          rules:
            - type: anyOf
              rules:
                # Allow specific IP ranges
                - type: ipRange
                  ranges:
                    - 192.168.0.0/16
                    - 10.0.0.0/8
                    - "[[ .data.ipRanges ]]"  # From external data
                  addInterface: true
                
                # Allow specific user agents
                - type: header
                  headers:
                    User-Agent: ".*Firefox.*"
                    X-Api-Key: "[[ .data.apiKey ]]"  # From external data

  routers:
    secure:
      rule: "Host(`secure.example.com`)"
      service: my-service
      tls:
        options: clientauth
      middlewares:
        - tlsguard

tls:
  options:
    clientauth:
      clientAuth:
        caFiles:
          - /path/to/ca.crt
        clientAuthType: VerifyClientCertIfGiven  # Important: allows both cert and non-cert access
```

## Setup with Client Certificates

### Creating a Certificate Authority

1. Create a Certificate Authority (CA):
   ```bash
   openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.crt -days 365 -nodes -subj "/CN=My Custom CA"
   ```

2. Create a client certificate signed by the CA:
   ```bash
   # Create a private key
   openssl genrsa -out client.key 4096
   
   # Create a Certificate Signing Request (CSR)
   openssl req -new -key client.key -out client.csr -subj "/CN=alice"
   
   # Sign the CSR with the CA
   openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365
   
   # Create a combined PEM file for clients
   cat client.crt client.key > client.pem
   ```

3. Configure Traefik to require client certificates:
   ```yaml
   tls:
     options:
       clientauth:
         clientAuth:
           caFiles:
             - /path/to/ca.crt
           clientAuthType: VerifyClientCertIfGiven  # Allows fallback to IP whitelist
   ```

4. Use the client certificate in requests:
   ```bash
   curl --cert client.pem https://secure.example.com
   ```

## Security Considerations

### Client Certificate Verification

When using the `VerifyClientCertIfGiven` option, be aware that:
- Clients with valid certificates will be authenticated based on the certificate
- Clients without certificates will fall back to IP whitelisting rules
- Invalid certificates will be rejected

For stricter security, consider using `RequireAndVerifyClientCert` in Traefik's TLS options, but note that this will require valid certificates from all clients and disable IP whitelisting.

### IP Spoofing Protection

When using IP whitelisting, be aware of potential IP spoofing attacks. TLSGuard checks the following headers in order to determine the client's IP address:
1. `X-Real-Ip` header
2. `X-Forwarded-For` header

Ensure your reverse proxy or load balancer correctly sets these headers and that they cannot be spoofed by clients.

### Regular Expression Security

When using regular expressions in header rules, be careful of potential regex denial-of-service (ReDoS) attacks. Avoid overly complex patterns with excessive backtracking.

## Headers Added by TLSGuard

TLSGuard adds the following headers to requests:

- `X-TLSGuard-Cert-SN`: Serial number of the client certificate (or "NoCert" if none)
- `X-TLSGuard-Cert-CN`: Common Name of the client certificate
- `X-TLSGuard-Cidr`: CIDR range that matched the client IP (when applicable)
- `X-TLSGuard-Header`: Set to "true" when a header rule matches
- Custom headers configured in `requestHeaders`
- Username header (if configured in `usernameHeader`)

## Development and Testing

### Prerequisites

- Go 1.19 or higher
- Golangci-lint
- Yaegi (for Traefik plugin testing)

### Running Tests

```bash
go test -v -cover ./...
```

### Testing with Yaegi

```bash
yaegi test -v .
```

### Local Testing with Docker Compose

The repository includes a Docker Compose setup for local testing:

1. Generate test certificates:
   ```bash
   cd tests/certs
   make
   ```

2. Start the test environment:
   ```bash
   cd tests
   docker-compose up -d
   ```

3. Test access with and without certificates:
   ```bash
   # With certificate
   curl -k --cert certs/alice-client.pem --key certs/alice-client-key.pem https://whoami.localhost.direct:8140
   
   # Without certificate (IP whitelist)
   curl -k https://whoami.localhost.direct:8140
   ```

## Troubleshooting

### Common Issues

1. **Certificate not recognized**:
   - Ensure the CA certificate is correctly configured in Traefik
   - Check that the certificate's Common Name or Subject Alternative Names match entries in the `users` configuration
   - Verify the certificate is valid and not expired

2. **IP whitelist not working**:
   - Check that the CIDR ranges are correctly formatted
   - Ensure the client's IP is correctly detected (X-Real-Ip or X-Forwarded-For headers)
   - Verify the `addInterface` option if relying on local network detection

3. **External data not loading**:
   - Check network connectivity to the external data source
   - Verify authentication headers are correct
   - Check that the response format matches expectations

### Debugging

Enable debug logging in Traefik to see detailed information about the authentication process:

```yaml
log:
  level: DEBUG
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Contact

HHF Technology - https://forum.hhf.technology

Project Link: [https://github.com/hhftechnology/tlsguard](https://github.com/hhftechnology/tlsguard)