# API Sentinel — Security & Defensive Hardening Policy

## 1. Defensive-Only Scanning Scope
API Sentinel is engineered exclusively for defensive posture assessment and vulnerability monitoring of **authorized** assets:
- **No Exploitation Payloads**: Scanners send non-destructive probes designed solely to detect missing controls or misconfigurations.
- **Scope Verification**: Scanners execute only against targets registered and verified by authorized users.
- **Request Throttling**: Safety controls enforce concurrency ceilings and rate limits to prevent overloading target APIs.

---

## 2. Server-Side Request Forgery (SSRF) Mitigations

The outbound HTTP client incorporates comprehensive SSRF defense mechanisms:
1. **Scheme Whitelisting**: Strictly restricts requests to `http` and `https`.
2. **Pre-Flight DNS Resolution**: Resolves target hostnames prior to connection.
3. **Restricted Subnet Blocking**:
   - Loopback: `127.0.0.0/8`, `::1`
   - RFC 1918 Private: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
   - Link-Local / IMDS: `169.254.0.0/16`, `169.254.169.254`, `fd00:ec2::254`
   - Multicast & Carrier-Grade NAT.
4. **Cloud Metadata Hostname Blocking**: Blocks `metadata.google.internal`, `metadata.internal`, `instance-data`.

---

## 3. Cryptographic Protection of Credentials

- **At-Rest Encryption**: All stored API keys, bearer tokens, and credentials are encrypted using AES-GCM / Fernet cryptography with 100,000 PBKDF2-HMAC iterations.
- **Secret Redaction Engine**: Automated regex sanitization strips tokens and auth headers from all logged evidence, cURL snippets, and UI views.
- **Masked Previews**: Only partial previews (e.g. `sk-live-****92`) are displayed in the user interface.
