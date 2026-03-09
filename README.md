# Client WHOIS Lookup (WHMCS Addon Module)

A secure, public-facing WHOIS lookup module for WHMCS that allows visitors or clients to perform WHOIS queries while maintaining performance, abuse protection, and administrative control.

This module provides:

- Public WHOIS lookup interface
- Strict domain validation (`<second-level-domain>.<top-level-domain>`)
- Configurable list of allowed TLDs
- WHOIS server overrides per TLD
- Automatic IANA WHOIS referral fallback
- Filesystem-based WHOIS caching
- Built-in WHMCS CAPTCHA protection for anonymous users
- Admin interface for managing WHOIS servers
- IDN / Punycode support
- Zero external dependencies
---

## Features

### Public WHOIS Lookup

The module creates a publicly accessible WHOIS lookup page:

```
https://yourwhmcs.com/index.php?m=client_whois
```

Visitors can search domains in the format:

```
example.com
example.net
example.org
```

The module strictly enforces the format:

```
<second-level-domain>.<top-level-domain>
```

Subdomains are not allowed.

Example of valid input:

```
example.com
test.org
mydomain.xyz
```

Invalid inputs:

```
example.com.au
test.example.com
http://example.com
```
---

## CAPTCHA Protection

Anonymous visitors must pass WHMCS CAPTCHA verification before a WHOIS lookup is executed.

CAPTCHA is automatically integrated with WHMCS security settings.

Supported CAPTCHA providers include:

- reCAPTCHA
- hCaptcha
- Cloudflare Turnstile
- WHMCS internal CAPTCHA

Logged-in users do **not** see CAPTCHA.

Configure CAPTCHA in:

```
WHMCS Admin → System Settings → Security → CAPTCHA
```

---

## WHOIS Server Resolution

The module resolves WHOIS servers in the following order:

1. Admin-defined WHOIS server (database)
2. Static fallback mapping
3. IANA referral lookup

Example resolution flow:

```
example.com
→ check admin override
→ fallback to static map
→ fallback to IANA whois.iana.org
→ follow referral server
```

This ensures maximum compatibility across TLD registries.

---

## WHOIS Caching

To improve performance and prevent abuse, WHOIS responses are cached locally.

Cache behavior:

| Property | Value |
|--------|------|
| Storage | Filesystem |
| Cache key | SHA1(domain) |
| Default TTL | 3600 seconds |
| Directory | `/modules/addons/client_whois/cache/` |

Example cache file:

```
cache/whois_9f86d081884c7d659a2feaa0c55ad015.txt
```

When cache exists and has not expired:

- No outbound WHOIS connection is made
- Cached response is returned instantly

---

## Admin WHOIS Server Management

The module provides a database-backed admin interface allowing custom WHOIS servers to be defined per TLD.

Admin page:

```
WHMCS Admin → Addons → Client WHOIS Lookup
```

You can:

- Add WHOIS servers
- Edit existing servers
- Disable servers
- Delete entries

Database table:

```
mod_client_whois_servers
```

Schema:

| Column | Description |
|------|------|
| id | Primary key |
| tld | TLD without leading dot |
| server | WHOIS hostname |
| port | WHOIS port (default 43) |
| active | Enable / disable |
| created_at | Timestamp |
| updated_at | Timestamp |

Example entry:

```
tld: com
server: whois.verisign-grs.com
port: 43
active: 1
```

---

## Allowed TLD Configuration

The module validates TLDs using a configurable list.

File:

```
/modules/addons/client_whois/config/tlds.php
````

Example:

```php
return [
    ".com",
    ".net",
    ".org",
    ".xyz",
];
````

If the module setting **Allow Non-Listed TLDs** is disabled, the domain must use one of these TLDs.

---

# File Structure

```
modules/addons/client_whois/
│
├── client_whois.php
├── README.md
│
├── config/
│   └── tlds.php
│
├── lib/
│   ├── WhoisClient.php
│   └── WhoisServers.php
│
├── templates/
│   ├── clientarea.tpl
│   └── style.css
│
└── cache/
```

---

## Installation

1. Upload the module directory:

```
/modules/addons/client_whois/
```

2. Ensure cache directory exists:

```
/modules/addons/client_whois/cache/
```

Set permissions:

```
chmod 755 cache
```

3. Login to WHMCS Admin.

4. Navigate to:

```
System Settings → Addon Modules
```

5. Activate **Client WHOIS Lookup**

6. Configure module settings.

---

## Module Settings

| Setting               | Description                       |
| --------------------- | --------------------------------- |
| Page Title            | Title shown on the lookup page    |
| WHOIS Timeout         | Socket timeout for WHOIS requests |
| Max Bytes             | Maximum WHOIS response size       |
| Cache TTL             | Cache expiration time             |
| Allow Non-Listed TLDs | Disable strict TLD validation     |

---

## Accessing the WHOIS Page

The module is publicly available at:

```
index.php?m=client_whois
```

Example:

```
https://yourwhmcs.com/index.php?m=client_whois
```

---

# Domain Validation Rules

The module validates:

* Exactly one dot in the domain
* SLD length 1–63 characters
* Only characters allowed in SLD:

```
a-z
0-9
-
```

Hyphens cannot appear at the start or end.

Examples:

Valid:

```
example.com
my-domain.net
test123.org
```

Invalid:

```
-example.com
example-.net
test..org
```

---

## Security Features

The module includes several abuse protections:

### CAPTCHA Protection

Anonymous users must pass CAPTCHA before lookup.

### Strict Domain Validation

Prevents injection attempts.

### Output Size Limits

WHOIS responses are truncated if they exceed configured limits.

### Timeout Protection

Socket connections automatically close after timeout.

### Cached Responses

Reduces repeated WHOIS requests.

---

## Performance Characteristics

Typical response times:

| Scenario     | Time       |
| ------------ | ---------- |
| Cache hit    | < 5 ms     |
| Cached WHOIS | < 20 ms    |
| Live WHOIS   | 200–900 ms |

Cache dramatically improves performance under load.

---

## IDN / International Domain Support

The module supports:

* Unicode domains
* Punycode conversion
* IDNA (UTS#46)

Example:

```
münchen.de
xn--mnchen-3ya.de
```

---

## Troubleshooting

### "WHOIS lookup failed"

Check firewall rules allowing outbound port 43.

Example:

```
iptables -A OUTPUT -p tcp --dport 43 -j ACCEPT
```

### Cache not writing

Ensure permissions:

```
chmod 755 cache
```

or

```
chown www-data cache
```

### CAPTCHA not showing

Verify CAPTCHA is enabled in:

```
WHMCS → Security Settings
```

---

## Optional Enhancements

The module architecture supports future extensions such as:

* IP rate limiting
* Redis caching
* WHOIS parsing
* Domain availability checking
* Registrar detection
* Admin cache purge
* WHOIS usage analytics

---

## License

This module is provided for internal or commercial use within WHMCS environments.

---

## Support

For issues or feature requests, review the module code or extend functionality using WHMCS addon development guidelines.
