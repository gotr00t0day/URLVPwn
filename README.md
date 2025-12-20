# URLVPwn

![Alt text](https://github.com/gotr00t0day/URLVPwn/blob/main/urlvpwn.jpg)


**URLVPwn** is a powerful URL validation bypass testing tool designed to evaluate Web Application Firewall (WAF) defenses on protected endpoints. It supports multiple attack classes including SSRF, open redirects, and path traversal, with advanced WAF bypass techniques and custom HTTP header injection capabilities.

---

## 🎯 Features

### Attack Classes
- **SSRF (Server-Side Request Forgery)** - Test SSRF vulnerabilities with callback URL encoding
- **Open Redirect** - Test URL validation bypasses for redirect vulnerabilities
- **Path Traversal** - Test directory traversal bypass techniques

### Advanced WAF Bypass Techniques
- **14 Encoding Methods** for callback URLs:
  - Raw URL (no encoding)
  - URL encode
  - Double URL encode
  - Triple URL encode
  - Hex encode
  - Octal encode
  - Unicode encode
  - Domain-only encoding
  - Path-only encoding
  - Dots encoding (%2E)
  - @ bypass technique
  - # bypass technique
  - Mixed encoding
  - **Custom HTTP header injection**

### Custom HTTP Header Injection
- Inject callback URLs into any HTTP header (Referer, X-Forwarded-For, Origin, etc.)
- Support for encoding callback URLs in headers
- Perfect for testing SSRF vulnerabilities where callbacks are sent via headers

### Additional Features
- Color-coded terminal output
- Support for HTTP and HTTPS
- SSL/TLS support
- Connection timeout handling
- Detailed request/response information
- Payload file-based testing for open redirects and path traversal

---

## 📋 Requirements

- **C++17** or higher
- **OpenSSL** (for HTTPS support)
- **Make** (for building)
- **GCC/G++** compiler

### macOS
```bash
brew install openssl@3
```

### Linux (Ubuntu/Debian)
```bash
sudo apt-get install build-essential libssl-dev
```

---

## 🔧 Installation

1. **Clone the repository:**
```bash
git clone https://github.com/gotr00t0day/URLVPwn.git
cd URLVPwn
```

2. **Build the project:**
```bash
make
```

3. **The executable will be created as `urlvpwn`**

### Clean Build
```bash
make clean
make
```

### Rebuild
```bash
make rebuild
```

---

## 🚀 Usage

### Basic Syntax
```bash
./urlvpwn <target_url> <payload_type>
```

### Payload Types
- `ssrf` - Server-Side Request Forgery testing
- `openredirect` - Open redirect vulnerability testing
- `pathtraversal` - Path traversal vulnerability testing

---

## 📖 Examples

### SSRF Testing

#### Basic SSRF Test
```bash
./urlvpwn http://target.com/api/fetch?url= ssrf
```

When prompted:
1. Enter your callback URL (e.g., `https://d53dtk7f7knvo5jbnb7gwbaejqxsabyhw.oast.live/`)
2. Choose an encoding method (1-14)

#### SSRF with Custom HTTP Header
```bash
./urlvpwn http://target.com/api/proxy ssrf
```

Select option **14** to send the callback URL in a custom HTTP header:
- Enter header name (e.g., `Referer`, `X-Forwarded-For`, `Origin`)
- Choose encoding for the callback URL in the header

**Example Output:**
```
[*] Sending SSRF request with custom header:
    Target URL: http://target.com/api/proxy
    Hostname: target.com
    Path: /api/proxy
    Header: Referer: https://d53dtk7f7knvo5jbnb7gwbaejqxsabyhw.oast.live/
    Request details:
    Method: GET
    Protocol: HTTP
[+] Request sent successfully!
    Status Code: 200
[*] Check your callback server: https://d53dtk7f7knvo5jbnb7gwbaejqxsabyhw.oast.live/
```

### Open Redirect Testing
```bash
./urlvpwn http://target.com/redirect?url= openredirect
```

The tool will:
- Load payloads from `payloads/open_redirect_bypasses.txt`
- Test each payload against the target URL
- Display results with color-coded output

### Path Traversal Testing
```bash
./urlvpwn http://target.com/api/file?path= pathtraversal
```

The tool will:
- Load payloads from `payloads/path_traversal_bypasses.txt`
- Test each payload against the target URL
- Check for successful traversal indicators

---

## 🔐 WAF Bypass Encoding Techniques

### Available Encoding Methods

1. **No encoding** - Raw callback URL
2. **URL encode** - Standard URL encoding (%XX)
3. **Double URL encode** - URL encoding applied twice
4. **Triple URL encode** - URL encoding applied three times
5. **Hex encode** - Hexadecimal encoding
6. **Octal encode** - Octal character encoding
7. **Unicode encode** - Unicode encoding (%uXXXX)
8. **Domain-only encoding** - Encodes only the domain, preserves protocol and path
9. **Path-only encoding** - Encodes only the path, preserves protocol and domain
10. **Dots encoding** - Encodes dots in domain (%2E)
11. **@ bypass** - Adds `evil.com@` before callback domain
12. **# bypass** - Adds fragment identifier to bypass filters
13. **Mixed encoding** - Selective encoding (protocol preserved)
14. **Custom HTTP header** - Send callback in any HTTP header

### When to Use Each Technique

- **URL/Double/Triple encoding**: Bypass WAFs that decode only once
- **Hex/Octal/Unicode**: Bypass signature-based detection
- **Domain/Path-only encoding**: When WAF checks specific URL parts
- **Dots encoding**: Bypass filters blocking domains with dots
- **@/# bypass**: Bypass URL parsing filters
- **Custom headers**: When SSRF reads URLs from HTTP headers

---

## 📁 Payload Files

The tool uses payload files located in the `payloads/` directory:

- `payloads/open_redirect_bypasses.txt` - Open redirect bypass payloads
- `payloads/path_traversal_bypasses.txt` - Path traversal bypass payloads
- `payloads/ssrf_bypasses.txt` - SSRF bypass payloads (for reference)

You can customize these files with your own payloads.

---

## 🎨 Output Colors

- **Green** - Successful requests/vulnerabilities found
- **Red** - Failed requests/errors
- **Yellow** - Information/status messages
- **Cyan** - Headers and technical details
- **Blue/Magenta** - Additional formatting

---

## 🔍 Use Cases

### 1. SSRF Testing with OAST Tools
Test SSRF vulnerabilities using OAST (Out-of-band Application Security Testing) tools like:
- Burp Collaborator
- Interactsh
- CanaryTokens
- Custom callback servers

### 2. WAF Evasion Testing
Evaluate how well WAFs handle various encoding techniques and bypass methods.

### 3. Security Assessment
Perform comprehensive security testing of URL validation mechanisms.

### 4. Bug Bounty Testing
Systematically test for URL validation bypass vulnerabilities.

---

## ⚠️ Legal Disclaimer

This tool is intended for **authorized security testing only**. Users are responsible for ensuring they have proper authorization before testing any systems. Unauthorized access to computer systems is illegal and may result in criminal prosecution.

**The author is not responsible for any misuse or damage caused by this tool.**

---

## 🛠️ Troubleshooting

### Compilation Issues

**OpenSSL not found:**
```bash
# macOS
export LDFLAGS="-L$(brew --prefix openssl@3)/lib"
export CPPFLAGS="-I$(brew --prefix openssl@3)/include"

# Linux
sudo apt-get install libssl-dev
```

**C++17 not supported:**
- Update your compiler to a version that supports C++17

### Runtime Issues

**Connection timeouts:**
- Check network connectivity
- Verify target URL is accessible
- Adjust timeout settings in code if needed

**SSL errors:**
- Verify OpenSSL is properly installed
- Check certificate validity for HTTPS targets

---

## 📝 Project Structure

```
URLVPwn/
├── main.cpp                 # Main entry point
├── Makefile                 # Build configuration
├── modules/
│   ├── urlvpwn.h           # Header file
│   └── urlvpwn.cpp         # Core implementation
├── includes/
│   └── httplib.h           # HTTP library
├── payloads/
│   ├── open_redirect_bypasses.txt
│   ├── path_traversal_bypasses.txt
│   └── ssrf_bypasses.txt
└── README.md               # This file
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

---

## 📄 License

This project is provided as-is for educational and authorized security testing purposes.

---

## 🙏 Acknowledgments

- Inspired by [PortSwigger's URL Validation Bypass Cheat Sheet](https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet)
- Uses [cpp-httplib](https://github.com/yhirose/cpp-httplib) for HTTP functionality

---

## 📧 Contact

- **Website:** https://gotr00t0day.github.io
- **Instagram:** @gotr00t0day

---

**Happy Hacking! 🚀**

