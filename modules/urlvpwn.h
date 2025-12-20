#pragma once
#include <vector>
#include <string>

void validateURL (std::string& urls);
std::vector<std::string> getPayloads (const std::string& file);
void Resolve(const std::string& urls, const std::string& payloadType);
void sendSSRFWithHeader(const std::string& targetUrl, const std::string& headerName, const std::string& headerValue);
std::string urlEncode(const std::string& url);
std::string doubleUrlEncode(const std::string& url);
std::string hexEncode(const std::string& url);
std::string octalEncode(const std::string& url);
std::string unicodeEncode(const std::string& url);
std::string encodeDomainOnly(const std::string& url);
std::string encodePathOnly(const std::string& url);
std::string encodeDotsOnly(const std::string& url);
std::string tripleUrlEncode(const std::string& url);
std::string addAtBypass(const std::string& url);
std::string addHashBypass(const std::string& url);
std::string mixedEncoding(const std::string& url);