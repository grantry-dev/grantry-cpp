// Windows platform layer: WinHTTP, BCrypt/CNG and DPAPI.
//
// ⚠️ NO THIRD-PARTY LIBRARIES, DELIBERATELY. Every function here is served by
// something in-box on Windows, which means a customer shipping this SDK ships
// no extra DLL beside their executable, reconciles nothing against whatever
// their engine already loaded, and inherits the system's certificate store and
// its updates for free. Linking OpenSSL to do the same work would be three
// megabytes and a CVE feed.
#ifdef _WIN32

#include "internal.hpp"

// clang-format off
//
// ⚠️ `WIN32_NO_STATUS` IS NOT OPTIONAL HERE. `windows.h` defines a handful of
// NTSTATUS codes itself, and `ntstatus.h` defines all of them — including those
// same ones, identically. Including both without this produces ~40 macro
// redefinition warnings, which is exactly the kind of noise that hides a real
// one. Defining it suppresses the subset in `windows.h`, and it is undefined
// again immediately so nothing downstream inherits a half-configured header.
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <shellapi.h>
#include <objbase.h>
#include <sddl.h>
#include <ntsecapi.h>
// clang-format on

#include <algorithm>
#include <cstdio>
#include <cstring>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
// `SHGetKnownFolderPath` hands back memory that only `CoTaskMemFree` can
// release, and that lives in ole32 rather than shell32. Named explicitly
// because CMake's default MSVC library list happens to include it — so leaving
// it implicit builds here and fails for anybody linking by hand.
#pragma comment(lib, "ole32.lib")

// Windows 8's chain query, which CertificateIsPinned reads; MinGW's headers lag the SDK's.
#ifndef WINHTTP_OPTION_SERVER_CERT_CHAIN_CONTEXT
#define WINHTTP_OPTION_SERVER_CERT_CHAIN_CONTEXT 147
#endif

namespace grantry {
namespace internal {
namespace {

std::wstring Widen(const std::string& text) {
  if (text.empty()) return std::wstring();
  int length = MultiByteToWideChar(CP_UTF8, 0, text.c_str(),
                                   static_cast<int>(text.size()), nullptr, 0);
  std::wstring wide(static_cast<std::size_t>(length), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                      &wide[0], length);
  return wide;
}

std::string Narrow(const std::wstring& text) {
  if (text.empty()) return std::string();
  int length = WideCharToMultiByte(CP_UTF8, 0, text.c_str(),
                                   static_cast<int>(text.size()), nullptr, 0,
                                   nullptr, nullptr);
  std::string narrow(static_cast<std::size_t>(length), '\0');
  WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                      &narrow[0], length, nullptr, nullptr);
  return narrow;
}

/// RAII for the three WinHTTP handles, so an early return cannot leak one.
struct Handle {
  HINTERNET value = nullptr;
  ~Handle() { if (value != nullptr) WinHttpCloseHandle(value); }
  Handle() = default;
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
};

std::string LowerCase(const std::string& text) {
  std::string out = text;
  for (char& c : out) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return out;
}

void ParseHeaders(const std::wstring& raw, std::map<std::string, std::string>& out) {
  std::string all = Narrow(raw);
  std::size_t start = 0;
  while (start < all.size()) {
    std::size_t end = all.find("\r\n", start);
    if (end == std::string::npos) end = all.size();
    std::string line = all.substr(start, end - start);
    start = end + 2;

    std::size_t colon = line.find(':');
    if (colon == std::string::npos) continue;

    std::string name = LowerCase(line.substr(0, colon));
    std::size_t value_start = colon + 1;
    while (value_start < line.size() && line[value_start] == ' ') value_start++;
    out[name] = line.substr(value_start);
  }
}

}  // namespace

/// The DER SubjectPublicKeyInfo of a certificate WinHTTP handed us, hashed.
///
/// ⚠️ THE PUBLIC KEY, NOT THE CERTIFICATE. Pinning a leaf means every renewal
/// bricks every shipped build, on somebody else's ninety-day schedule. The SPKI
/// survives renewal because the key does.
///
/// CryptEncodeObject re-emits the structure Windows already parsed, so the
/// bytes hashed here are the same bytes openssl would print — a fingerprint
/// nobody else can compute is a pin nobody can rotate.
std::string SpkiFingerprint(PCCERT_CONTEXT certificate) {
  if (certificate == nullptr || certificate->pCertInfo == nullptr) return std::string();

  DWORD size = 0;
  if (!CryptEncodeObject(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
                         &certificate->pCertInfo->SubjectPublicKeyInfo, nullptr, &size)
      || size == 0) {
    return std::string();
  }

  std::vector<std::uint8_t> spki(size);
  if (!CryptEncodeObject(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
                         &certificate->pCertInfo->SubjectPublicKeyInfo, spki.data(), &size)) {
    return std::string();
  }
  spki.resize(size);

  return Base64Encode(Sha256(spki));
}

/// Whether the server presented a key we published.
///
/// ⚠️ CHECKED AFTER THE HANDSHAKE, WHICH IS THE BEST WinHTTP OFFERS IN
/// SYNCHRONOUS MODE. There is no hook that fires between the handshake and the
/// request, so this cannot refuse before the headers go out the way libcurl's
/// CURLOPT_PINNEDPUBLICKEY does on POSIX. That gap is why `GrantryClient`
/// probes the transport with a credential-free request before it sends anything
/// worth intercepting: by the time a session token travels, a proxy has already
/// been detected and every call refused.
///
/// ⚠️ AND THE CHAIN IS STILL VALIDATED — WinHTTP did that during the
/// handshake, and this SDK offers no option to skip it. Pinning ADDS a test; a
/// pin that replaced chain validation would accept an expired or revoked
/// certificate carrying the right key, which is weaker than not pinning.
///
/// ⚠️ EVERY CERTIFICATE IN THE CHAIN WINDOWS BUILT, NOT ONLY THE SERVER'S (17
/// October 2026). The built-in pins are Let's Encrypt's roots (crypto.cpp), and
/// a root is never the certificate the server presents first. The chain is the
/// one Windows validated against its own store, so it runs to the trust anchor
/// whether or not the server sent the root; a cross-signed copy carries the
/// same key as the root it stands for, so a store that stops at ISRG Root X1
/// and one that holds Root YE both match.
bool CertificateIsPinned(HINTERNET http_request, const std::vector<std::string>& pins) {
  auto pinned = [&pins](PCCERT_CONTEXT certificate) {
    const std::string fingerprint = SpkiFingerprint(certificate);
    if (fingerprint.empty()) return false;
    for (const std::string& pin : pins) {
      if (!pin.empty() && FixedTimeEquals(pin, fingerprint)) return true;
    }
    return false;
  };

  PCCERT_CHAIN_CONTEXT chain = nullptr;
  DWORD chain_size = sizeof(chain);
  if (WinHttpQueryOption(http_request, WINHTTP_OPTION_SERVER_CERT_CHAIN_CONTEXT, &chain,
                         &chain_size)
      && chain != nullptr) {
    bool matched = false;
    for (DWORD i = 0; i < chain->cChain && !matched; ++i) {
      const CERT_SIMPLE_CHAIN* simple = chain->rgpChain[i];
      for (DWORD j = 0; simple != nullptr && j < simple->cElement && !matched; ++j) {
        matched = pinned(simple->rgpElement[j]->pCertContext);
      }
    }
    CertFreeCertificateChain(chain);
    return matched;
  }

  // No chain to read (Windows before 8). The server's own certificate is all
  // there is, and a root pin cannot match it: this fails closed, as it should.
  PCCERT_CONTEXT certificate = nullptr;
  DWORD size = sizeof(certificate);
  if (!WinHttpQueryOption(http_request, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &certificate, &size)
      || certificate == nullptr) {
    // Could not read it, so cannot vouch for it. Fails closed.
    return false;
  }
  const bool matched = pinned(certificate);
  CertFreeCertificateContext(certificate);
  return matched;
}

std::vector<std::string> PemBundleSpkiPins(const std::string& pem) {
  static const std::string kBegin = "-----BEGIN CERTIFICATE-----";
  static const std::string kEnd = "-----END CERTIFICATE-----";
  std::vector<std::string> pins;
  std::size_t at = 0;
  while ((at = pem.find(kBegin, at)) != std::string::npos) {
    const std::size_t end = pem.find(kEnd, at);
    if (end == std::string::npos) return {};
    const std::string block = pem.substr(at, end + kEnd.size() - at);
    at = end + kEnd.size();

    DWORD size = 0;
    if (!CryptStringToBinaryA(block.c_str(), static_cast<DWORD>(block.size()),
                              CRYPT_STRING_BASE64HEADER, nullptr, &size, nullptr, nullptr)) {
      return {};
    }
    std::vector<BYTE> der(size);
    if (!CryptStringToBinaryA(block.c_str(), static_cast<DWORD>(block.size()),
                              CRYPT_STRING_BASE64HEADER, der.data(), &size, nullptr, nullptr)) {
      return {};
    }
    PCCERT_CONTEXT certificate = CertCreateCertificateContext(X509_ASN_ENCODING, der.data(), size);
    if (certificate == nullptr) return {};
    pins.push_back(SpkiFingerprint(certificate));
    CertFreeCertificateContext(certificate);
    if (pins.back().empty()) return {};
  }
  return pins;
}

bool HttpSend(const HttpRequest& request, HttpResponse& response, std::string& error) {
  URL_COMPONENTS components;
  ZeroMemory(&components, sizeof(components));
  components.dwStructSize = sizeof(components);
  components.dwSchemeLength = static_cast<DWORD>(-1);
  components.dwHostNameLength = static_cast<DWORD>(-1);
  components.dwUrlPathLength = static_cast<DWORD>(-1);
  components.dwExtraInfoLength = static_cast<DWORD>(-1);

  std::wstring url = Widen(request.url);
  if (!WinHttpCrackUrl(url.c_str(), static_cast<DWORD>(url.size()), 0, &components)) {
    error = "The API URL could not be parsed.";
    return false;
  }

  bool secure = components.nScheme == INTERNET_SCHEME_HTTPS;
  if (!secure && !request.allow_insecure) {
    // Belt and braces: Options::Validate already refuses this. Repeating it at
    // the socket means a future caller that skips validation still cannot send
    // a session token in the clear.
    error = "Refusing to send credentials over plain HTTP.";
    return false;
  }

  std::wstring host(components.lpszHostName, components.dwHostNameLength);
  std::wstring path(components.lpszUrlPath, components.dwUrlPathLength);
  if (components.dwExtraInfoLength > 0) {
    path.append(components.lpszExtraInfo, components.dwExtraInfoLength);
  }

  Handle session;
  const std::wstring user_agent = Widen(std::string("grantry-cpp/") + Version());
  session.value = WinHttpOpen(user_agent.c_str(),
                              WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (session.value == nullptr) {
    error = "WinHttpOpen failed.";
    return false;
  }

  /*
   * ⚠️ TLS 1.2 AND ABOVE ONLY.
   *
   * WinHTTP's default depends on the Windows version and its registry state, so
   * an old or badly managed machine can negotiate TLS 1.0 without anybody
   * noticing. Setting the floor explicitly means the SDK's transport security
   * does not vary by deployment.
   */
  DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
#ifdef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
  protocols |= WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
#endif
  WinHttpSetOption(session.value, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols,
                   sizeof(protocols));

  DWORD timeout = static_cast<DWORD>(request.timeout_seconds) * 1000;
  WinHttpSetTimeouts(session.value, static_cast<int>(timeout), static_cast<int>(timeout),
                     static_cast<int>(timeout), static_cast<int>(timeout));

  Handle connection;
  connection.value = WinHttpConnect(session.value, host.c_str(), components.nPort, 0);
  if (connection.value == nullptr) {
    error = "Could not connect to " + Narrow(host) + ".";
    return false;
  }

  Handle http_request;
  http_request.value = WinHttpOpenRequest(
      connection.value, Widen(request.method).c_str(), path.c_str(), nullptr,
      WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
      secure ? WINHTTP_FLAG_SECURE : 0);
  if (http_request.value == nullptr) {
    error = "WinHttpOpenRequest failed.";
    return false;
  }

  /*
   * ⚠️ A 3XX COMES BACK AS ITSELF, AS IT ALWAYS HAS ON POSIX (CURLOPT_FOLLOWLOCATION 0). WinHTTP
   * follows redirects by default and sends the request again to wherever one points, so the same
   * call meant different things on the two platforms — and the loopback's own answer, a 303 to
   * the sign-in host, could not be seen on Windows at all.
   */
  DWORD never_follow = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
  WinHttpSetOption(http_request.value, WINHTTP_OPTION_REDIRECT_POLICY, &never_follow,
                   sizeof(never_follow));

  std::wstring headers;
  for (const auto& entry : request.headers) {
    headers += Widen(entry.first) + L": " + Widen(entry.second) + L"\r\n";
  }

  const void* body = request.body.empty() ? WINHTTP_NO_REQUEST_DATA : request.body.data();
  DWORD body_length = static_cast<DWORD>(request.body.size());

  if (!WinHttpSendRequest(http_request.value,
                          headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str(),
                          headers.empty() ? 0 : static_cast<DWORD>(-1),
                          const_cast<void*>(body), body_length, body_length, 0)) {
    DWORD code = GetLastError();
    // ⚠️ A CERTIFICATE FAILURE IS REPORTED, NEVER RETRIED WITHOUT VALIDATION.
    // There is no option in this library to ignore one, because the only
    // reason to want that is the reason not to allow it.
    error = code == ERROR_WINHTTP_SECURE_FAILURE
                ? "The server's TLS certificate was not accepted."
                : "The request could not be sent.";
    return false;
  }

  /*
   * ⚠️ BEFORE THE RESPONSE IS READ, NOT AFTER.
   *
   * A body from a server we are about to reject is a body we should never have
   * parsed. Refusing here means nothing from an unpinned peer reaches the JSON
   * parser, the token verifier or the caller.
   */
  if (secure && !request.certificate_pins.empty()
      && !CertificateIsPinned(http_request.value, request.certificate_pins)) {
    response.pin_refused = true;
    error =
        "The server did not present Grantry's public key. Something is intercepting this "
        "connection.";
    return false;
  }

  if (!WinHttpReceiveResponse(http_request.value, nullptr)) {
    error = "No response from the server.";
    return false;
  }

  DWORD status = 0;
  DWORD status_size = sizeof(status);
  WinHttpQueryHeaders(http_request.value,
                      WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                      WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size,
                      WINHTTP_NO_HEADER_INDEX);
  response.status = static_cast<int>(status);

  DWORD headers_size = 0;
  WinHttpQueryHeaders(http_request.value, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                      WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &headers_size,
                      WINHTTP_NO_HEADER_INDEX);
  if (headers_size > 0) {
    std::wstring raw(headers_size / sizeof(wchar_t), L'\0');
    if (WinHttpQueryHeaders(http_request.value, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                            WINHTTP_HEADER_NAME_BY_INDEX, &raw[0], &headers_size,
                            WINHTTP_NO_HEADER_INDEX)) {
      ParseHeaders(raw, response.headers);
    }
  }

  /*
   * ⚠️ A READ THAT FAILS PART-WAY IS A FAILED REQUEST, NOT A SHORT BODY. Both
   * reads used to `break` and return success, so a connection dropped mid-answer
   * handed back whatever had arrived: a JSON reply cut short read as "not JSON",
   * a kApi blamed on the server, and a download cut short reached the caller as
   * a checksum mismatch, reported as an attack. libcurl already fails the
   * transfer in the same case, so the two platforms now agree.
   */
  response.body.clear();
  while (true) {
    DWORD available = 0;
    if (!WinHttpQueryDataAvailable(http_request.value, &available)) {
      error = "The connection failed while the response was being read.";
      return false;
    }
    if (available == 0) break;

    /*
     * A ceiling on the response body, the request's own.
     *
     * Nothing this library reads as JSON is large — a JWKS is a few hundred bytes and a
     * token response a couple of kilobytes. Without a cap, a hostile or broken
     * server can make a desktop client allocate until it dies, which is a
     * denial of service that needs no authentication at all.
     *
     * ⚠️ PER REQUEST SINCE 9 OCTOBER 2026. It was a fixed megabyte, so `Download`
     * failed for every file larger than that; a download now asks for more.
     */
    if (response.body.size() + available > request.max_body_bytes) {
      error = "The response was larger than this SDK will read.";
      return false;
    }

    std::string chunk(available, '\0');
    DWORD read = 0;
    if (!WinHttpReadData(http_request.value, &chunk[0], available, &read)) {
      error = "The connection failed while the response was being read.";
      return false;
    }
    chunk.resize(read);
    response.body += chunk;
  }

  /*
   * ⚠️ AND A CONNECTION CLOSED EARLY READS AS THE END OF THE BODY. WinHTTP
   * answers "nothing more available" rather than failing when the server hangs
   * up inside a Content-Length body, so the declared length is the only witness
   * that bytes are missing. (Decompression is off, so it counts these bytes.)
   */
  auto declared = response.headers.find("content-length");
  if (declared != response.headers.end() && request.method != "HEAD" && !declared->second.empty()) {
    std::uint64_t expected = 0;
    bool numeric = declared->second.size() <= 18;
    for (char c : declared->second) {
      if (c < '0' || c > '9') numeric = false;
      if (numeric) expected = expected * 10 + static_cast<std::uint64_t>(c - '0');
    }
    if (numeric && expected != response.body.size()) {
      error = "The connection closed before the whole response arrived.";
      return false;
    }
  }

  return true;
}

bool RandomBytes(std::uint8_t* out, std::size_t length) {
  NTSTATUS status = BCryptGenRandom(nullptr, out, static_cast<ULONG>(length),
                                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  return status == STATUS_SUCCESS;
}

std::vector<std::uint8_t> Sha256(const std::string& text) {
  std::vector<std::uint8_t> digest(32, 0);

  BCRYPT_ALG_HANDLE algorithm = nullptr;
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0)
      != STATUS_SUCCESS) {
    return digest;
  }

  BCryptHash(algorithm, nullptr, 0,
             reinterpret_cast<PUCHAR>(const_cast<char*>(text.data())),
             static_cast<ULONG>(text.size()), digest.data(),
             static_cast<ULONG>(digest.size()));

  BCryptCloseAlgorithmProvider(algorithm, 0);
  return digest;
}

std::vector<std::uint8_t> Sha256(const std::vector<std::uint8_t>& bytes) {
  std::vector<std::uint8_t> digest(32, 0);

  BCRYPT_ALG_HANDLE algorithm = nullptr;
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0)
      != STATUS_SUCCESS) {
    return digest;
  }

  BCryptHash(algorithm, nullptr, 0, const_cast<PUCHAR>(bytes.data()),
             static_cast<ULONG>(bytes.size()), digest.data(),
             static_cast<ULONG>(digest.size()));

  BCryptCloseAlgorithmProvider(algorithm, 0);
  return digest;
}

bool HmacSha256(const std::vector<std::uint8_t>& key,
                const std::vector<std::uint8_t>& message,
                std::vector<std::uint8_t>& out) {
  out.assign(32, 0);

  BCRYPT_ALG_HANDLE algorithm = nullptr;
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr,
                                  BCRYPT_ALG_HANDLE_HMAC_FLAG)
      != STATUS_SUCCESS) {
    return false;
  }

  // A zero-length key is legal and meaningful — HKDF's empty salt lands here —
  // so it must produce a real HMAC rather than a refusal.
  PUCHAR key_data = key.empty() ? reinterpret_cast<PUCHAR>(const_cast<char*>(""))
                                : const_cast<PUCHAR>(key.data());

  const NTSTATUS status =
      BCryptHash(algorithm, key_data, static_cast<ULONG>(key.size()),
                 const_cast<PUCHAR>(message.data()), static_cast<ULONG>(message.size()),
                 out.data(), static_cast<ULONG>(out.size()));

  BCryptCloseAlgorithmProvider(algorithm, 0);
  return status == STATUS_SUCCESS;
}

bool AesGcmDecrypt(const std::vector<std::uint8_t>& key,
                   const std::vector<std::uint8_t>& iv,
                   const std::vector<std::uint8_t>& ciphertext,
                   const std::vector<std::uint8_t>& tag,
                   std::vector<std::uint8_t>& out) {
  if (key.size() != 32 || iv.size() != 12 || tag.size() != 16) return false;

  BCRYPT_ALG_HANDLE algorithm = nullptr;
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM, nullptr, 0)
      != STATUS_SUCCESS) {
    return false;
  }

  bool ok = false;
  BCRYPT_KEY_HANDLE key_handle = nullptr;
  std::vector<std::uint8_t> plaintext(ciphertext.size());

  do {
    if (BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE,
                          reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0)
        != STATUS_SUCCESS) {
      break;
    }

    if (BCryptGenerateSymmetricKey(algorithm, &key_handle, nullptr, 0,
                                   const_cast<PUCHAR>(key.data()),
                                   static_cast<ULONG>(key.size()), 0)
        != STATUS_SUCCESS) {
      break;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<PUCHAR>(iv.data());
    info.cbNonce = static_cast<ULONG>(iv.size());
    info.pbTag = const_cast<PUCHAR>(tag.data());
    info.cbTag = static_cast<ULONG>(tag.size());

    ULONG produced = 0;

    /*
     * ⚠️ BCryptDecrypt VERIFIES THE TAG AND RETURNS STATUS_AUTH_TAG_MISMATCH
     * WITHOUT PRODUCING PLAINTEXT. There is no mode here that hands back
     * unauthenticated bytes, and adding one would mean handing an application a
     * value an attacker chose.
     */
    const NTSTATUS status = BCryptDecrypt(
        key_handle, ciphertext.empty() ? nullptr : const_cast<PUCHAR>(ciphertext.data()),
        static_cast<ULONG>(ciphertext.size()), &info, nullptr, 0,
        plaintext.empty() ? nullptr : plaintext.data(),
        static_cast<ULONG>(plaintext.size()), &produced, 0);

    if (status != STATUS_SUCCESS) break;

    plaintext.resize(produced);
    ok = true;
  } while (false);

  if (key_handle != nullptr) BCryptDestroyKey(key_handle);
  BCryptCloseAlgorithmProvider(algorithm, 0);

  if (!ok) return false;
  out = std::move(plaintext);
  return true;
}

bool RsaSha256Verify(const std::vector<std::uint8_t>& modulus,
                     const std::vector<std::uint8_t>& exponent,
                     const std::vector<std::uint8_t>& message,
                     const std::vector<std::uint8_t>& signature) {
  if (modulus.empty() || exponent.empty() || signature.empty()) return false;

  BCRYPT_ALG_HANDLE algorithm = nullptr;
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_RSA_ALGORITHM, nullptr, 0)
      != STATUS_SUCCESS) {
    return false;
  }

  // BCRYPT_RSAKEY_BLOB, then the exponent, then the modulus — big-endian, which
  // is exactly how both arrive in a JWK.
  std::vector<std::uint8_t> blob(sizeof(BCRYPT_RSAKEY_BLOB) + exponent.size() + modulus.size());
  auto* header = reinterpret_cast<BCRYPT_RSAKEY_BLOB*>(blob.data());
  header->Magic = BCRYPT_RSAPUBLIC_MAGIC;
  header->BitLength = static_cast<ULONG>(modulus.size() * 8);
  header->cbPublicExp = static_cast<ULONG>(exponent.size());
  header->cbModulus = static_cast<ULONG>(modulus.size());
  header->cbPrime1 = 0;
  header->cbPrime2 = 0;

  std::uint8_t* cursor = blob.data() + sizeof(BCRYPT_RSAKEY_BLOB);
  std::memcpy(cursor, exponent.data(), exponent.size());
  std::memcpy(cursor + exponent.size(), modulus.data(), modulus.size());

  BCRYPT_KEY_HANDLE key = nullptr;
  NTSTATUS status = BCryptImportKeyPair(algorithm, nullptr, BCRYPT_RSAPUBLIC_BLOB, &key,
                                        blob.data(), static_cast<ULONG>(blob.size()), 0);
  if (status != STATUS_SUCCESS) {
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return false;
  }

  std::vector<std::uint8_t> digest(32, 0);
  {
    BCRYPT_ALG_HANDLE sha = nullptr;
    if (BCryptOpenAlgorithmProvider(&sha, BCRYPT_SHA256_ALGORITHM, nullptr, 0)
        == STATUS_SUCCESS) {
      BCryptHash(sha, nullptr, 0, const_cast<PUCHAR>(message.data()),
                 static_cast<ULONG>(message.size()), digest.data(),
                 static_cast<ULONG>(digest.size()));
      BCryptCloseAlgorithmProvider(sha, 0);
    }
  }

  BCRYPT_PKCS1_PADDING_INFO padding;
  padding.pszAlgId = BCRYPT_SHA256_ALGORITHM;

  status = BCryptVerifySignature(key, &padding, digest.data(),
                                 static_cast<ULONG>(digest.size()),
                                 const_cast<PUCHAR>(signature.data()),
                                 static_cast<ULONG>(signature.size()),
                                 BCRYPT_PAD_PKCS1);

  BCryptDestroyKey(key);
  BCryptCloseAlgorithmProvider(algorithm, 0);

  // ⚠️ ONLY STATUS_SUCCESS IS TRUE. Every other NTSTATUS — including the ones
  // that mean "the key was malformed" rather than "the signature was wrong" —
  // is a failure to verify, and must never be treated as verified.
  return status == STATUS_SUCCESS;
}

namespace {
// Bound to this SDK. Changing it invalidates every stored session, which is why
// it is a constant rather than something derived from a version.
const char kEntropy[] = "grantry.sdk.session.v1";
}  // namespace

bool ProtectLocal(const std::vector<std::uint8_t>& plaintext,
                  std::vector<std::uint8_t>& out) {
  DATA_BLOB in;
  in.pbData = const_cast<BYTE*>(plaintext.data());
  in.cbData = static_cast<DWORD>(plaintext.size());

  DATA_BLOB entropy;
  entropy.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(kEntropy));
  entropy.cbData = static_cast<DWORD>(sizeof(kEntropy) - 1);

  DATA_BLOB result;
  ZeroMemory(&result, sizeof(result));

  if (!CryptProtectData(&in, L"grantry session", &entropy, nullptr, nullptr,
                        CRYPTPROTECT_UI_FORBIDDEN, &result)) {
    return false;
  }

  out.assign(result.pbData, result.pbData + result.cbData);
  LocalFree(result.pbData);
  return true;
}

bool UnprotectLocal(const std::vector<std::uint8_t>& ciphertext,
                    std::vector<std::uint8_t>& out) {
  DATA_BLOB in;
  in.pbData = const_cast<BYTE*>(ciphertext.data());
  in.cbData = static_cast<DWORD>(ciphertext.size());

  DATA_BLOB entropy;
  entropy.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(kEntropy));
  entropy.cbData = static_cast<DWORD>(sizeof(kEntropy) - 1);

  DATA_BLOB result;
  ZeroMemory(&result, sizeof(result));

  if (!CryptUnprotectData(&in, nullptr, &entropy, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN, &result)) {
    return false;
  }

  out.assign(result.pbData, result.pbData + result.cbData);
  LocalFree(result.pbData);
  return true;
}

std::string UserDataDirectory() {
  PWSTR path = nullptr;
  if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &path))) {
    std::string result = Narrow(path);
    CoTaskMemFree(path);
    return result;
  }

  const char* fallback = std::getenv("LOCALAPPDATA");
  return fallback != nullptr ? std::string(fallback) : std::string(".");
}

bool MakeDirectories(const std::string& path) {
  std::wstring wide = Widen(path);
  for (std::size_t i = 0; i < wide.size(); i++) {
    if (wide[i] == L'\\' || wide[i] == L'/') {
      std::wstring parent = wide.substr(0, i);
      if (!parent.empty() && parent.back() != L':') {
        CreateDirectoryW(parent.c_str(), nullptr);
      }
    }
  }
  CreateDirectoryW(wide.c_str(), nullptr);

  DWORD attributes = GetFileAttributesW(wide.c_str());
  return attributes != INVALID_FILE_ATTRIBUTES
      && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

// ---------------------------------------------------------------------------
// Machine anchor
// ---------------------------------------------------------------------------

const char* PlatformName() { return "windows"; }

/// The machine SID, as the Local Security Authority states it.
///
/// ⚠️ THE MACHINE SID, NOT THE USER'S. Every local account's SID is
/// `<machine SID>-<RID>`, so anchoring to the user's would make a household PC
/// shared by two people two devices — support tickets indistinguishable from
/// piracy.
///
/// `LsaQueryInformationPolicy(PolicyAccountDomainInformation)` is the machine's
/// own account domain whoever is signed in — what `PsGetSid` prints — and needs
/// no elevation: `POLICY_VIEW_LOCAL_INFORMATION` is granted to everybody.
///
/// ⚠️ IT WAS THE CURRENT USER'S ACCOUNT DOMAIN, AND FOR A DOMAIN USER THAT IS
/// THE DOMAIN'S SID, shared by every workstation in the company: one licence
/// covered the building. The check meant to catch it asked `CreateWellKnownSid`
/// for the local Administrator under that authority and expected a failure for
/// a domain — it succeeds for any account domain, so it passed everything.
/// Found by the native-settings audit, 25 September 2026, alongside the same
/// check in the C# SDK. An Entra ID user (`S-1-12-1-…`) had no anchor at all.
/// For a local account the value is unchanged.
std::string ReadMachineAnchor() {
  LSA_OBJECT_ATTRIBUTES attributes;
  ZeroMemory(&attributes, sizeof(attributes));
  attributes.Length = sizeof(attributes);

  LSA_HANDLE policy = nullptr;
  if (LsaOpenPolicy(nullptr, &attributes, POLICY_VIEW_LOCAL_INFORMATION, &policy) != STATUS_SUCCESS) {
    return std::string();
  }

  void* buffer = nullptr;
  NTSTATUS status = LsaQueryInformationPolicy(policy, PolicyAccountDomainInformation, &buffer);
  LsaClose(policy);
  if (status != STATUS_SUCCESS || buffer == nullptr) return std::string();

  const auto* info = static_cast<const POLICY_ACCOUNT_DOMAIN_INFO*>(buffer);
  std::string result;
  LPWSTR text = nullptr;
  if (info->DomainSid != nullptr && ConvertSidToStringSidW(info->DomainSid, &text)) {
    result = Narrow(text);
    LocalFree(text);
  }
  LsaFreeMemory(buffer);
  return result;
}

namespace {
/// A session store holds a token or two. Anything this large is not one.
constexpr LONGLONG kMaxStoredFileBytes = 1024 * 1024;
}  // namespace

std::optional<std::vector<std::uint8_t>> ReadFileBytes(const std::string& path) {
  HANDLE file = CreateFileW(Widen(path).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) return std::nullopt;

  std::optional<std::vector<std::uint8_t>> result;
  LARGE_INTEGER size;
  if (GetFileSizeEx(file, &size) && size.QuadPart >= 0 && size.QuadPart <= kMaxStoredFileBytes) {
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size.QuadPart));
    DWORD read = 0;
    if (bytes.empty() || (ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &read,
                                   nullptr) &&
                          read == bytes.size())) {
      result = std::move(bytes);
    }
  }
  CloseHandle(file);
  return result;
}

bool ReplaceFilePrivately(const std::string& path, const std::vector<std::uint8_t>& bytes) {
  /*
   * Nothing to narrow on the file itself. The stored blob is DPAPI ciphertext
   * bound to this user, so another local account reading it learns nothing, and
   * the profile directory it lives in is already ACL'd to the owner.
   */
  const std::wstring target = Widen(path);
  const std::wstring temporary = Widen(path + ".tmp");

  HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) return false;

  bool written = true;
  std::size_t offset = 0;
  while (written && offset < bytes.size()) {
    DWORD wrote = 0;
    const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(bytes.size() - offset, 1 << 20));
    written = WriteFile(file, bytes.data() + offset, chunk, &wrote, nullptr) && wrote > 0;
    offset += wrote;
  }
  // A token half on disk is worse than the previous one, so a failed flush keeps the old file.
  written = written && FlushFileBuffers(file);
  CloseHandle(file);

  if (!written ||
      !MoveFileExW(temporary.c_str(), target.c_str(),
                   MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    DeleteFileW(temporary.c_str());
    return false;
  }
  return true;
}

void RemoveFile(const std::string& path) { DeleteFileW(Widen(path).c_str()); }

bool ReadApplicationSlice(std::int64_t offset, std::size_t length, std::vector<std::uint8_t>& out) {
  if (offset < 0 || length == 0 || length > 65536) return false;
  wchar_t path[MAX_PATH];
  DWORD size = GetModuleFileNameW(nullptr, path, MAX_PATH);
  if (size == 0 || size == MAX_PATH) return false;

  HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) return false;

  bool whole = false;
  LARGE_INTEGER at;
  at.QuadPart = offset;
  if (SetFilePointerEx(file, at, nullptr, FILE_BEGIN)) {
    out.assign(length, 0);
    std::size_t got = 0;
    DWORD read = 0;
    while (got < length
           && ReadFile(file, out.data() + got, static_cast<DWORD>(length - got), &read, nullptr)
           && read > 0) {
      got += read;
    }
    whole = got == length;
  }
  CloseHandle(file);
  return whole;
}

std::string ApplicationHash() {
  wchar_t path[MAX_PATH];
  DWORD length = GetModuleFileNameW(nullptr, path, MAX_PATH);
  if (length == 0 || length == MAX_PATH) return std::string();

  HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) return std::string();

  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  std::string result;

  do {
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) break;
    if (BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) != 0) break;

    std::vector<std::uint8_t> buffer(64 * 1024);
    DWORD read = 0;
    bool failed = false;
    while (ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr)
           && read > 0) {
      if (BCryptHashData(hash, buffer.data(), read, 0) != 0) {
        failed = true;
        break;
      }
    }
    if (failed) break;

    std::vector<std::uint8_t> digest(32);
    if (BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) != 0) break;

    // Lowercase hex: the server stores and compares in exactly that shape.
    static const char* kHex = "0123456789abcdef";
    result.reserve(64);
    for (std::uint8_t b : digest) {
      result.push_back(kHex[b >> 4]);
      result.push_back(kHex[b & 0x0F]);
    }
  } while (false);

  if (hash != nullptr) BCryptDestroyHash(hash);
  if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0);
  CloseHandle(file);
  return result;
}

bool OpenSystemBrowser(const std::string& url) {
  /*
   * The shell's handler for the scheme, which for http(s) is the person's own default
   * browser. SignInUrlOpenable has already refused anything else, which is what makes
   * handing a server's address to ShellExecute safe.
   *
   * COM first, as ShellExecute's documentation asks: the handler may be a shell
   * extension that needs it. A thread that already chose another apartment keeps it.
   */
  const HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
  HINSTANCE opened = ShellExecuteW(nullptr, L"open", Widen(url).c_str(), nullptr, nullptr,
                                   SW_SHOWNORMAL);
  if (SUCCEEDED(com)) CoUninitialize();

  // Anything above 32 is success; the rest are error codes dressed as a handle.
  return reinterpret_cast<INT_PTR>(opened) > 32;
}

}  // namespace internal
}  // namespace grantry

#endif  // _WIN32
