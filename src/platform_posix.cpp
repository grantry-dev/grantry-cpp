// POSIX platform layer: libcurl and OpenSSL.
//
// Both are the system libraries on macOS and Linux, which is the same argument
// the Windows layer makes for WinHTTP and BCrypt: use what the platform already
// ships and updates, rather than vendoring a second copy of it.
//
// ⚠️ THERE IS NO DPAPI EQUIVALENT HERE, AND THIS FILE DOES NOT PRETEND
// OTHERWISE. `ProtectLocal` returns false, the session is stored as plaintext
// in a `0600` file, and the public header says so in as many words. The honest
// answers are the login keychain on macOS and the Secret Service on Linux; both
// need a dependency this library deliberately does not take, so a product that
// needs them implements `SessionStore` itself.
#ifndef _WIN32

#include "internal.hpp"

#include <curl/curl.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <cstring>
#include <mutex>
#include <vector>
#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif
#include <unistd.h>
#include <fcntl.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

// The process environment, for posix_spawnp. Declared by no standard header.
extern char** environ;

namespace grantry {
namespace internal {
namespace {

/// Where a response body goes, and the most of it this request will read.
struct BodySink {
  std::string* out;
  std::size_t limit;
};

std::size_t WriteBody(char* data, std::size_t size, std::size_t count, void* user) {
  auto* sink = static_cast<BodySink*>(user);
  std::size_t bytes = size * count;

  // The same ceiling the Windows layer applies, for the same reason: a hostile
  // or broken server must not be able to make a desktop client allocate until
  // it dies. The request's own, so a download may be larger than a JSON answer.
  if (sink->out->size() + bytes > sink->limit) return 0;

  sink->out->append(data, bytes);
  return bytes;
}

std::size_t WriteHeader(char* data, std::size_t size, std::size_t count, void* user) {
  auto* out = static_cast<std::map<std::string, std::string>*>(user);
  std::string line(data, size * count);

  std::size_t colon = line.find(':');
  if (colon == std::string::npos) return size * count;

  std::string name = line.substr(0, colon);
  for (char& c : name) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }

  std::string value = line.substr(colon + 1);
  while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.erase(0, 1);
  while (!value.empty() && (value.back() == '\r' || value.back() == '\n')) value.pop_back();

  (*out)[name] = value;
  return size * count;
}

/// Whether the chain the server presented (CURLOPT_CERTINFO) verifies against
/// `anchors_pem` and nothing else, with this library's own OpenSSL.
///
/// ⚠️ ONLY PEM TEXT CROSSES FROM libcurl. Its TLS backend may be another
/// OpenSSL, LibreSSL or Apple's, and handing its objects to this OpenSSL would
/// be an ABI mismatch; the certificates are re-read here from their PEM. A
/// backend that records no chain fails this, closed.
bool PresentedChainReachesAnchors(CURL* curl, const char* anchors_pem) {
  struct curl_certinfo* info = nullptr;
  if (curl_easy_getinfo(curl, CURLINFO_CERTINFO, &info) != CURLE_OK || info == nullptr
      || info->num_of_certs <= 0) {
    return false;
  }

  std::vector<X509*> presented;
  for (int i = 0; i < info->num_of_certs; ++i) {
    for (struct curl_slist* field = info->certinfo[i]; field != nullptr; field = field->next) {
      if (std::strncmp(field->data, "Cert:", 5) != 0) continue;
      BIO* bio = BIO_new_mem_buf(field->data + 5, -1);
      X509* certificate = bio != nullptr ? PEM_read_bio_X509(bio, nullptr, nullptr, nullptr) : nullptr;
      if (bio != nullptr) BIO_free(bio);
      if (certificate != nullptr) presented.push_back(certificate);
      break;
    }
  }

  bool verified = false;
  X509_STORE* store = X509_STORE_new();
  STACK_OF(X509)* untrusted = sk_X509_new_null();
  X509_STORE_CTX* context = X509_STORE_CTX_new();
  if (!presented.empty() && store != nullptr && untrusted != nullptr && context != nullptr) {
    int roots = 0;
    BIO* bio = BIO_new_mem_buf(anchors_pem, -1);
    while (X509* root = bio != nullptr ? PEM_read_bio_X509(bio, nullptr, nullptr, nullptr) : nullptr) {
      if (X509_STORE_add_cert(store, root) == 1) ++roots;
      X509_free(root);
    }
    if (bio != nullptr) BIO_free(bio);
    for (std::size_t i = 1; i < presented.size(); ++i) sk_X509_push(untrusted, presented[i]);
    if (roots > 0 && X509_STORE_CTX_init(context, store, presented[0], untrusted) == 1) {
      verified = X509_verify_cert(context) == 1;
    }
  }
  if (context != nullptr) X509_STORE_CTX_free(context);
  if (untrusted != nullptr) sk_X509_free(untrusted);  // the certificates are freed below
  if (store != nullptr) X509_STORE_free(store);
  for (X509* certificate : presented) X509_free(certificate);
  ERR_clear_error();
  return verified;
}

}  // namespace

bool HttpSend(const HttpRequest& request, HttpResponse& response, std::string& error) {
  const bool secure = request.url.rfind("https://", 0) == 0;
  if (!secure && !request.allow_insecure) {
    error = "Refusing to send credentials over plain HTTP.";
    return false;
  }

  /*
   * ⚠️ ONCE, BEFORE ANY HANDLE, AND NOT LEFT TO curl_easy_init. That calls
   * curl_global_init itself when nobody has, and curl_global_init is not
   * thread-safe — while this library makes its first request from two threads
   * at once by design: the start-up probe, beside whatever the application
   * calls first. A call_once makes the first initialisation the only one.
   */
  static std::once_flag initialised;
  static CURLcode initialisation = CURLE_OK;
  std::call_once(initialised, [] { initialisation = curl_global_init(CURL_GLOBAL_DEFAULT); });
  if (initialisation != CURLE_OK) {
    error = "libcurl could not be initialised.";
    return false;
  }

  CURL* curl = curl_easy_init();
  if (curl == nullptr) {
    error = "curl_easy_init failed.";
    return false;
  }

  const std::string user_agent = std::string("grantry-cpp/") + Version();
  curl_easy_setopt(curl, CURLOPT_URL, request.url.c_str());
  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, request.method.c_str());
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, static_cast<long>(request.timeout_seconds));
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agent.c_str());

  /*
   * ⚠️ NO SIGNALS. Without this, a libcurl built on the synchronous resolver
   * times DNS out with SIGALRM and longjmp, which is undefined behaviour in a
   * process with more than one thread — and every process using this SDK has
   * one more than it started with. libcurl's own documentation asks for it in
   * any multi-threaded program.
   */
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

  // The two schemes this library speaks, so nothing in a URL can make libcurl
  // reach for another of the twenty-odd it was built with.
  // CURLOPT_PROTOCOLS_STR from 7.85, where the bitmask form was deprecated.
#if LIBCURL_VERSION_NUM >= 0x075500
  curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, secure ? "https" : "http,https");
#else
  curl_easy_setopt(curl, CURLOPT_PROTOCOLS,
                   secure ? static_cast<long>(CURLPROTO_HTTPS)
                          : static_cast<long>(CURLPROTO_HTTP | CURLPROTO_HTTPS));
#endif

  /*
   * ⚠️ VERIFICATION IS SET EXPLICITLY RATHER THAN LEFT TO THE DEFAULT.
   *
   * The defaults are right today, but "we rely on libcurl's default" is a
   * security property held by a library we do not version. Stating it means a
   * distribution that ships a patched curl cannot silently downgrade this.
   * There is deliberately no option to turn either off.
   */
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
  curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);

  /*
   * ⚠️ THE PIN, AND THE REASON IT IS libcurl'S RATHER THAN OURS.
   *
   * CURLOPT_PINNEDPUBLICKEY is checked DURING the handshake: a server whose key
   * does not match is refused before a single request byte leaves this process,
   * so an interception proxy never sees the session token, never sees the
   * request, and has nothing to replay. A check we wrote ourselves after the
   * exchange could only refuse the answer, by which point the credential has
   * already been handed over.
   *
   * The format is `sha256//BASE64`, semicolon-separated — which is exactly the
   * SPKI digest we publish, so nothing is transformed on the way in.
   *
   * ⚠️ BUT ONLY THE SERVER'S OWN KEY, so the built-in pins go another way (17
   * October 2026). They are Let's Encrypt's roots (crypto.cpp), which no server
   * presents as its own certificate. libcurl cannot pin a root, but it can be
   * told which roots exist: the handshake trusts those four and nothing else,
   * so a proxy's certificate fails verification before a byte is sent, just as
   * a pin failure would. A merchant's own pins name their server's key and keep
   * the pin.
   */
  const char* const anchors = TrustAnchorsFor(request.certificate_pins);
  if (anchors != nullptr) {
#if LIBCURL_VERSION_NUM >= 0x074d00
    curl_blob blob;
    blob.data = const_cast<char*>(anchors);
    blob.len = std::strlen(anchors);
    blob.flags = CURL_BLOB_COPY;
    const CURLcode set = curl_easy_setopt(curl, CURLOPT_CAINFO_BLOB, &blob);
    // The machine's CA directory as well would put every root it holds back in.
    // A TLS backend with no directory support has none to put back, so that
    // refusal is the one this tolerates.
    const CURLcode cleared = curl_easy_setopt(curl, CURLOPT_CAPATH, nullptr);
    // The presented chain, for PresentedChainReachesAnchors once the exchange is done.
    const CURLcode recorded = curl_easy_setopt(curl, CURLOPT_CERTINFO, 1L);
    if (set != CURLE_OK || recorded != CURLE_OK
        || (cleared != CURLE_OK && cleared != CURLE_NOT_BUILT_IN)) {
      error = "This libcurl cannot limit the roots it trusts, so Grantry's certificate cannot be "
              "pinned. Build against libcurl 7.77 or later with OpenSSL, or set pin_certificate "
              "to false to accept the risk deliberately.";
      curl_easy_cleanup(curl);
      return false;
    }
#else
    // ⚠️ REFUSED, NOT SENT UNPINNED: the defence must not vanish on an old libcurl.
    error = "This libcurl predates 7.77 and cannot limit the roots it trusts, so Grantry's "
            "certificate cannot be pinned. Build against a newer libcurl, or set "
            "pin_certificate to false to accept the risk deliberately.";
    curl_easy_cleanup(curl);
    return false;
#endif
  } else {
    std::string pinned;
    for (const std::string& pin : request.certificate_pins) {
      if (pin.empty()) continue;
      if (!pinned.empty()) pinned += ";";
      pinned += "sha256//" + pin;
    }
    if (!pinned.empty()) {
      curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, pinned.c_str());
    }
  }

  struct curl_slist* headers = nullptr;
  for (const auto& entry : request.headers) {
    headers = curl_slist_append(headers, (entry.first + ": " + entry.second).c_str());
  }
  if (headers != nullptr) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  if (!request.body.empty()) {
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(request.body.size()));
  }

  BodySink sink{&response.body, request.max_body_bytes};
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteBody);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &sink);
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteHeader);
  curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response.headers);

  CURLcode code = curl_easy_perform(curl);

  /*
   * ⚠️ AND THE CHAIN IS CHECKED AGAIN AFTERWARDS, BECAUSE APPLE'S libcurl DOES
   * NOT KEEP TO THE ROOTS IT IS GIVEN (17 October 2026). Measured on the
   * macos-latest runner: with the four roots as its trust store, the system
   * libcurl still accepted Google's certificate, so it falls back to the
   * keychain — where an interception proxy installs its root. Linux keeps to
   * them. So the chain the server presented is verified here against the four
   * roots alone, with this library's own OpenSSL, and a failure is the pin
   * failing. On macOS this lands after the exchange, as on Windows, which is
   * what the client's credential-free probe is for; on Linux the handshake has
   * refused already and this agrees.
   */
  if (code == CURLE_OK && anchors != nullptr && !PresentedChainReachesAnchors(curl, anchors)) {
    response = HttpResponse();
    response.pin_refused = true;
    error =
        "The server did not present a certificate chain to Grantry's roots. Something is "
        "intercepting this connection.";
    if (headers != nullptr) curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return false;
  }

  if (code == CURLE_OK) {
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    response.status = static_cast<int>(status);
  } else {
    error = curl_easy_strerror(code);
    // The one failure the transport probe latches. See HttpResponse::pin_refused.
    // With the trust store limited to the pinned roots, a certificate that does
    // not chain to one of them IS the pin failing.
    if (code == CURLE_SSL_PINNEDPUBKEYNOTMATCH
        || (anchors != nullptr && code == CURLE_PEER_FAILED_VERIFICATION)) {
      response.pin_refused = true;
    }
  }

  if (headers != nullptr) curl_slist_free_all(headers);
  curl_easy_cleanup(curl);

  return code == CURLE_OK;
}

std::vector<std::string> PemBundleSpkiPins(const std::string& pem) {
  std::vector<std::string> pins;
  BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (bio == nullptr) return pins;
  while (X509* certificate = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr)) {
    unsigned char* der = nullptr;
    const int length = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(certificate), &der);
    X509_free(certificate);
    if (length <= 0 || der == nullptr) {
      BIO_free(bio);
      return {};
    }
    pins.push_back(Base64Encode(Sha256(std::vector<std::uint8_t>(der, der + length))));
    OPENSSL_free(der);
  }
  // The loop ends on the first block that does not parse, so a bundle with a
  // broken certificate in it must not pass as a shorter good one.
  ERR_clear_error();
  BIO_free(bio);
  const std::string kBegin = "-----BEGIN CERTIFICATE-----";
  std::size_t blocks = 0;
  for (std::size_t at = pem.find(kBegin); at != std::string::npos; at = pem.find(kBegin, at + 1)) {
    ++blocks;
  }
  if (blocks != pins.size()) return {};
  return pins;
}

bool RandomBytes(std::uint8_t* out, std::size_t length) {
  return RAND_bytes(out, static_cast<int>(length)) == 1;
}

std::vector<std::uint8_t> Sha256(const std::string& text) {
  std::vector<std::uint8_t> digest(SHA256_DIGEST_LENGTH, 0);
  SHA256(reinterpret_cast<const unsigned char*>(text.data()), text.size(), digest.data());
  return digest;
}

std::vector<std::uint8_t> Sha256(const std::vector<std::uint8_t>& bytes) {
  std::vector<std::uint8_t> digest(SHA256_DIGEST_LENGTH, 0);
  SHA256(bytes.data(), bytes.size(), digest.data());
  return digest;
}

bool HmacSha256(const std::vector<std::uint8_t>& key,
                const std::vector<std::uint8_t>& message,
                std::vector<std::uint8_t>& out) {
  out.assign(SHA256_DIGEST_LENGTH, 0);
  unsigned int length = 0;

  // A zero-length key is legal and meaningful — HKDF's empty salt lands here —
  // so an empty vector must still produce a real HMAC rather than a refusal.
  const unsigned char* key_data =
      key.empty() ? reinterpret_cast<const unsigned char*>("") : key.data();

  const unsigned char* result = HMAC(EVP_sha256(), key_data, static_cast<int>(key.size()),
                                     message.data(), message.size(), out.data(), &length);
  return result != nullptr && length == SHA256_DIGEST_LENGTH;
}

bool AesGcmDecrypt(const std::vector<std::uint8_t>& key,
                   const std::vector<std::uint8_t>& iv,
                   const std::vector<std::uint8_t>& ciphertext,
                   const std::vector<std::uint8_t>& tag,
                   std::vector<std::uint8_t>& out) {
  if (key.size() != 32 || iv.size() != 12 || tag.size() != 16) return false;

  EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
  if (context == nullptr) return false;

  std::vector<std::uint8_t> plaintext(ciphertext.size());
  int length = 0;
  int produced = 0;
  bool ok = false;

  do {
    if (EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;
    if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) break;
    if (EVP_DecryptInit_ex(context, nullptr, nullptr, key.data(), iv.data()) != 1) break;

    if (!ciphertext.empty()) {
      if (EVP_DecryptUpdate(context, plaintext.data(), &length, ciphertext.data(),
                            static_cast<int>(ciphertext.size())) != 1) {
        break;
      }
      produced = length;
    }

    if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, 16,
                            const_cast<std::uint8_t*>(tag.data())) != 1) {
      break;
    }

    /*
     * ⚠️ THE TAG IS CHECKED HERE, AND A FAILURE PRODUCES NOTHING.
     *
     * EVP_DecryptFinal_ex returns zero when the tag does not authenticate, and
     * the plaintext computed so far is discarded rather than returned. Handing
     * it back "so the caller can decide" would mean handing an application a
     * value an attacker chose, which is the exact thing the tag exists to stop.
     */
    if (EVP_DecryptFinal_ex(context, plaintext.data() + produced, &length) != 1) break;
    produced += length;
    ok = true;
  } while (false);

  EVP_CIPHER_CTX_free(context);
  if (!ok) return false;

  plaintext.resize(static_cast<std::size_t>(produced));
  out = std::move(plaintext);
  return true;
}

bool RsaSha256Verify(const std::vector<std::uint8_t>& modulus,
                     const std::vector<std::uint8_t>& exponent,
                     const std::vector<std::uint8_t>& message,
                     const std::vector<std::uint8_t>& signature) {
  if (modulus.empty() || exponent.empty() || signature.empty()) return false;

  BIGNUM* n = BN_bin2bn(modulus.data(), static_cast<int>(modulus.size()), nullptr);
  BIGNUM* e = BN_bin2bn(exponent.data(), static_cast<int>(exponent.size()), nullptr);
  if (n == nullptr || e == nullptr) {
    BN_free(n);
    BN_free(e);
    return false;
  }

  RSA* rsa = RSA_new();
  if (rsa == nullptr) {
    BN_free(n);
    BN_free(e);
    return false;
  }
  // Takes ownership of both BIGNUMs.
  RSA_set0_key(rsa, n, e, nullptr);

  EVP_PKEY* key = EVP_PKEY_new();
  if (key == nullptr || EVP_PKEY_assign_RSA(key, rsa) != 1) {
    EVP_PKEY_free(key);
    RSA_free(rsa);
    return false;
  }

  EVP_MD_CTX* context = EVP_MD_CTX_new();
  bool verified = false;
  if (context != nullptr
      && EVP_DigestVerifyInit(context, nullptr, EVP_sha256(), nullptr, key) == 1) {
    // ⚠️ ONLY AN EXACT 1 IS SUCCESS. OpenSSL returns 0 for "did not verify" and
    // negative for "something went wrong", and a `!= 0` test would treat the
    // error case as a valid signature.
    verified = EVP_DigestVerify(context, signature.data(), signature.size(),
                                message.data(), message.size()) == 1;
  }

  EVP_MD_CTX_free(context);
  EVP_PKEY_free(key);
  return verified;
}

bool ProtectLocal(const std::vector<std::uint8_t>&, std::vector<std::uint8_t>&) {
  // See the file header. No platform facility here, and inventing one out of a
  // key derived from something on the same disk would be obfuscation sold as
  // encryption.
  return false;
}

bool UnprotectLocal(const std::vector<std::uint8_t>&, std::vector<std::uint8_t>&) {
  return false;
}

std::string UserDataDirectory() {
  const char* xdg = std::getenv("XDG_CONFIG_HOME");
  if (xdg != nullptr && xdg[0] != '\0') return std::string(xdg);

  const char* home = std::getenv("HOME");
  if (home != nullptr && home[0] != '\0') return std::string(home) + "/.config";

  return std::string(".");
}

bool MakeDirectories(const std::string& path) {
  std::string partial;
  for (std::size_t i = 0; i < path.size(); i++) {
    partial.push_back(path[i]);
    if (path[i] == '/' && partial.size() > 1) {
      ::mkdir(partial.c_str(), 0700);
    }
  }
  ::mkdir(path.c_str(), 0700);

  struct stat info;
  return ::stat(path.c_str(), &info) == 0 && S_ISDIR(info.st_mode);
}

// ---------------------------------------------------------------------------
// Machine anchor
// ---------------------------------------------------------------------------

#ifdef __APPLE__
const char* PlatformName() { return "macos"; }

/// `IOPlatformUUID`, read through `ioreg`.
///
/// ⚠️ UNLIKE THE WINDOWS ANCHOR, THIS SURVIVES A REINSTALL. The inconsistency is
/// real and is why the platform is reported alongside the hash: support
/// answering "my customer says they changed nothing" needs to know which of the
/// two behaviours they are looking at.
///
/// A subprocess rather than linking IOKit: one string, read once per launch,
/// against a framework dependency that has to keep working across
/// architectures. `ioreg` ships with every macOS.
std::string ReadMachineAnchor() {
  std::FILE* pipe = popen("/usr/sbin/ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null", "r");
  if (pipe == nullptr) return std::string();

  std::string output;
  char chunk[512];
  while (std::fgets(chunk, sizeof(chunk), pipe) != nullptr) {
    output += chunk;
    // Bounded: a hostile or hung `ioreg` must not stall the launch or grow
    // without limit.
    if (output.size() > 64 * 1024) break;
  }
  pclose(pipe);

  const std::string needle = "\"IOPlatformUUID\" = \"";
  std::size_t start = output.find(needle);
  if (start == std::string::npos) return std::string();

  start += needle.size();
  std::size_t end = output.find('"', start);
  if (end == std::string::npos) return std::string();

  return output.substr(start, end - start);
}
#else
const char* PlatformName() { return "linux"; }

/// `/etc/machine-id`, or the D-Bus copy on older systems.
///
/// Regenerated on reinstall, so it behaves like the Windows anchor. The better
/// answer is the DMI product UUID, which is root-only on modern kernels — and an
/// SDK that needs root to sign a user in is not one anybody ships.
std::string ReadMachineAnchor() {
  for (const char* path : {"/etc/machine-id", "/var/lib/dbus/machine-id"}) {
    std::ifstream file(path);
    if (!file) continue;

    std::string value;
    std::getline(file, value);
    while (!value.empty() && (value.back() == '\n' || value.back() == '\r' ||
                              value.back() == ' ')) {
      value.pop_back();
    }
    if (!value.empty()) return value;
  }
  return std::string();
}
#endif

std::optional<std::vector<std::uint8_t>> ReadFileBytes(const std::string& path) {
  std::ifstream file(path, std::ios::binary);
  if (!file) return std::nullopt;

  // A session store holds a token or two. Anything this large is not one.
  constexpr std::size_t kMaxStoredFileBytes = 1024 * 1024;
  std::vector<std::uint8_t> bytes;
  char chunk[4096];
  while (file.read(chunk, sizeof(chunk)) || file.gcount() > 0) {
    bytes.insert(bytes.end(), chunk, chunk + file.gcount());
    if (bytes.size() > kMaxStoredFileBytes) return std::nullopt;
  }
  return bytes;
}

bool ReplaceFilePrivately(const std::string& path, const std::vector<std::uint8_t>& bytes) {
  const std::string temporary = path + ".tmp";

  /*
   * The mode argument applies at CREATION, which is what makes this different
   * from a chmod afterwards: there is no instant at which the file exists with
   * wider permissions. (umask can only narrow it further, never widen it.) An
   * existing file keeps its old mode through open(), so it is narrowed too,
   * through the descriptor rather than the name. O_NOFOLLOW: a link planted at
   * the temporary name is refused rather than written through.
   */
  int fd = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                  S_IRUSR | S_IWUSR);
  if (fd < 0) return false;
  bool written = ::fchmod(fd, S_IRUSR | S_IWUSR) == 0;

  std::size_t offset = 0;
  while (written && offset < bytes.size()) {
    const ssize_t wrote = ::write(fd, bytes.data() + offset, bytes.size() - offset);
    if (wrote < 0 && errno == EINTR) continue;
    if (wrote <= 0) {
      written = false;
      break;
    }
    offset += static_cast<std::size_t>(wrote);
  }
  // A token half on disk is worse than the previous one, so a failed sync keeps the old file.
  written = written && ::fsync(fd) == 0;
  ::close(fd);

  // rename() replaces the target in one step on every POSIX file system.
  if (!written || ::rename(temporary.c_str(), path.c_str()) != 0) {
    ::unlink(temporary.c_str());
    return false;
  }
  return true;
}

void RemoveFile(const std::string& path) { ::unlink(path.c_str()); }

/*
 * The path to our own executable.
 *
 * Linux exposes it as /proc/self/exe; macOS through _NSGetExecutablePath.
 * Both are the file on disk, which is what the merchant uploaded. Empty when
 * neither answers.
 */
static std::string ExecutablePath() {
  std::string path;
#if defined(__APPLE__)
  std::uint32_t size = 0;
  _NSGetExecutablePath(nullptr, &size);
  if (size == 0) return std::string();
  path.resize(size);
  if (_NSGetExecutablePath(&path[0], &size) != 0) return std::string();
  path.resize(std::strlen(path.c_str()));
#else
  char link[4096];
  ssize_t written = ::readlink("/proc/self/exe", link, sizeof(link) - 1);
  if (written <= 0) return std::string();
  link[written] = '\0';
  path.assign(link);
#endif
  return path;
}

bool ReadApplicationSlice(std::int64_t offset, std::size_t length, std::vector<std::uint8_t>& out) {
  if (offset < 0 || length == 0 || length > 65536) return false;
  const std::string path = ExecutablePath();
  if (path.empty()) return false;
  std::FILE* file = std::fopen(path.c_str(), "rb");
  if (file == nullptr) return false;
  bool whole = false;
  if (::fseeko(file, static_cast<off_t>(offset), SEEK_SET) == 0) {
    out.assign(length, 0);
    whole = std::fread(out.data(), 1, length, file) == length;
  }
  std::fclose(file);
  return whole;
}

std::string ApplicationHash() {
  const std::string path = ExecutablePath();
  if (path.empty()) return std::string();

  std::FILE* file = std::fopen(path.c_str(), "rb");
  if (file == nullptr) return std::string();

  SHA256_CTX context;
  SHA256_Init(&context);

  std::vector<unsigned char> buffer(64 * 1024);
  std::size_t read = 0;
  while ((read = std::fread(buffer.data(), 1, buffer.size(), file)) > 0) {
    SHA256_Update(&context, buffer.data(), read);
  }
  std::fclose(file);

  unsigned char digest[SHA256_DIGEST_LENGTH];
  SHA256_Final(digest, &context);

  static const char* kHex = "0123456789abcdef";
  std::string result;
  result.reserve(SHA256_DIGEST_LENGTH * 2);
  for (unsigned char b : digest) {
    result.push_back(kHex[b >> 4]);
    result.push_back(kHex[b & 0x0F]);
  }
  return result;
}

bool OpenSystemBrowser(const std::string& url) {
  /*
   * `open` on macOS and `xdg-open` elsewhere: each hands the address to the person's
   * own default browser. Spawned with an argument vector, never through a shell, so
   * nothing in the address is interpreted on the way; SignInUrlOpenable has already
   * refused anything but https, or http on a development host.
   */
#if defined(__APPLE__)
  const char* program = "open";
#else
  const char* program = "xdg-open";
#endif
  std::string argument = url;
  char* arguments[] = {const_cast<char*>(program), &argument[0], nullptr};

  pid_t child = 0;
  if (posix_spawnp(&child, program, nullptr, nullptr, arguments, environ) != 0) return false;

  // Both hand the address over and exit; their status says whether they could.
  int status = 0;
  if (waitpid(child, &status, 0) != child) return false;
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

}  // namespace internal
}  // namespace grantry

#endif  // !_WIN32
