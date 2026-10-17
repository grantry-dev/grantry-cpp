// Internals. Not installed, not part of the ABI.
#ifndef GRANTRY_INTERNAL_HPP
#define GRANTRY_INTERNAL_HPP

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "grantry/grantry.hpp"

namespace grantry {
namespace internal {

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

/// A minimal JSON value.
///
/// Hand-written rather than pulled from a package, for the reason in the public
/// header: a desktop SDK with a dependency tree is one a games studio cannot
/// ship. It parses exactly what this library consumes — a JWKS, a JWT payload
/// and a handful of API responses — and refuses everything else rather than
/// guessing.
class Json {
 public:
  enum class Type { kNull, kBool, kNumber, kString, kArray, kObject };

  Type type = Type::kNull;
  bool boolean = false;
  double number = 0;
  std::string string;
  std::vector<Json> array;
  std::map<std::string, Json> object;

  bool is_null() const { return type == Type::kNull; }
  bool is_object() const { return type == Type::kObject; }
  bool is_array() const { return type == Type::kArray; }
  bool is_string() const { return type == Type::kString; }
  bool is_number() const { return type == Type::kNumber; }

  /// A member of an object, or nullptr.
  const Json* Find(const std::string& key) const;

  /// A string member, or nullopt when absent or the wrong type.
  std::optional<std::string> GetString(const std::string& key) const;
  /// An integer member. Rejects a non-integral double rather than truncating.
  std::optional<std::int64_t> GetInt(const std::string& key) const;
  bool GetBool(const std::string& key) const;
  std::vector<std::string> GetStringArray(const std::string& key) const;

  static bool Parse(const std::string& text, Json& out);
  /// Serialise. Only what this library emits: objects of strings.
  static std::string Serialize(const std::map<std::string, std::string>& fields);
  /// The same, plus boolean members.
  ///
  /// Separate maps rather than a variant because two kinds is all this library
  /// sends, and a variant would invite a third.
  static std::string Serialize(const std::map<std::string, std::string>& fields,
                               const std::map<std::string, bool>& flags);
};

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

std::string Base64UrlEncode(const std::vector<std::uint8_t>& bytes);

/// Decode base64url, rejecting anything that is not exactly that.
///
/// ⚠️ STRICT ON PURPOSE. A decoder that quietly accepts `+` and `/`, or ignores
/// trailing junk, lets two different strings decode to the same bytes — which
/// is a signature-splicing primitive when the thing being decoded is a JWT
/// segment.
bool Base64UrlDecode(const std::string& text, std::vector<std::uint8_t>& out);

/// Compare without leaking where two strings first differ.
///
/// The nonce comparison runs on every token, so an ordinary `==` — which
/// returns at the first differing byte — gives a local attacker a timing oracle
/// they can walk one character at a time.
bool FixedTimeEquals(const std::string& a, const std::string& b);

/// RFC 7638 thumbprint of an RSA public key, from its JWK members.
///
/// Derived from the key material rather than read from the JWKS. A `kid` is
/// whatever the server chose to call the key; a thumbprint IS the key, so
/// pinning one pins the key and not its label.
std::string RsaThumbprint(const std::string& n_b64url, const std::string& e_b64url);

/// Lowercase hex, which is how a checksum is published.
std::string Hex(const std::vector<std::uint8_t>& bytes);

/// HKDF-SHA256, RFC 5869, extract then expand.
///
/// Written on top of HmacSha256 rather than taken from a platform library,
/// because the platforms disagree about whether they have one: OpenSSL grew
/// EVP_KDF late, and BCrypt's HKDF needs Windows 10 1803. One implementation
/// means one thing to get right, and it is checked against the RFC's own
/// vectors — see the test suite.
///
/// An empty salt is defined as a string of zeros the length of the hash, NOT as
/// "skip the extract step". They are different functions that look the same
/// from outside.
bool Hkdf(const std::vector<std::uint8_t>& ikm, const std::vector<std::uint8_t>& salt,
          const std::vector<std::uint8_t>& info, std::size_t length,
          std::vector<std::uint8_t>& out);

// ---------------------------------------------------------------------------
// Certificate pinning
// ---------------------------------------------------------------------------

/// The public API's SPKI pins, base64 SHA-256: Let's Encrypt's four root keys
/// (crypto.cpp says why the roots and not the server's own key).
///
/// ⚠️ MORE THAN ONE, DELIBERATELY. A single pin is an outage waiting for the
/// day the key changes: every build already shipped would refuse to connect,
/// and no update can reach them because the updater is behind the same pin.
extern const char* const kDefaultCertificatePins[4];

/// The roots those pins name, PEM, in the same order.
extern const char* const kDefaultTrustAnchorsPem;

/// The host those pins belong to.
extern const char* const kDefaultPinnedHost;

/// The trust store a handshake should be limited to for these pins: the
/// built-in roots when `pins` is exactly the built-in set, otherwise null.
///
/// ⚠️ libcurl CAN PIN ONLY THE SERVER'S OWN KEY, so a root pin cannot be
/// enforced through CURLOPT_PINNEDPUBLICKEY. The POSIX transport enforces the
/// built-in pins by trusting these roots and nothing else, which refuses a
/// proxy's certificate during the handshake, before a byte is sent. A
/// merchant's own pins name their server's key and stay leaf pins there.
const char* TrustAnchorsFor(const std::vector<std::string>& pins);

/// The SPKI pin of every certificate in a PEM bundle, in order, computed with
/// this platform's own crypto. Empty if any certificate fails to parse.
/// What the tests prove the built-in pins against.
std::vector<std::string> PemBundleSpkiPins(const std::string& pem);

/// Whether pinning applies, given what the caller configured.
///
/// An explicit setting always wins. Otherwise pinning is on exactly when the
/// base URL is the API the built-in pins describe, so the default protects
/// production and a merchant pointing at staging is not left debugging a
/// handshake failure they did not ask for.
bool ShouldPin(const Options& options);

/// The pins to enforce. The caller's, if they supplied any.
std::vector<std::string> PinsFor(const Options& options);

// ---------------------------------------------------------------------------
// Platform
// ---------------------------------------------------------------------------

struct HttpResponse {
  int status = 0;
  std::string body;
  /// Response headers, lower-cased keys.
  std::map<std::string, std::string> headers;
  /// The send failed because the server's key matched none of the pins.
  ///
  /// ⚠️ SET ONLY FOR THAT, so the caller can tell an interception proxy from a
  /// dropped connection. The transport probe latches the first and must never
  /// latch the second: an application started offline would otherwise refuse
  /// every call until it was restarted.
  bool pin_refused = false;
};

struct HttpRequest {
  std::string method;
  std::string url;
  std::map<std::string, std::string> headers;
  /// Empty means no body.
  std::string body;
  int timeout_seconds = 30;
  /// Loopback over plain HTTP, for development. See Options.
  bool allow_insecure = false;
  /// The most of a response body this request will read. A megabyte for everything the API
  /// answers in JSON; `Download` raises it for a file, which is the one large answer there is.
  std::size_t max_body_bytes = 1024 * 1024;

  /// SPKI pins, base64 SHA-256. Empty means "trust the machine's store".
  ///
  /// ⚠️ ENFORCED AT HANDSHAKE TIME WHERE THE PLATFORM ALLOWS IT, which on
  /// POSIX means libcurl refuses the connection before a single request byte
  /// leaves: the built-in pins as the only trusted roots (TrustAnchorsFor),
  /// anybody else's as the server's own key. WinHTTP has no equivalent hook in
  /// synchronous mode, so the Windows path compares every certificate in the
  /// chain Windows built after the handshake and refuses the exchange — which
  /// is why `GrantryClient` probes the transport with a credential-free request
  /// before it sends anything worth intercepting. See ProbeTransport.
  std::vector<std::string> certificate_pins;
};

/// One HTTPS request, using the platform's own stack and trust store.
bool HttpSend(const HttpRequest& request, HttpResponse& response, std::string& error);

/// Fill `out` with cryptographically secure random bytes.
///
/// ⚠️ `rand()` WOULD BE A VULNERABILITY HERE, not a style choice. The nonce's
/// whole job is to be unpredictable to somebody replaying a recorded response.
bool RandomBytes(std::uint8_t* out, std::size_t length);

/// Verify an RSASSA-PKCS1-v1_5 SHA-256 signature.
///
/// `modulus` and `exponent` are raw big-endian integers, as they arrive in a
/// JWK. Returns false for any failure, including a malformed key — never
/// "true on error".
bool RsaSha256Verify(const std::vector<std::uint8_t>& modulus,
                     const std::vector<std::uint8_t>& exponent,
                     const std::vector<std::uint8_t>& message,
                     const std::vector<std::uint8_t>& signature);

std::vector<std::uint8_t> Sha256(const std::string& text);
std::vector<std::uint8_t> Sha256(const std::vector<std::uint8_t>& bytes);

/// HMAC-SHA256. The only building block HKDF needs.
bool HmacSha256(const std::vector<std::uint8_t>& key,
                const std::vector<std::uint8_t>& message,
                std::vector<std::uint8_t>& out);

/// AES-256-GCM, decrypt and authenticate, with no additional data.
///
/// ⚠️ THE TAG IS CHECKED BEFORE ANY PLAINTEXT IS PRODUCED, and a failure
/// returns false with `out` untouched. Releasing unauthenticated plaintext
/// "just to look at it" is how padding-oracle-shaped bugs get built; here it
/// would mean handing an application a value an attacker chose.
///
/// The IV is always 96 bits and the tag 128, because that is the only shape the
/// server produces. Accepting others would mean writing branches nothing
/// exercises.
bool AesGcmDecrypt(const std::vector<std::uint8_t>& key,
                   const std::vector<std::uint8_t>& iv,
                   const std::vector<std::uint8_t>& ciphertext,
                   const std::vector<std::uint8_t>& tag,
                   std::vector<std::uint8_t>& out);

/// Base64 SHA-256 over a certificate's DER SubjectPublicKeyInfo.
///
/// Standard base64 with padding, matching every other tool that prints a pin —
/// a fingerprint nobody else can compute is a pin nobody can rotate.
std::string Base64Encode(const std::vector<std::uint8_t>& bytes);

/// Wrap and unwrap with OS-held key material, where the platform has any.
/// Returns false when the platform has no such facility; the caller then
/// stores plaintext under restrictive permissions and the header says so.
bool ProtectLocal(const std::vector<std::uint8_t>& plaintext,
                  std::vector<std::uint8_t>& out);
bool UnprotectLocal(const std::vector<std::uint8_t>& ciphertext,
                    std::vector<std::uint8_t>& out);

/// `%LOCALAPPDATA%` or `$XDG_CONFIG_HOME`, whichever the platform uses.
std::string UserDataDirectory();

/// Create a directory and every parent.
bool MakeDirectories(const std::string& path);

/// A whole file, or nullopt when it is absent, unreadable or implausibly large
/// for a session store. `path` is UTF-8 on every platform.
std::optional<std::vector<std::uint8_t>> ReadFileBytes(const std::string& path);

/// Replace `path` with `bytes`, or leave it as it was. False when nothing changed.
///
/// Written to `<path>.tmp`, created owner-only BEFORE any byte goes in, flushed,
/// then moved over `path` in one step.
///
/// ⚠️ ORDER IS THE POINT, TWICE. Writing first and narrowing afterwards leaves
/// the token readable by every local account for the length of the write; and
/// deleting the old file before moving the new one in — what this did on
/// Windows, because `std::rename` there refuses an existing target — left a
/// moment with no session at all, which a crash turned into a sign-out.
///
/// ⚠️ AND UTF-8 PATHS ON WINDOWS, THROUGH THE WIDE API. `std::fopen` and
/// `std::ofstream` read a narrow path in the ANSI code page, so a profile named
/// `José` or `Łukasz` produced a mangled path whose directory did not exist,
/// and the session was never saved — silently, on every sign-in.
bool ReplaceFilePrivately(const std::string& path, const std::vector<std::uint8_t>& bytes);

/// Delete a file. Absent already is not a failure.
void RemoveFile(const std::string& path);

/// SHA-256 of this process's own executable, as lowercase hex.
///
/// Empty when it cannot be read, which the caller turns into an omitted header
/// rather than a failure — reading our own file can fail for entirely
/// ordinary reasons and refusing to start would be worse than not sending it.
///
/// ⚠️ THE FILE ON DISK, NOT THE LOADED IMAGE. Relocations and ASLR rewrite
/// the image as it loads, so a hash of memory would never match what the
/// merchant uploaded.
///
/// ⚠️ AND NOT A SECURITY BOUNDARY. A patched build reports whatever it
/// likes; this raises the cost of redistributing a modified or stale binary.
std::string ApplicationHash();

/// A slice of this program's own file — the one `ApplicationHash` reads — for the build challenge
/// (migration 0362). False when it cannot be read whole.
///
/// ⚠️ READ AGAIN FOR EACH CHALLENGE, NOT HELD FROM THE START: a few kilobytes every ten minutes,
/// where keeping the whole build in memory would cost every application its own size.
bool ReadApplicationSlice(std::int64_t offset, std::size_t length, std::vector<std::uint8_t>& out);

/// The platform's machine anchor, raw.
///
/// ⚠️ THIS VALUE NEVER LEAVES THE MACHINE. It is the customer's hardware
/// identity — a Windows machine SID, a macOS IOPlatformUUID, a Linux
/// machine-id — and the caller hashes it with the environment id before
/// anything is sent. Empty when the platform offers nothing usable.
///
/// Windows returns the MACHINE SID rather than the user's: every local
/// account's SID is `<machine SID>-<RID>`, so anchoring to the user's would
/// burn two device slots on a household PC that two people share.
std::string ReadMachineAnchor();

/// The anchor to hash: `machine_anchor`, or — when the platform offered none — a random
/// identifier kept in `store`'s device-fallback slot, made and kept on first use.
std::string AnchorOrFallback(const std::string& machine_anchor, SessionStore& store);

/// `windows`, `macos`, `linux` or `other`.
const char* PlatformName();

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

struct SigningKey {
  std::string kid;
  std::string thumbprint;
  std::vector<std::uint8_t> modulus;
  std::vector<std::uint8_t> exponent;
};

/// The published signing keys, fetched once and reused.
///
/// ⚠️ THE REFRESH IS RATE LIMITED, AND THAT IS A SECURITY CONTROL RATHER THAN
/// POLITENESS. An unknown `kid` triggers a refetch, because that is what makes
/// key rotation invisible to a running application — but "unknown kid" is
/// entirely attacker-controlled. Without a floor, a flood of forged tokens is a
/// way to make a desktop client hammer the API on command.
class JwksCache {
 public:
  /// Fetches the JWKS document. Returns false and sets `error` on failure.
  ///
  /// Injected rather than called directly so the verifier can be tested without
  /// a network — and, more importantly, so the parsing and pinning rules below
  /// are exercised against documents a real server would never send. A test
  /// that can only fetch from a real API can only test the happy path.
  using Fetcher = std::function<bool(std::string& body, std::string& error)>;

  /// `pins` are RFC 7638 key thumbprints; `certificate_pins` are the
  /// transport's SPKI pins, empty when pinning is off.
  JwksCache(std::string url, int lifetime_seconds, std::vector<std::string> pins,
            int timeout_seconds, bool allow_insecure,
            std::vector<std::string> certificate_pins);

  /// Same cache, with a caller-supplied fetcher.
  JwksCache(Fetcher fetcher, int lifetime_seconds, std::vector<std::string> pins);

  /// The key a token names, fetching if unknown or stale. False when no match.
  ///
  /// ⚠️ A COPY, NOT A POINTER INTO THE CACHE, AND UNDER A LOCK. One client
  /// verifies from several threads at once — a variable read beside a mint, and
  /// since WatchPlans a mint on a thread of the SDK's own — and a refetch
  /// replaces the map. A pointer handed out before it was a pointer into freed
  /// memory by the time the signature was checked against it.
  bool GetKey(const std::string& kid, SigningKey& out, std::string& error);

  int fetch_count() const;

 private:
  bool Fetch(std::string& error);

  Fetcher fetcher_;
  int lifetime_seconds_;
  std::vector<std::string> pins_;

  /// Guards everything below, and is held across a fetch, so threads that
  /// meet an unknown key together make one request rather than one each.
  mutable std::mutex mutex_;
  std::map<std::string, SigningKey> keys_;
  std::int64_t fetched_at_ = 0;
  std::int64_t last_attempt_at_ = 0;
  int fetch_count_ = 0;
};

std::int64_t UnixNow();

/// The `attempts_remaining` an error body claims, or -1 when it claims none.
///
/// ⚠️ THE BODY THIS READS IS NOT SIGNED, which is why the value is clamped
/// rather than trusted. Anything able to answer this SDK writes it, and an
/// application that renders it unchecked draws "you have -1 attempts left", or
/// a number with four thousand digits in it, inside a window the user trusts.
///
/// A pure function so the hostile inputs can be tested without a network. Pass
/// the `error` object, not the whole document.
int AttemptsRemainingFrom(const Json& api_error);

/// The unspent recovery codes a response claims, or -1 when it claims none.
///
/// ⚠️ -1 RATHER THAN 0, BECAUSE ZERO IS A REAL AND ALARMING ANSWER. "You have
/// no recovery codes left" is a sentence an application should put on screen;
/// "the server did not mention them" is not, and a default of zero would have
/// every path that never reports the count announce a lockout that has not
/// happened. The same rule as `attempts_remaining` above.
///
/// ⚠️ AND CLAMPED FOR THE SAME REASON THAT ONE IS: the body is not signed, and
/// a count with four thousand digits in it would go straight onto a screen.
///
/// A pure function, so the hostile inputs can be tested without a network. Pass
/// the whole document.
int BackupCodesRemainingFrom(const Json& document);

/// Read the reveal's answer (0279): `{"status":"shown","backupCodes":[...]}`,
/// or `{"status":"regenerate"}`. False for anything else.
///
/// ⚠️ FALSE, NOT AN EMPTY SET, FOR A BODY THIS CANNOT READ. "You have no codes"
/// is a claim about the account, and an answer nobody could parse is not
/// evidence for it — the caller reports an error instead. A pure function, so
/// the shapes can be tested without a network.
bool BackupCodeViewFrom(const Json& document, BackupCodeView& out);

/// The body the backup-code routes take: the proof's one field and nothing else.
std::string ProofBody(const Proof& proof);

/// A 202 that refused the session because the password must change.
struct PasswordUpdate {
  /// The single-use password-reset token. Never empty when the parse succeeded.
  std::string token;
  /// Whether "breached" was among the reasons. See SignInResult.
  bool breached = false;
};

/// Recognise `{"status":"password_update_required","token":...}`, or don't.
///
/// ⚠️ THE TOKEN IS THE TEST, NOT THE STATUS STRING. A body carrying the status
/// and no token describes an outcome the caller cannot act on — there is no
/// session and nothing to redeem — and reporting it would put an application on
/// a new-password screen whose submit button has nothing to send. Returning
/// false sends it down the ordinary path, where the absent session is caught.
///
/// ⚠️ AND IT IS KEYED ON THE BODY RATHER THAN ON THE 202. The status code says
/// how the response travelled; the body says what happened. Nothing is lost by
/// reading the body alone — a responder that could lie about one can lie about
/// both — and a check on the code would break the day the route answers 200.
///
/// A pure function, so both call sites and the hostile inputs can be tested
/// without a network. Pass the whole document.
bool PasswordUpdateFrom(const Json& document, PasswordUpdate& out);

// ---------------------------------------------------------------------------
// Redirect sign-in (docs/hosted-sign-in.md §12 decision 3)
// ---------------------------------------------------------------------------

/// RFC 7636's S256: BASE64URL(SHA-256(ASCII(verifier))).
std::string PkceChallenge(const std::string& verifier);

/// Whether `url` may be handed to the operating system to open.
///
/// ⚠️ THE ADDRESS COMES FROM THE SERVER, AND THE SHELL WILL OPEN ANYTHING.
/// ShellExecute, `open` and `xdg-open` all dispatch on the scheme, so a `file:` or
/// `ms-settings:` address from a response somebody tampered with would launch what
/// is registered for it. https, then, and http only on a local development host: a
/// development environment's sign-in URL is `http://<slug>.localhost:3103`.
bool SignInUrlOpenable(const std::string& url);

/// A query string's parameters, application/x-www-form-urlencoded. False when a
/// name repeats: `state=ours&state=theirs` is an answer somebody built, and taking
/// either copy would let them choose which check passes.
bool ParseQuery(const std::string& query, std::map<std::string, std::string>& out);

/// The code in the answer the listener took, or the `kRedirect` error saying why
/// there is none. The state was checked by the listener; this checks the rest
/// (RFC 9207's `iss` first, on an error too), before anything is sent anywhere.
Error CodeFromAnswer(const std::map<std::string, std::string>& answer,
                     const std::string& sign_in_url, std::string& code);

/// Where the browser is sent once the answer is dealt with: the sign-in host's own
/// `/finished` page, `?outcome=signed_in` or `?outcome=failed`. The same address the C#
/// and Python SDKs send it to, so the ending is the hosted card in every SDK.
std::string FinishedUrl(const std::string& sign_in_url, bool signed_in);

/// What a request that is not this sign-in's answer is told.
std::string NotThisSignInPage();

/// Open `url` in the system's default browser. False when it could not be.
bool OpenSystemBrowser(const std::string& url);

/// Where a redirect sign-in comes back: a socket on 127.0.0.1, on a port the
/// operating system chose, answering one sign-in (RFC 8252 §7.3). See
/// loopback.cpp for the rules.
class LoopbackListener {
 public:
  enum class Outcome { kAnswered, kTimedOut, kCancelled, kFailed };

  /// Binds 127.0.0.1 on any free port. Check `ok()`.
  LoopbackListener();
  /// Closes the listening socket and every connection, the answer's included.
  ~LoopbackListener();

  LoopbackListener(const LoopbackListener&) = delete;
  LoopbackListener& operator=(const LoopbackListener&) = delete;

  bool ok() const { return port_ != 0; }
  unsigned short port() const { return port_; }
  /// The address the socket is bound to, dotted. Always 127.0.0.1; the tests say so.
  std::string address() const;
  /// `http://127.0.0.1:<port>/callback`: sent to authorize, and presented again at
  /// the exchange.
  std::string redirect_uri() const;

  /// Wait for the request on /callback carrying `state`, until `timeout_seconds`
  /// pass or `cancelled` answers true. On kAnswered, `answer` holds its parameters,
  /// the listening socket is closed, and the connection waits for `Redirect`.
  Outcome Wait(const std::string& state, int timeout_seconds,
               const std::function<bool()>& cancelled,
               std::map<std::string, std::string>& answer);

  /// Send the browser on to `location` (a 303) and close the answer's connection.
  void Redirect(const std::string& location);

  /// Whether the listening socket is still open.
  bool listening() const;

 private:
  void CloseListener();

#ifdef _WIN32
  using Socket = std::uintptr_t;
#else
  using Socket = int;
#endif
  Socket listener_;
  Socket answer_;
  bool started_ = false;
  unsigned short port_ = 0;
};

}  // namespace internal

/// Turns a JWT into an `Identity`, or refuses.
///
/// ⚠️ THE ONLY PLACE AN `Identity` IS CREATED, and the library is arranged so
/// that stays true. Every field a caller reads has been through the checks
/// below; there is no path that parses a token and hands back claims without
/// verifying it first, because that path is how signed tokens end up being used
/// as if they were JSON.
class TokenVerifier {
 public:
  TokenVerifier(internal::JwksCache* jwks, std::string issuer, int clock_skew_seconds,
                std::vector<std::string> pins);

  Result<Identity> Verify(const std::string& token, const std::string& expected_audience,
                          const std::string& expected_nonce);

  /// What a signed resource envelope has to say to be accepted.
  struct ResourceExpectation {
    std::string audience;
    std::string nonce;
    /// `variable` or `file`.
    std::string kind;
    /// The variable key, or the file id — the one ASKED FOR, never the one the
    /// body came back carrying.
    std::string key;
    /// The signed-in user, when the SDK has already verified one. Empty skips
    /// that single check; the nonce still binds the envelope to a request made
    /// with this session's token.
    std::string subject;
    /// Base64url SHA-256 of a variable's plaintext, or a file's hex checksum.
    std::string digest;
  };

  /// Verify one envelope, or refuse.
  ///
  /// ⚠️ THERE IS NO BOOLEAN RESULT TO IGNORE, and no accessor that hands the
  /// expected digest back for the caller to compare themselves. A `bool
  /// Verify()` is one ignored return value from silently accepting a forged
  /// value, and one `NOP` from being bypassed in a patched binary. The only
  /// path out of here that leaves the caller running is the one where every
  /// check passed.
  Status VerifyResource(const std::string& envelope, const ResourceExpectation& expected);

 private:
  /// The JWS half, shared by access tokens and resource envelopes.
  ///
  /// ⚠️ ONE IMPLEMENTATION ON PURPOSE. A second copy for signed variables
  /// would be a second place for the algorithm check to be written slightly
  /// differently, and algorithm confusion is exactly the bug that survives a
  /// copy-paste.
  ///
  /// On success `payload` holds the verified claims.
  Status VerifyEnvelope(const std::string& token, const std::string& expected_audience,
                        const std::string& expected_nonce, std::int64_t maximum_lifetime,
                        internal::Json& payload);

  internal::JwksCache* jwks_;
  std::string issuer_;
  int clock_skew_seconds_;
  std::vector<std::string> pins_;
};

}  // namespace grantry

#endif  // GRANTRY_INTERNAL_HPP
