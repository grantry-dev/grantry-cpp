// The C++ SDK's test suite.
//
// Every test that touches verification plays the attacker. None of them assume
// a patched binary — that is out of scope by construction, and sdks/SECURITY.md
// says so. What is in scope is everything an attacker can do WITHOUT touching
// the binary: serve a different JWKS, intercept and replace a response, replay
// a recording, point the client at another environment.
//
// No test framework: one more dependency for a library whose whole argument is
// that it has none. `CHECK` prints the failing expression and the line, which is
// what a framework would have done anyway.

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cctype>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <map>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "internal.hpp"

// clang-format off
#ifdef _WIN32
// See platform_windows.cpp: both headers define the same NTSTATUS codes.
// WIN32_NO_STATUS first, THEN winsock2.h, THEN windows.h.
//
// winsock2.h has to precede windows.h or the latter pulls in the original
// winsock.h and every socket symbol is declared twice. But winsock2.h reaches
// windows.h itself, so the guard below has to be set before it rather than
// between the two — otherwise ntstatus.h redefines a hundred status macros and
// the build fills with C4005.
#define WIN32_NO_STATUS
#include <winsock2.h>
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <bcrypt.h>
#else
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#endif
// clang-format on

using grantry::Identity;
using grantry::Result;
using grantry::TokenVerifier;
using grantry::VerificationFailure;
using grantry::internal::Base64UrlDecode;
using grantry::internal::Base64UrlEncode;
using grantry::internal::FixedTimeEquals;
using grantry::internal::Json;
using grantry::internal::JwksCache;
using grantry::internal::AesGcmDecrypt;
using grantry::internal::Hex;
using grantry::internal::Hkdf;
using grantry::internal::HmacSha256;
using grantry::internal::PinsFor;
using grantry::internal::RsaThumbprint;
using grantry::internal::Sha256;
using grantry::internal::ShouldPin;
using grantry::internal::UnixNow;

namespace {

int g_failures = 0;
int g_checks = 0;

#define CHECK(expression)                                                       \
  do {                                                                          \
    g_checks++;                                                                 \
    if (!(expression)) {                                                        \
      g_failures++;                                                             \
      std::printf("  FAIL  %s:%d  %s\n", __FILE__, __LINE__, #expression);      \
    }                                                                           \
  } while (false)

void Section(const char* name) { std::printf("%s\n", name); }

// ---------------------------------------------------------------------------
// A signing key, so the tests can mint tokens the way a server would
// ---------------------------------------------------------------------------

/// An RSA-2048 key pair, used to sign test tokens.
///
/// The library only ever VERIFIES, so there is no signing code to reuse — the
/// tests have to bring their own. Two instances are created: one standing for
/// the real server, one for anybody who can serve a JWKS or intercept a
/// response. A verifier is only worth anything if it can tell them apart.
class TestKey {
 public:
  TestKey() { Generate(); }

  ~TestKey() {
#ifdef _WIN32
    if (key_ != nullptr) BCryptDestroyKey(key_);
    if (algorithm_ != nullptr) BCryptCloseAlgorithmProvider(algorithm_, 0);
#else
    if (pkey_ != nullptr) EVP_PKEY_free(pkey_);
#endif
  }

  TestKey(const TestKey&) = delete;
  TestKey& operator=(const TestKey&) = delete;

  const std::string& n() const { return n_; }
  const std::string& e() const { return e_; }
  std::string thumbprint() const { return RsaThumbprint(n_, e_); }

  std::vector<std::uint8_t> Sign(const std::string& message) const {
#ifdef _WIN32
    std::vector<std::uint8_t> digest(32, 0);
    BCRYPT_ALG_HANDLE sha = nullptr;
    BCryptOpenAlgorithmProvider(&sha, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    BCryptHash(sha, nullptr, 0,
               reinterpret_cast<PUCHAR>(const_cast<char*>(message.data())),
               static_cast<ULONG>(message.size()), digest.data(), 32);
    BCryptCloseAlgorithmProvider(sha, 0);

    BCRYPT_PKCS1_PADDING_INFO padding;
    padding.pszAlgId = BCRYPT_SHA256_ALGORITHM;

    ULONG needed = 0;
    BCryptSignHash(key_, &padding, digest.data(), 32, nullptr, 0, &needed,
                   BCRYPT_PAD_PKCS1);

    std::vector<std::uint8_t> signature(needed);
    ULONG written = 0;
    BCryptSignHash(key_, &padding, digest.data(), 32, signature.data(), needed,
                   &written, BCRYPT_PAD_PKCS1);
    signature.resize(written);
    return signature;
#else
    std::vector<std::uint8_t> signature(EVP_PKEY_size(pkey_));
    std::size_t length = signature.size();

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    EVP_DigestSignInit(context, nullptr, EVP_sha256(), nullptr, pkey_);
    EVP_DigestSign(context, signature.data(), &length,
                   reinterpret_cast<const unsigned char*>(message.data()),
                   message.size());
    EVP_MD_CTX_free(context);

    signature.resize(length);
    return signature;
#endif
  }

 private:
  void Generate() {
#ifdef _WIN32
    BCryptOpenAlgorithmProvider(&algorithm_, BCRYPT_RSA_ALGORITHM, nullptr, 0);
    BCryptGenerateKeyPair(algorithm_, &key_, 2048, 0);
    BCryptFinalizeKeyPair(key_, 0);

    ULONG needed = 0;
    BCryptExportKey(key_, nullptr, BCRYPT_RSAPUBLIC_BLOB, nullptr, 0, &needed, 0);
    std::vector<std::uint8_t> blob(needed);
    ULONG written = 0;
    BCryptExportKey(key_, nullptr, BCRYPT_RSAPUBLIC_BLOB, blob.data(), needed,
                    &written, 0);

    const auto* header = reinterpret_cast<const BCRYPT_RSAKEY_BLOB*>(blob.data());
    const std::uint8_t* cursor = blob.data() + sizeof(BCRYPT_RSAKEY_BLOB);

    std::vector<std::uint8_t> exponent(cursor, cursor + header->cbPublicExp);
    cursor += header->cbPublicExp;
    std::vector<std::uint8_t> modulus(cursor, cursor + header->cbModulus);

    n_ = Base64UrlEncode(modulus);
    e_ = Base64UrlEncode(exponent);
#else
    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(context);
    EVP_PKEY_CTX_set_rsa_keygen_bits(context, 2048);
    EVP_PKEY_keygen(context, &pkey_);
    EVP_PKEY_CTX_free(context);

    const RSA* rsa = EVP_PKEY_get0_RSA(pkey_);
    const BIGNUM* n = nullptr;
    const BIGNUM* e = nullptr;
    RSA_get0_key(rsa, &n, &e, nullptr);

    std::vector<std::uint8_t> modulus(BN_num_bytes(n));
    BN_bn2bin(n, modulus.data());
    std::vector<std::uint8_t> exponent(BN_num_bytes(e));
    BN_bn2bin(e, exponent.data());

    n_ = Base64UrlEncode(modulus);
    e_ = Base64UrlEncode(exponent);
#endif
  }

  std::string n_;
  std::string e_;
#ifdef _WIN32
  BCRYPT_ALG_HANDLE algorithm_ = nullptr;
  BCRYPT_KEY_HANDLE key_ = nullptr;
#else
  EVP_PKEY* pkey_ = nullptr;
#endif
};

// ---------------------------------------------------------------------------
// Token minting
// ---------------------------------------------------------------------------

const char kIssuer[] = "https://grantry.dev";
const char kEnvironment[] = "env_test_1234567890";
const char kUser[] = "usr_test_1234567890";

std::string Segment(const std::string& json) {
  return Base64UrlEncode(std::vector<std::uint8_t>(json.begin(), json.end()));
}

struct TokenSpec {
  std::string algorithm = "RS256";
  std::string kid;
  std::string subject = kUser;
  std::string issuer = kIssuer;
  std::string audience = kEnvironment;
  std::string nonce;
  bool include_nonce = true;
  std::int64_t expires_in = 60;
  std::string extra_claims;
};

std::string Mint(const TestKey& key, const TokenSpec& spec) {
  std::string header = "{\"alg\":\"" + spec.algorithm + "\",\"kid\":\"" + spec.kid
                     + "\",\"typ\":\"JWT\"}";

  std::int64_t now = UnixNow();
  std::string payload = "{\"sub\":\"" + spec.subject
                      + "\",\"sid\":\"sess_1\",\"env\":\"" + std::string(kEnvironment)
                      + "\",\"aud\":\"" + spec.audience + "\",\"iss\":\"" + spec.issuer
                      + "\",\"ev\":true,\"iat\":" + std::to_string(now - 1)
                      + ",\"exp\":" + std::to_string(now + spec.expires_in);

  if (spec.include_nonce && !spec.nonce.empty()) {
    payload += ",\"nonce\":\"" + spec.nonce + "\"";
  }
  if (!spec.extra_claims.empty()) payload += "," + spec.extra_claims;
  payload += "}";

  std::string signing_input = Segment(header) + "." + Segment(payload);

  if (spec.algorithm == "none") return signing_input + ".";

  return signing_input + "." + Base64UrlEncode(key.Sign(signing_input));
}

std::string Jwks(const TestKey& key, const std::string& kid) {
  return "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"alg\":\"RS256\",\"kid\":\""
       + kid + "\",\"n\":\"" + key.n() + "\",\"e\":\"" + key.e() + "\"}]}";
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

void TestEncoding() {
  Section("encoding");

  std::vector<std::uint8_t> bytes = {0x00, 0x01, 0xFE, 0xFF, 0x7F, 0x80};
  std::string encoded = Base64UrlEncode(bytes);

  std::vector<std::uint8_t> decoded;
  CHECK(Base64UrlDecode(encoded, decoded));
  CHECK(decoded == bytes);

  // No padding, and none of the standard-base64 alphabet.
  CHECK(encoded.find('=') == std::string::npos);
  CHECK(encoded.find('+') == std::string::npos);
  CHECK(encoded.find('/') == std::string::npos);

  // ⚠️ STRICTNESS IS THE SECURITY PROPERTY. A decoder that accepts these lets
  // two different strings decode to the same bytes, which is a splicing
  // primitive when the input is a JWT segment.
  std::vector<std::uint8_t> ignored;
  CHECK(!Base64UrlDecode("AA==", ignored));
  CHECK(!Base64UrlDecode("a+b/", ignored));
  CHECK(!Base64UrlDecode("AAAAA", ignored));   // 1 mod 4 is impossible
  CHECK(!Base64UrlDecode("AA A", ignored));
  CHECK(!Base64UrlDecode("", ignored));

  CHECK(FixedTimeEquals("abcdef", "abcdef"));
  CHECK(!FixedTimeEquals("abcdef", "abcdeg"));
  CHECK(!FixedTimeEquals("abcdef", "abcde"));

  // The thumbprint is a function of the key, so it is stable across calls and
  // differs for different keys. That is what makes pinning mean anything.
  TestKey a;
  TestKey b;
  CHECK(a.thumbprint() == a.thumbprint());
  CHECK(a.thumbprint() != b.thumbprint());
  CHECK(a.thumbprint().size() == 43);  // SHA-256, base64url, unpadded
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

void TestJson() {
  Section("json");

  Json document;
  CHECK(Json::Parse("{\"a\":\"x\",\"b\":42,\"c\":true,\"d\":null,\"e\":[\"p\",\"q\"]}",
                    document));
  CHECK(document.GetString("a").value_or("") == "x");
  CHECK(document.GetInt("b").value_or(0) == 42);
  CHECK(document.GetBool("c"));
  CHECK(document.GetStringArray("e").size() == 2);

  /*
   * The exact body maintenance mode returns.
   *
   * ⚠️ THE `code` IS WHAT DECIDES THE ERROR KIND, so a parser that quietly
   * misses a nested field turns "we are closed, come back shortly" into a
   * generic API failure — and the application shows a sign-in error instead of
   * a wait screen. The nesting is the part worth asserting: a top-level
   * `GetString("code")` would find nothing and fail silently.
   */
  Json closed;
  CHECK(Json::Parse(
      "{\"error\":{\"code\":\"maintenance\",\"message\":\"Back at 09:00 UTC.\"}}",
      closed));
  const Json* closed_error = closed.Find("error");
  CHECK(closed_error != nullptr);
  CHECK(closed_error->GetString("code").value_or("") == "maintenance");
  CHECK(closed_error->GetString("message").value_or("") == "Back at 09:00 UTC.");

  /*
   * The attempt count, and the hostile numbers an unsigned body can carry.
   *
   * ⚠️ THIS IS THE ONE FIELD OF AN ERROR BODY AN APPLICATION IS TOLD IT MAY
   * PUT ON SCREEN, which is exactly why it is the one that has to be clamped.
   * `message` is guarded by telling callers never to render it; this has no
   * such protection, so the guard has to be in the parse.
   */
  Json refusal;
  CHECK(Json::Parse(
      "{\"error\":{\"code\":\"unauthorized\",\"attempts_remaining\":3}}",
      refusal));
  CHECK(AttemptsRemainingFrom(*refusal.Find("error")) == 3);

  // Zero is a real answer: that guess was the last one.
  Json spent;
  CHECK(Json::Parse("{\"error\":{\"attempts_remaining\":0}}", spent));
  CHECK(AttemptsRemainingFrom(*spent.Find("error")) == 0);

  // Absent means the server said nothing, which is NOT the same as zero.
  Json silent;
  CHECK(Json::Parse("{\"error\":{\"code\":\"unauthorized\"}}", silent));
  CHECK(AttemptsRemainingFrom(*silent.Find("error")) == -1);

  // Nonsense means silence too, rather than a sentence about -1 attempts.
  Json hostile;
  CHECK(Json::Parse("{\"error\":{\"attempts_remaining\":-5}}", hostile));
  CHECK(AttemptsRemainingFrom(*hostile.Find("error")) == -1);

  Json enormous;
  CHECK(Json::Parse("{\"error\":{\"attempts_remaining\":99999999999}}", enormous));
  CHECK(AttemptsRemainingFrom(*enormous.Find("error")) == -1);

  // A string that looks like a number is still not a number.
  Json stringly;
  CHECK(Json::Parse("{\"error\":{\"attempts_remaining\":\"3\"}}", stringly));
  CHECK(AttemptsRemainingFrom(*stringly.Find("error")) == -1);

  // Trailing content is refused: a document that "parses" and has junk after it
  // is not the document it claimed to be.
  Json ignored;
  CHECK(!Json::Parse("{\"a\":1} junk", ignored));
  CHECK(!Json::Parse("{\"a\":}", ignored));
  CHECK(!Json::Parse("[1,2", ignored));

  // ⚠️ THE DEPTH LIMIT IS A DENIAL-OF-SERVICE DEFENCE. A few kilobytes of `[`
  // blows a recursive-descent parser's stack, and every input this library
  // parses arrives from the network.
  std::string deep(200, '[');
  CHECK(!Json::Parse(deep, ignored));

  // A non-integral number is refused rather than truncated: an `exp` of
  // 1.7e9 + 0.5 is a malformed token, not one expiring half a second early.
  Json fractional;
  CHECK(Json::Parse("{\"exp\":1.5}", fractional));
  CHECK(!fractional.GetInt("exp").has_value());

  /*
   * ⚠️ AND SO IS ONE NO int64 CAN HOLD (12 October 2026). Infinity's fractional
   * part is zero, so `1e999` and `1e300` passed the integral test and were then
   * converted to an integer — undefined behaviour, reachable from an unsigned
   * error body's attempt count before its range check ran.
   */
  Json huge;
  CHECK(Json::Parse(
      "{\"inf\":1e999,\"big\":1e300,\"small\":-1e300,\"edge\":9007199254740992}", huge));
  CHECK(!huge.GetInt("inf").has_value());
  CHECK(!huge.GetInt("big").has_value());
  CHECK(!huge.GetInt("small").has_value());
  CHECK(huge.GetInt("edge").value_or(0) == 9007199254740992LL);
  Json hostile_huge;
  CHECK(Json::Parse("{\"error\":{\"attempts_remaining\":1e300}}", hostile_huge));
  CHECK(AttemptsRemainingFrom(*hostile_huge.Find("error")) == -1);

  Json escapes;
  CHECK(Json::Parse("{\"s\":\"a\\\"b\\\\c\\u0041\"}", escapes));
  CHECK(escapes.GetString("s").value_or("") == "a\"b\\cA");

  /*
   * Booleans are emitted unquoted.
   *
   * ⚠️ `"signOutOfOtherSessions":"false"` IS A NON-EMPTY STRING, WHICH IS
   * TRUTHY IN MOST PARSERS. Getting this wrong would not fail loudly — it would
   * quietly mean the opposite of what the caller asked, on the one flag that
   * decides whether a password change kicks out a session somebody else may be
   * holding.
   */
  std::map<std::string, std::string> fields;
  fields["newPassword"] = "a-new-long-password";

  std::map<std::string, bool> flags;
  flags["signOutOfOtherSessions"] = false;

  Json mixed;
  CHECK(Json::Parse(Json::Serialize(fields, flags), mixed));
  CHECK(mixed.GetString("newPassword").value_or("") == "a-new-long-password");
  CHECK(!mixed.GetBool("signOutOfOtherSessions"));
  const Json* emitted = mixed.Find("signOutOfOtherSessions");
  CHECK(emitted != nullptr && !emitted->is_string());

  flags["signOutOfOtherSessions"] = true;
  Json on;
  CHECK(Json::Parse(Json::Serialize(fields, flags), on));
  CHECK(on.GetBool("signOutOfOtherSessions"));

  // Escaping still applies to the keys and to the string half.
  std::map<std::string, std::string> quoted;
  quoted["a\"b"] = "c\\d";
  Json round_trip;
  CHECK(Json::Parse(Json::Serialize(quoted, flags), round_trip));
  CHECK(round_trip.GetString("a\"b").value_or("") == "c\\d");
}

// ---------------------------------------------------------------------------
// The 202 that is not an error and is not a session
// ---------------------------------------------------------------------------

/*
 * ⚠️ THE OUTCOME EVERY SDK HERE GOT WRONG, WHICH IS WHY IT IS PARSED BY A PURE
 * FUNCTION AND TESTED WITHOUT A NETWORK.
 *
 * `POST /sign-in` and `POST /mfa/verify` can answer 202 with
 * `{"status":"password_update_required","token":...}`: the password was
 * CORRECT and is no longer acceptable. A transport that reads any 2xx as
 * success falls through to fetching an identity, finds no session, and reports
 * NOT SIGNED IN — an unexplained sign-out at the moment the right screen is
 * "choose a new password", with the reset token discarded.
 */
void TestPasswordUpdate() {
  Section("password update");

  using grantry::internal::PasswordUpdate;
  using grantry::internal::PasswordUpdateFrom;

  // The sign-in shape: a token AND the reasons.
  Json refused;
  CHECK(Json::Parse(
      "{\"status\":\"password_update_required\",\"token\":\"vt_abc\","
      "\"reasons\":[\"too_short\",\"breached\"]}",
      refused));
  PasswordUpdate update;
  CHECK(PasswordUpdateFrom(refused, update));
  CHECK(update.token == "vt_abc");
  CHECK(update.breached);

  /*
   * The MFA shape: the same status and token, and NO reasons at all. The
   * verdict is decided at sign-in and only a boolean rides on the challenge, so
   * an application that rendered the list would state the requirements on one
   * path and nothing on the other — which is why the requirement list comes
   * from Environment::password_policy and only "breached" is lifted out.
   */
  Json after_factor;
  CHECK(Json::Parse(
      "{\"status\":\"password_update_required\",\"token\":\"vt_xyz\"}",
      after_factor));
  PasswordUpdate second;
  CHECK(PasswordUpdateFrom(after_factor, second));
  CHECK(second.token == "vt_xyz");
  // False here means "not said", NOT "not breached". Announcing a breach the
  // server never mentioned would be alarming and wrong; silence leaves the
  // ordinary requirement list, which applies either way.
  CHECK(!second.breached);

  // Reasons that are not "breached" leave the flag alone rather than setting it
  // on any refusal at all.
  Json policy_only;
  CHECK(Json::Parse(
      "{\"status\":\"password_update_required\",\"token\":\"vt_1\","
      "\"reasons\":[\"needs_symbol\",\"too_weak\"]}",
      policy_only));
  PasswordUpdate third;
  CHECK(PasswordUpdateFrom(policy_only, third));
  CHECK(!third.breached);

  /*
   * ⚠️ THE STATUS WITHOUT A TOKEN IS NOT THIS OUTCOME. There would be nothing
   * to redeem, so an application put on a new-password screen would have
   * nothing to send when the user pressed the button. Refusing it here sends
   * the body down the ordinary path, where the absent session is caught.
   */
  Json tokenless;
  CHECK(Json::Parse("{\"status\":\"password_update_required\"}", tokenless));
  PasswordUpdate none;
  CHECK(!PasswordUpdateFrom(tokenless, none));

  Json empty_token;
  CHECK(Json::Parse(
      "{\"status\":\"password_update_required\",\"token\":\"\"}", empty_token));
  CHECK(!PasswordUpdateFrom(empty_token, none));

  // An ordinary sign-in, and the two sign-up outcomes, are not this. A parser
  // that matched on the token alone would swallow every one of them.
  Json session;
  CHECK(Json::Parse("{\"user\":{\"id\":\"usr_1\"},\"token\":\"nope\"}", session));
  CHECK(!PasswordUpdateFrom(session, none));

  Json waitlisted;
  CHECK(Json::Parse("{\"status\":\"waitlisted\",\"token\":\"nope\"}", waitlisted));
  CHECK(!PasswordUpdateFrom(waitlisted, none));

  // A status of the wrong type is not the string, and neither is a near miss.
  Json numeric;
  CHECK(Json::Parse("{\"status\":202,\"token\":\"vt_2\"}", numeric));
  CHECK(!PasswordUpdateFrom(numeric, none));

  Json misspelt;
  CHECK(Json::Parse(
      "{\"status\":\"password_update\",\"token\":\"vt_3\"}", misspelt));
  CHECK(!PasswordUpdateFrom(misspelt, none));

  /*
   * The success body of the same route, which carries the one fact that is
   * otherwise invisible: how many ways back into the account are left.
   *
   * ⚠️ ABSENT IS -1 AND NOT 0, because zero is a real answer meaning "that was
   * your last recovery code" — a sentence worth putting on screen — and every
   * other sign-in path reports nothing at all.
   */
  using grantry::internal::BackupCodesRemainingFrom;

  Json verified;
  CHECK(Json::Parse("{\"backupCodesRemaining\":7}", verified));
  CHECK(BackupCodesRemainingFrom(verified) == 7);

  Json exhausted;
  CHECK(Json::Parse("{\"backupCodesRemaining\":0}", exhausted));
  CHECK(BackupCodesRemainingFrom(exhausted) == 0);

  // Every path but a completed MFA verify — including the sign-in that has
  // just been refused above.
  CHECK(BackupCodesRemainingFrom(session) == -1);
  CHECK(BackupCodesRemainingFrom(refused) == -1);

  // Nonsense from an unsigned body means silence rather than a screen
  // promising ninety-nine billion recovery codes.
  Json negative;
  CHECK(Json::Parse("{\"backupCodesRemaining\":-3}", negative));
  CHECK(BackupCodesRemainingFrom(negative) == -1);

  Json vast;
  CHECK(Json::Parse("{\"backupCodesRemaining\":99999999999}", vast));
  CHECK(BackupCodesRemainingFrom(vast) == -1);

  Json textual;
  CHECK(Json::Parse("{\"backupCodesRemaining\":\"7\"}", textual));
  CHECK(BackupCodesRemainingFrom(textual) == -1);
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

struct Harness {
  TestKey real;
  TestKey rogue;
  std::string kid = "test-key-1";
  bool serve_rogue = false;
  int fetches = 0;

  JwksCache MakeCache(std::vector<std::string> pins = {}) {
    return JwksCache(
        [this](std::string& body, std::string&) {
          fetches++;
          body = Jwks(serve_rogue ? rogue : real, kid);
          return true;
        },
        3600, std::move(pins));
  }
};

void TestVerification() {
  Section("verification");

  const std::string nonce = "a-nonce-that-is-long-enough-to-be-real";

  {
    // The happy path.
    Harness harness;
    JwksCache cache = harness.MakeCache();
    TokenVerifier verifier(&cache, kIssuer, 30, {});

    TokenSpec spec;
    spec.kid = harness.kid;
    spec.nonce = nonce;
    spec.extra_claims = "\"pln\":\"pro\",\"fea\":[\"pro_export\"]";

    Result<Identity> result = verifier.Verify(Mint(harness.real, spec), kEnvironment, nonce);
    CHECK(result.ok());
    if (result.ok()) {
      CHECK(result->user_id() == kUser);
      CHECK(result->environment_id() == kEnvironment);
      CHECK(result->plan_key().value_or("") == "pro");

      /*
       * ⚠️ THE OLDEST LICENSING BYPASS THERE IS, CLOSED. A trial that
       * expires by time(nullptr) expires whenever the user says it does:
       * winding the system clock back costs nothing and needs no tooling.
       *
       * `iat` rides inside the signature just verified against the server's
       * key, so it cannot be moved without breaking that signature. This
       * asserts it survives verification rather than being dropped, which is
       * what it was doing.
       */
      CHECK(result->server_time() > 0);
      CHECK(result->server_time() < result->expires_at());
      CHECK(result->has_feature("pro_export"));
      CHECK(!result->has_feature("something_else"));

      // One plan and no `pls`: the plan is the whole list.
      CHECK(result->plan_keys().size() == 1);
      CHECK(result->has_plan("pro"));
      CHECK(!result->has_plan("spoofer"));
    }
  }

  {
    // Several products held at once, as an application selling one-time purchases allows.
    Harness harness;
    JwksCache cache = harness.MakeCache();
    TokenVerifier verifier(&cache, kIssuer, 30, {});

    TokenSpec spec;
    spec.kid = harness.kid;
    spec.nonce = nonce;
    spec.extra_claims = "\"pln\":\"pro\",\"fea\":[],\"pls\":[\"pro\",\"spoofer\"]";

    Result<Identity> result = verifier.Verify(Mint(harness.real, spec), kEnvironment, nonce);
    CHECK(result.ok());
    if (result.ok()) {
      CHECK(result->plan_key().value_or("") == "pro");
      CHECK(result->plan_keys().size() == 2);
      CHECK(result->has_plan("spoofer"));
      CHECK(!result->has_plan("loader"));
    }
  }

  {
    /*
     * ⚠️ A RESPONSE SIGNED BY A KEY THE ATTACKER CONTROLS.
     *
     * The shape of every "spoofed response" attack that does not involve
     * patching: intercept the reply and substitute one of your own. It fails on
     * the signature, which is the property the whole library rests on.
     */
    Harness harness;
    JwksCache cache = harness.MakeCache();
    TokenVerifier verifier(&cache, kIssuer, 30, {});

    TokenSpec spec;
    spec.kid = harness.kid;
    spec.nonce = nonce;

    Result<Identity> result = verifier.Verify(Mint(harness.rogue, spec), kEnvironment, nonce);
    CHECK(!result.ok());
    CHECK(result.error.verification == VerificationFailure::kBadSignature);
  }

  {
    /*
     * ⚠️ THE REPLAY. This token is signed by the real key, has the right issuer
     * and audience, and has not expired — every check except one passes, because
     * every other claim describes the SESSION rather than the request. One
     * recording from a paying subscriber would otherwise unlock every cracked
     * copy of an application.
     */
    Harness harness;
    JwksCache cache = harness.MakeCache();
    TokenVerifier verifier(&cache, kIssuer, 30, {});

    TokenSpec spec;
    spec.kid = harness.kid;
    spec.nonce = "a-nonce-from-somebody-elses-request";

    Result<Identity> result = verifier.Verify(Mint(harness.real, spec), kEnvironment, nonce);
    CHECK(!result.ok());
    CHECK(result.error.verification == VerificationFailure::kReplayedNonce);
  }

  {
    // No nonce at all. A server that saw this request would have echoed it.
    Harness harness;
    JwksCache cache = harness.MakeCache();
    TokenVerifier verifier(&cache, kIssuer, 30, {});

    TokenSpec spec;
    spec.kid = harness.kid;
    spec.include_nonce = false;

    Result<Identity> result = verifier.Verify(Mint(harness.real, spec), kEnvironment, nonce);
    CHECK(!result.ok());
    CHECK(result.error.verification == VerificationFailure::kReplayedNonce);
  }

  {
    // A token minted for a different application on the same instance. Its
    // signature is genuinely valid; the audience is the only thing separating a
    // customer's free demo from their paid product.
    Harness harness;
    JwksCache cache = harness.MakeCache();
    TokenVerifier verifier(&cache, kIssuer, 30, {});

    TokenSpec spec;
    spec.kid = harness.kid;
    spec.nonce = nonce;
    spec.audience = "env_someone_elses_app";

    Result<Identity> result = verifier.Verify(Mint(harness.real, spec), kEnvironment, nonce);
    CHECK(!result.ok());
    CHECK(result.error.verification == VerificationFailure::kWrongAudience);
  }

  {
    Harness harness;
    JwksCache cache = harness.MakeCache();
    TokenVerifier verifier(&cache, kIssuer, 30, {});

    TokenSpec spec;
    spec.kid = harness.kid;
    spec.nonce = nonce;
    spec.issuer = "https://not-grantry.example";

    Result<Identity> result = verifier.Verify(Mint(harness.real, spec), kEnvironment, nonce);
    CHECK(!result.ok());
    CHECK(result.error.verification == VerificationFailure::kWrongIssuer);
  }

  {
    Harness harness;
    JwksCache cache = harness.MakeCache();
    TokenVerifier verifier(&cache, kIssuer, 30, {});

    TokenSpec spec;
    spec.kid = harness.kid;
    spec.nonce = nonce;
    spec.expires_in = -600;

    Result<Identity> result = verifier.Verify(Mint(harness.real, spec), kEnvironment, nonce);
    CHECK(!result.ok());
    CHECK(result.error.verification == VerificationFailure::kExpired);
  }

  {
    /*
     * A token that claims to live for a week.
     *
     * ⚠️ THE ENTITLEMENT-REVOCATION BYPASS, AND IT VERIFIES PERFECTLY
     * OTHERWISE. Real signature, right issuer, right audience, nonce echoed
     * back. Every check passes except the one asking how long it claims to
     * live — and without that check the client caches the plan and features
     * until the stated expiry, so a cancelled subscription keeps working for as
     * long as the token says. The short TTL IS the revocation mechanism.
     */
    Harness harness;
    JwksCache cache = harness.MakeCache();
    TokenVerifier verifier(&cache, kIssuer, 30, {});

    TokenSpec spec;
    spec.kid = harness.kid;
    spec.nonce = nonce;
    spec.expires_in = 7 * 24 * 60 * 60;

    Result<Identity> result = verifier.Verify(Mint(harness.real, spec), kEnvironment, nonce);
    CHECK(!result.ok());
    CHECK(result.error.verification == VerificationFailure::kLifetimeTooLong);
  }

  {
    // A generous but sane token still works: the ceiling has to leave room to
    // lengthen the real TTL without shipping new clients.
    Harness harness;
    JwksCache cache = harness.MakeCache();
    TokenVerifier verifier(&cache, kIssuer, 30, {});

    TokenSpec spec;
    spec.kid = harness.kid;
    spec.nonce = nonce;
    spec.expires_in = 10 * 60;

    Result<Identity> result = verifier.Verify(Mint(harness.real, spec), kEnvironment, nonce);
    CHECK(result.ok());
  }

  {
    // `alg: none` — no signature at all.
    Harness harness;
    JwksCache cache = harness.MakeCache();
    TokenVerifier verifier(&cache, kIssuer, 30, {});

    TokenSpec spec;
    spec.kid = harness.kid;
    spec.nonce = nonce;
    spec.algorithm = "none";

    Result<Identity> result = verifier.Verify(Mint(harness.real, spec), kEnvironment, nonce);
    CHECK(!result.ok());
    // ⚠️ AND THE REASON IS THE ALGORITHM, not "malformed base64" — which is what
    // a verifier that decoded all three segments before checking policy would
    // report. The operator reading the log needs to know an UNSIGNED token
    // arrived, not that some base64 was odd.
    CHECK(result.error.verification == VerificationFailure::kUnexpectedAlgorithm);
  }

  {
    // The algorithm-confusion attack. `HS256` here would be keyed with the
    // public key the attacker downloaded a moment earlier; a verifier that read
    // the algorithm from the header would do the same computation and agree.
    Harness harness;
    JwksCache cache = harness.MakeCache();
    TokenVerifier verifier(&cache, kIssuer, 30, {});

    TokenSpec spec;
    spec.kid = harness.kid;
    spec.nonce = nonce;
    spec.algorithm = "HS256";

    Result<Identity> result = verifier.Verify(Mint(harness.real, spec), kEnvironment, nonce);
    CHECK(!result.ok());
    CHECK(result.error.verification == VerificationFailure::kUnexpectedAlgorithm);
  }

  {
    // An unknown key id.
    Harness harness;
    JwksCache cache = harness.MakeCache();
    TokenVerifier verifier(&cache, kIssuer, 30, {});

    TokenSpec spec;
    spec.kid = "a-key-that-was-never-published";
    spec.nonce = nonce;

    Result<Identity> result = verifier.Verify(Mint(harness.real, spec), kEnvironment, nonce);
    CHECK(!result.ok());
    CHECK(result.error.verification == VerificationFailure::kUnknownKey);
  }

  {
    /*
     * The attacker serves their own JWKS as well as their own token.
     *
     * ⚠️ WITHOUT PINNING THIS SUCCEEDS, and the test says so rather than
     * pretending otherwise. Somebody who can serve the JWKS over a certificate
     * the machine trusts has replaced the root of trust, and no client logic
     * recovers from that.
     */
    Harness harness;
    harness.serve_rogue = true;
    JwksCache cache = harness.MakeCache();
    TokenVerifier verifier(&cache, kIssuer, 30, {});

    TokenSpec spec;
    spec.kid = harness.kid;
    spec.nonce = nonce;

    Result<Identity> result = verifier.Verify(Mint(harness.rogue, spec), kEnvironment, nonce);
    CHECK(result.ok());
  }

  {
    // …and pinning is what closes it.
    Harness harness;
    harness.serve_rogue = true;
    std::string pin = harness.real.thumbprint();

    JwksCache cache = harness.MakeCache({pin});
    TokenVerifier verifier(&cache, kIssuer, 30, {pin});

    TokenSpec spec;
    spec.kid = harness.kid;
    spec.nonce = nonce;

    Result<Identity> result = verifier.Verify(Mint(harness.rogue, spec), kEnvironment, nonce);
    CHECK(!result.ok());
    // The rogue key never enters the cache, so the `kid` resolves to nothing.
    CHECK(result.error.verification == VerificationFailure::kUnknownKey);
  }

  {
    // Malformed input, in the shapes a fuzzer finds first.
    Harness harness;
    JwksCache cache = harness.MakeCache();
    TokenVerifier verifier(&cache, kIssuer, 30, {});

    const char* garbage[] = {"", ".", "..", "a.b", "a.b.c.d", "!!!.???.###"};
    for (const char* token : garbage) {
      Result<Identity> result = verifier.Verify(token, kEnvironment, nonce);
      CHECK(!result.ok());
      CHECK(result.error.kind == grantry::ErrorKind::kVerification);
    }
  }

  {
    /*
     * ⚠️ THE REFRESH FLOOR. An unknown `kid` is entirely attacker-controlled, so
     * without a floor a flood of forged tokens is a way to make a desktop client
     * hammer the API on command. One fetch per minute, not one per token.
     */
    Harness harness;
    JwksCache cache = harness.MakeCache();
    TokenVerifier verifier(&cache, kIssuer, 30, {});

    TokenSpec spec;
    spec.nonce = nonce;
    for (int i = 0; i < 25; i++) {
      spec.kid = "forged-kid-" + std::to_string(i);
      verifier.Verify(Mint(harness.real, spec), kEnvironment, nonce);
    }

    CHECK(harness.fetches == 1);
  }
}

// ---------------------------------------------------------------------------
// Device anchor
// ---------------------------------------------------------------------------

/*
 * ⚠️ THESE ARE ABOUT FORGERY, NOT SECRECY. Nothing here claims a value is
 * hidden from the person running the binary — it cannot be, they own the
 * memory, and a test asserting otherwise would be asserting a lie. Every case
 * below is a substitution, a transplant or a replay: the things an interception
 * proxy makes trivial and the signature makes impossible.
 */
void TestSignedResources() {
  Section("signed resources");

  const std::string nonce = "a-nonce-that-is-long-enough-to-be-real";
  const std::string digest =
      Base64UrlEncode(Sha256(std::string("pro")));

  auto Envelope = [&](Harness& harness, const std::string& kind, const std::string& key,
                      const std::string& dig, TokenSpec spec) {
    spec.kid = harness.kid;
    spec.subject = spec.subject.empty() ? std::string(kUser) : spec.subject;
    spec.extra_claims = "\"kind\":\"" + kind + "\",\"key\":\"" + key
                      + "\",\"dig\":\"" + dig + "\"";
    return Mint(harness.real, spec);
  };

  auto Expected = [&](const std::string& kind, const std::string& key,
                      const std::string& dig, const std::string& subject) {
    TokenVerifier::ResourceExpectation expected;
    expected.audience = kEnvironment;
    expected.nonce = nonce;
    expected.kind = kind;
    expected.key = key;
    expected.digest = dig;
    expected.subject = subject;
    return expected;
  };

  {
    // The happy path, and the shape everything below deviates from.
    Harness harness;
    JwksCache cache = harness.MakeCache();
    TokenVerifier verifier(&cache, kIssuer, 30, {});

    TokenSpec spec;
    spec.nonce = nonce;
    const std::string envelope = Envelope(harness, "variable", "tier", digest, spec);

    CHECK(verifier.VerifyResource(envelope, Expected("variable", "tier", digest, kUser)).ok());

    // The subject check is skipped, not failed, when the SDK has not yet
    // verified an identity to compare against.
    CHECK(verifier.VerifyResource(envelope, Expected("variable", "tier", digest, "")).ok());
  }

  {
    /*
     * ⚠️ THE ATTACK THIS WHOLE MECHANISM EXISTS FOR: a genuine, current,
     * correctly-signed envelope delivered next to a value somebody swapped in a
     * proxy. Before signing, that was the entire attack — open HTTPToolkit,
     * change "free" to "lifetime", done, no understanding of anything required.
     */
    Harness harness;
    JwksCache cache = harness.MakeCache();
    TokenVerifier verifier(&cache, kIssuer, 30, {});

    TokenSpec spec;
    spec.nonce = nonce;
    const std::string envelope = Envelope(harness, "variable", "tier", digest, spec);

    const std::string substituted = Base64UrlEncode(Sha256(std::string("lifetime")));
    grantry::Status refused =
        verifier.VerifyResource(envelope, Expected("variable", "tier", substituted, kUser));
    CHECK(!refused.ok());
    CHECK(refused.error.verification == VerificationFailure::kContentMismatch);
  }

  {
    /*
     * ⚠️ A SIGNATURE ONLY SPEAKS ABOUT THE RESOURCE IT NAMES. Without this,
     * one valid envelope for a harmless public variable could be pasted onto
     * every gated one, and the scheme would degrade to "some value, somewhere,
     * was signed once".
     */
    Harness harness;
    JwksCache cache = harness.MakeCache();
    TokenVerifier verifier(&cache, kIssuer, 30, {});

    TokenSpec spec;
    spec.nonce = nonce;

    const std::string other_key = Envelope(harness, "variable", "motd", digest, spec);
    grantry::Status a =
        verifier.VerifyResource(other_key, Expected("variable", "tier", digest, kUser));
    CHECK(!a.ok());
    CHECK(a.error.verification == VerificationFailure::kWrongResource);

    const std::string other_kind = Envelope(harness, "file", "tier", digest, spec);
    grantry::Status b =
        verifier.VerifyResource(other_kind, Expected("variable", "tier", digest, kUser));
    CHECK(!b.ok());
    CHECK(b.error.verification == VerificationFailure::kWrongResource);
  }

  {
    // ⚠️ AN ENVELOPE DOES NOT TRANSFER BETWEEN ACCOUNTS. This is what stops a
    // free user replaying a colleague's paid read.
    Harness harness;
    JwksCache cache = harness.MakeCache();
    TokenVerifier verifier(&cache, kIssuer, 30, {});

    TokenSpec spec;
    spec.nonce = nonce;
    spec.subject = "usr_somebody_else";

    grantry::Status refused = verifier.VerifyResource(
        Envelope(harness, "variable", "tier", digest, spec),
        Expected("variable", "tier", digest, kUser));
    CHECK(!refused.ok());
    CHECK(refused.error.verification == VerificationFailure::kWrongResource);
  }

  {
    // ⚠️ EVERY ENVIRONMENT ON AN INSTANCE SHARES ONE SIGNING KEY, so a valid
    // signature says nothing about WHICH application asked. The audience does.
    Harness harness;
    JwksCache cache = harness.MakeCache();
    TokenVerifier verifier(&cache, kIssuer, 30, {});

    TokenSpec spec;
    spec.nonce = nonce;
    spec.audience = "env_somebody_elses_app";

    grantry::Status refused = verifier.VerifyResource(
        Envelope(harness, "variable", "tier", digest, spec),
        Expected("variable", "tier", digest, kUser));
    CHECK(!refused.ok());
    CHECK(refused.error.verification == VerificationFailure::kWrongAudience);
  }

  {
    // A recording carries somebody else's nonce, or none at all. Both are
    // replays: the server ignores a malformed nonce rather than rejecting it,
    // so an omission has to be the client's failure.
    Harness harness;
    JwksCache cache = harness.MakeCache();
    TokenVerifier verifier(&cache, kIssuer, 30, {});

    TokenSpec stale;
    stale.nonce = "a-nonce-from-somebody-elses-request";
    grantry::Status a = verifier.VerifyResource(
        Envelope(harness, "variable", "tier", digest, stale),
        Expected("variable", "tier", digest, kUser));
    CHECK(!a.ok());
    CHECK(a.error.verification == VerificationFailure::kReplayedNonce);

    TokenSpec absent;
    absent.nonce = nonce;
    absent.include_nonce = false;
    grantry::Status b = verifier.VerifyResource(
        Envelope(harness, "variable", "tier", digest, absent),
        Expected("variable", "tier", digest, kUser));
    CHECK(!b.ok());
    CHECK(b.error.verification == VerificationFailure::kReplayedNonce);
  }

  {
    // The signature is checked the same way an access token's is, so the
    // algorithm-confusion and rogue-key defences apply here too.
    Harness harness;
    JwksCache cache = harness.MakeCache();
    TokenVerifier verifier(&cache, kIssuer, 30, {});

    TokenSpec spec;
    spec.nonce = nonce;
    spec.kid = harness.kid;
    spec.extra_claims = "\"kind\":\"variable\",\"key\":\"tier\",\"dig\":\""
                      + digest + "\"";

    grantry::Status rogue = verifier.VerifyResource(
        Mint(harness.rogue, spec), Expected("variable", "tier", digest, kUser));
    CHECK(!rogue.ok());
    CHECK(rogue.error.verification == VerificationFailure::kBadSignature);

    TokenSpec unsigned_spec = spec;
    unsigned_spec.algorithm = "none";
    grantry::Status none = verifier.VerifyResource(
        Mint(harness.real, unsigned_spec), Expected("variable", "tier", digest, kUser));
    CHECK(!none.ok());
    CHECK(none.error.verification == VerificationFailure::kUnexpectedAlgorithm);
  }

  {
    /*
     * ⚠️ THE CEILING IS TIGHTER THAN AN ACCESS TOKEN'S, AND THIS IS WHAT
     * PROVES IT. Ten minutes is a lifetime a token would be allowed; an
     * envelope is a statement about what one value was at one moment, and one
     * good for ten minutes is a cache the merchant never asked for and cannot
     * clear.
     */
    Harness harness;
    JwksCache cache = harness.MakeCache();
    TokenVerifier verifier(&cache, kIssuer, 30, {});

    TokenSpec spec;
    spec.nonce = nonce;
    spec.expires_in = 10 * 60;

    grantry::Status refused = verifier.VerifyResource(
        Envelope(harness, "variable", "tier", digest, spec),
        Expected("variable", "tier", digest, kUser));
    CHECK(!refused.ok());
    CHECK(refused.error.verification == VerificationFailure::kLifetimeTooLong);

    // The same envelope is inside an access token's ceiling, so this really is
    // the resource rule and not a shared one.
    TokenSpec token = spec;
    token.kid = harness.kid;
    CHECK(verifier.Verify(Mint(harness.real, token), kEnvironment, nonce).ok());
  }
}

void TestDeviceAnchor() {
  Section("device anchor");

  std::string anchor = grantry::internal::ReadMachineAnchor();

  /*
   * ⚠️ THE RAW ANCHOR MUST NEVER BE WHAT IS SENT. On Windows it is the machine
   * SID in its readable `S-1-5-21-...` form — the customer's hardware identity,
   * and nobody's business at the API.
   */
  if (!anchor.empty()) {
    std::string hashed = grantry::internal::Base64UrlEncode(
        grantry::internal::Sha256(anchor + static_cast<char>(0x1f) + kEnvironment));

    CHECK(hashed != anchor);
    CHECK(hashed.find("S-1-5") == std::string::npos);
    CHECK(hashed.size() == 43);  // SHA-256, base64url, unpadded

    // Stable for one environment…
    std::string again = grantry::internal::Base64UrlEncode(
        grantry::internal::Sha256(anchor + static_cast<char>(0x1f) + kEnvironment));
    CHECK(hashed == again);

    // …and different for another, so one merchant cannot recognise another's
    // customers from a hash they hold.
    std::string elsewhere = grantry::internal::Base64UrlEncode(
        grantry::internal::Sha256(anchor + static_cast<char>(0x1f) + "env_different"));
    CHECK(hashed != elsewhere);
  }

  CHECK(std::string(grantry::internal::PlatformName()).size() > 0);
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

void TestOptions() {
  Section("options");

  {
    /*
     * ⚠️ THE KEY CARRIES ITS OWN ENVIRONMENT, so there is nothing to
     * configure. The fixture is a real key from `packages/shared/src/keys.ts`,
     * which is what mints them - a decoder tested only against its own encoder
     * agrees with itself and with nothing that ships.
     */
    grantry::Options options;
    // No start-up probe: these cases are about construction, not about
    // reaching a network that is not there.
    options.connect_on_start = false;
    options.publishable_key =
        "pk_test_ZW52XzRKZ2dkNHd6ZkM2OEVzc0tEYXM5bkJFcA_201cac9f982c4a70b060eb5ac7ee990d";
    options.api_base_url = "https://api.example.test";
    options.session_store = grantry::MakeInMemorySessionStore();

    Result<std::shared_ptr<grantry::Client>> result = grantry::Client::Create(options);
    CHECK(result.ok());
    if (result.ok()) {
      CHECK((*result)->environment_id() == "env_4Jggd4wzfC68EssKDas9nBEp");
    }
  }

  {
    // The key wins over a supplied value: it is what actually authenticates.
    grantry::Options options;
    // No start-up probe: these cases are about construction, not about
    // reaching a network that is not there.
    options.connect_on_start = false;
    options.publishable_key =
        "pk_test_ZW52XzRKZ2dkNHd6ZkM2OEVzc0tEYXM5bkJFcA_201cac9f982c4a70b060eb5ac7ee990d";
    options.environment_id = "env_somethingelse";
    options.api_base_url = "https://api.example.test";
    options.session_store = grantry::MakeInMemorySessionStore();

    Result<std::shared_ptr<grantry::Client>> result = grantry::Client::Create(options);
    CHECK(result.ok());
    if (result.ok()) {
      CHECK((*result)->environment_id() == "env_4Jggd4wzfC68EssKDas9nBEp");
    }
  }

  {
    // An older key still works, and still has to be told.
    grantry::Options options;
    // No start-up probe: these cases are about construction, not about
    // reaching a network that is not there.
    options.connect_on_start = false;
    options.publishable_key = "pk_test_abcdefghijklmnopqrstuvwxyz012345";
    options.api_base_url = "https://api.example.test";
    options.session_store = grantry::MakeInMemorySessionStore();

    Result<std::shared_ptr<grantry::Client>> result = grantry::Client::Create(options);
    CHECK(!result.ok());
    CHECK(result.error.message.find("does not carry its environment") != std::string::npos);
  }

  {
    /*
     * ⚠️ `pk_test_YWJj_abc` DECODES CLEANLY TO "abc", which is not an
     * environment. Without the `env_` prefix check it would be accepted, then
     * compared against every token's audience, refusing all of them.
     */
    grantry::Options options;
    // No start-up probe: these cases are about construction, not about
    // reaching a network that is not there.
    options.connect_on_start = false;
    options.publishable_key = "pk_test_YWJj_abcdefghijklmnop";
    options.environment_id = kEnvironment;
    options.api_base_url = "https://api.example.test";
    options.session_store = grantry::MakeInMemorySessionStore();

    Result<std::shared_ptr<grantry::Client>> result = grantry::Client::Create(options);
    CHECK(result.ok());
    if (result.ok()) CHECK((*result)->environment_id() == kEnvironment);
  }

  {
    /*
     * ⚠️ THE CHECK THAT STOPS A FULL COMPROMISE SHIPPING. A secret key in a
     * desktop binary is the whole environment handed to anybody who runs
     * `strings` on the executable.
     */
    grantry::Options options;
    // No start-up probe: these cases are about construction, not about
    // reaching a network that is not there.
    options.connect_on_start = false;
    options.publishable_key = "sk_live_thisisasecretkey";
    options.environment_id = kEnvironment;
    options.environment_id = kEnvironment;
    options.api_base_url = "https://api.example.test";
    options.session_store = grantry::MakeInMemorySessionStore();

    Result<std::shared_ptr<grantry::Client>> result = grantry::Client::Create(options);
    CHECK(!result.ok());
    CHECK(result.error.kind == grantry::ErrorKind::kConfiguration);
    CHECK(result.error.message.find("never be used in a native application")
          != std::string::npos);
  }

  {
    grantry::Options options;
    // No start-up probe: these cases are about construction, not about
    // reaching a network that is not there.
    options.connect_on_start = false;
    options.publishable_key = "pk_test_abcdefghijklmnop";
    options.environment_id = kEnvironment;
    options.api_base_url = "http://api.example.test";
    options.session_store = grantry::MakeInMemorySessionStore();

    Result<std::shared_ptr<grantry::Client>> result = grantry::Client::Create(options);
    CHECK(!result.ok());
    CHECK(result.error.kind == grantry::ErrorKind::kConfiguration);
  }

  {
    // Loopback needs an explicit opt-in, and then works.
    grantry::Options options;
    // No start-up probe: these cases are about construction, not about
    // reaching a network that is not there.
    options.connect_on_start = false;
    options.publishable_key = "pk_test_abcdefghijklmnop";
    options.environment_id = kEnvironment;
    options.api_base_url = "http://localhost:3102";
    options.session_store = grantry::MakeInMemorySessionStore();

    CHECK(!grantry::Client::Create(options).ok());

    options.allow_insecure_loopback = true;
    options.session_store = grantry::MakeInMemorySessionStore();
    Result<std::shared_ptr<grantry::Client>> result = grantry::Client::Create(options);
    CHECK(result.ok());
    if (result.ok()) CHECK(!(*result)->has_session());
  }

  {
    /*
     * ⚠️ LOOPBACK IS AN ADDRESS, NOT A PREFIX (12 October 2026). "Begins `127.`"
     * let `127.attacker.example` — a name anybody can register — through over
     * plain HTTP, and `127.0.0.1@host` is a request to `host`. Both are refused
     * now, with the opt-in set; and `[::1]`, which the old parse could never
     * read, is admitted.
     */
    auto created = [](const std::string& url) {
      grantry::Options options;
      options.connect_on_start = false;
      options.publishable_key = "pk_test_abcdefghijklmnop";
      options.environment_id = kEnvironment;
      options.api_base_url = url;
      options.allow_insecure_loopback = true;
      options.session_store = grantry::MakeInMemorySessionStore();
      return grantry::Client::Create(options).ok();
    };
    CHECK(!created("http://127.attacker.example"));
    CHECK(!created("http://127.0.0.1.attacker.example:3102"));
    CHECK(!created("http://127.0.0.1@api.example.test"));
    CHECK(!created("http://localhost@api.example.test/"));
    CHECK(!created("http://1270.0.0.1"));
    CHECK(!created("http://127.0.0.256"));
    CHECK(created("http://127.0.0.1:3102"));
    CHECK(created("http://127.4.5.6"));
    CHECK(created("http://LOCALHOST:3102/"));
    CHECK(created("http://[::1]:3102"));

    // And no API address carries a user name, over HTTPS either.
    CHECK(!created("https://user:pass@api.example.test"));
    CHECK(!created("https://api.grantry.dev@api.example.test"));
    CHECK(!created("not a url"));
  }

  {
    grantry::Options options;
    // No start-up probe: these cases are about construction, not about
    // reaching a network that is not there.
    options.connect_on_start = false;
    options.publishable_key = "pk_test_abcdefghijklmnop";
    options.environment_id = kEnvironment;
    options.api_base_url = "https://api.example.test";
    options.clock_skew_seconds = 3600;
    options.session_store = grantry::MakeInMemorySessionStore();

    CHECK(!grantry::Client::Create(options).ok());
  }
}



// ---------------------------------------------------------------------------
// A socket, so a request can be proved to arrive
// ---------------------------------------------------------------------------

/*
 * ⚠️ WITHOUT THIS THE CONNECT-ON-START TEST WOULD BE WORTHLESS, and worthless
 * in the way this repository keeps getting bitten by: it would assert that
 * creating a client does not crash, pass forever, and pass just as happily on
 * the day somebody deletes the line that sends the request. The C#, Python and
 * JavaScript suites can stub a transport; C++ has no seam to stub, so the
 * honest answer is a real socket on a real port.
 *
 * It is not an HTTP server. It accepts the connection and closes it, which is
 * all the assertion needs — the probe drops its answer anyway, so a client
 * that gets EOF has done everything this test cares about, and does it in
 * milliseconds rather than waiting out a timeout.
 */
class LoopbackListener {
 public:
  LoopbackListener() {
#ifdef _WIN32
    WSADATA data;
    WSAStartup(MAKEWORD(2, 2), &data);
#endif
    socket_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (!Valid(socket_)) return;

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;  // Any free port; asked for below.

    if (::bind(socket_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) return;
    if (::listen(socket_, 8) != 0) return;

#ifdef _WIN32
    int length = sizeof(address);
#else
    socklen_t length = sizeof(address);
#endif
    if (::getsockname(socket_, reinterpret_cast<sockaddr*>(&address), &length) != 0) return;
    port_ = ntohs(address.sin_port);
  }

  ~LoopbackListener() {
    if (Valid(socket_)) Close(socket_);
#ifdef _WIN32
    WSACleanup();
#endif
  }

  LoopbackListener(const LoopbackListener&) = delete;
  LoopbackListener& operator=(const LoopbackListener&) = delete;

  bool ok() const { return port_ != 0; }

  std::string url() const {
    return "http://127.0.0.1:" + std::to_string(static_cast<int>(port_));
  }

  /// Accept everything that has arrived within `seconds`, and say how many.
  ///
  /// A wait rather than a sleep: it returns as soon as the connection lands, so
  /// the test is as slow as the code is and no slower. The timeout is a failure
  /// condition, not a schedule.
  int Accepted(int seconds) {
    int count = 0;
    for (int elapsed = 0; elapsed < seconds * 20; elapsed++) {
      fd_set readable;
      FD_ZERO(&readable);
      FD_SET(socket_, &readable);

      timeval timeout{};
      timeout.tv_sec = 0;
      timeout.tv_usec = 50 * 1000;

#ifdef _WIN32
      int ready = ::select(0, &readable, nullptr, nullptr, &timeout);
#else
      int ready = ::select(socket_ + 1, &readable, nullptr, nullptr, &timeout);
#endif
      if (ready > 0) {
        Socket accepted = ::accept(socket_, nullptr, nullptr);
        if (Valid(accepted)) {
          Close(accepted);
          count++;
          // Keep draining briefly: a second connection would be the bug where
          // one request is sent twice.
        }
      } else if (count > 0) {
        return count;
      }
    }
    return count;
  }

 private:
#ifdef _WIN32
  using Socket = SOCKET;
  static bool Valid(Socket s) { return s != INVALID_SOCKET; }
  static void Close(Socket s) { ::closesocket(s); }
  Socket socket_ = INVALID_SOCKET;
#else
  using Socket = int;
  static bool Valid(Socket s) { return s >= 0; }
  static void Close(Socket s) { ::close(s); }
  Socket socket_ = -1;
#endif
  unsigned short port_ = 0;
};

// ---------------------------------------------------------------------------
// An HTTP answer, so what a request carried can be read back
// ---------------------------------------------------------------------------

/*
 * ⚠️ THE LISTENER ABOVE PROVES A REQUEST ARRIVES; THIS PROVES WHAT IT SAID.
 * StartSso read a field the route has never sent, and this suite could not have
 * seen it: with no transport to stub, no request's path or body and no answer's
 * handling was observable here. This answers every request with one canned
 * response and keeps the method, path, headers and body of each.
 *
 * Deliberately not a server: one request per connection, answered with
 * `Connection: close`, bodies by Content-Length only — which is all either
 * platform's transport sends for a JSON call.
 */
class CannedHttpServer {
 public:
  struct Received {
    std::string method;
    std::string path;
    /// Lower-cased names.
    std::map<std::string, std::string> headers;
    std::string body;
  };

  /// What one request is answered with.
  struct Reply {
    int status = 200;
    std::string body;
    /// Sent beside Content-Type and Content-Length: a session header, say.
    std::map<std::string, std::string> headers;
  };

  /// Decides each answer. Runs on the server's thread, one request at a time.
  using Handler = std::function<Reply(const Received&)>;

  CannedHttpServer(int status, std::string body)
      : CannedHttpServer([status, body](const Received&) {
          Reply reply;
          reply.status = status;
          reply.body = body;
          return reply;
        }) {}

  /// A server that routes: the fake API a redirect sign-in talks to.
  explicit CannedHttpServer(Handler handler) : handler_(std::move(handler)) {
#ifdef _WIN32
    WSADATA data;
    WSAStartup(MAKEWORD(2, 2), &data);
#endif
    socket_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (!Valid(socket_)) return;

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;

    if (::bind(socket_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) return;
    if (::listen(socket_, 8) != 0) return;

#ifdef _WIN32
    int length = sizeof(address);
#else
    socklen_t length = sizeof(address);
#endif
    if (::getsockname(socket_, reinterpret_cast<sockaddr*>(&address), &length) != 0) return;
    port_ = ntohs(address.sin_port);
    thread_ = std::thread([this] { Serve(); });
  }

  ~CannedHttpServer() {
    stop_ = true;
    if (thread_.joinable()) thread_.join();
    if (Valid(socket_)) Close(socket_);
#ifdef _WIN32
    WSACleanup();
#endif
  }

  CannedHttpServer(const CannedHttpServer&) = delete;
  CannedHttpServer& operator=(const CannedHttpServer&) = delete;

  bool ok() const { return port_ != 0; }

  std::string url() const {
    return "http://127.0.0.1:" + std::to_string(static_cast<int>(port_));
  }

  /// Every request answered so far, in order.
  std::vector<Received> received() {
    std::lock_guard<std::mutex> lock(mutex_);
    return received_;
  }

 private:
#ifdef _WIN32
  using Socket = SOCKET;
  static bool Valid(Socket s) { return s != INVALID_SOCKET; }
  static void Close(Socket s) { ::closesocket(s); }
  Socket socket_ = INVALID_SOCKET;
#else
  using Socket = int;
  static bool Valid(Socket s) { return s >= 0; }
  static void Close(Socket s) { ::close(s); }
  Socket socket_ = -1;
#endif

  /// Whether `s` has something to read within `milliseconds`.
  static bool Readable(Socket s, int milliseconds) {
    fd_set readable;
    FD_ZERO(&readable);
    FD_SET(s, &readable);

    timeval timeout{};
    timeout.tv_sec = milliseconds / 1000;
    timeout.tv_usec = (milliseconds % 1000) * 1000;

#ifdef _WIN32
    return ::select(0, &readable, nullptr, nullptr, &timeout) > 0;
#else
    return ::select(s + 1, &readable, nullptr, nullptr, &timeout) > 0;
#endif
  }

  void Serve() {
    // Polled rather than blocked in accept, so the destructor can stop it.
    while (!stop_) {
      if (!Readable(socket_, 50)) continue;
      Socket accepted = ::accept(socket_, nullptr, nullptr);
      if (!Valid(accepted)) continue;

      Received request;
      if (Read(accepted, request)) {
        {
          std::lock_guard<std::mutex> lock(mutex_);
          received_.push_back(request);
        }
        const Reply answer = handler_(request);
        std::string extra;
        for (const auto& header : answer.headers) {
          extra += header.first + ": " + header.second + "\r\n";
        }
        std::string reply = "HTTP/1.1 " + std::to_string(answer.status) + " Canned\r\n" +
                            "Content-Type: application/json\r\n" +
                            "Content-Length: " + std::to_string(answer.body.size()) + "\r\n" +
                            extra + "Connection: close\r\n\r\n" + answer.body;
        std::size_t sent = 0;
        while (sent < reply.size()) {
          int n = static_cast<int>(::send(accepted, reply.data() + sent,
                                          static_cast<int>(reply.size() - sent), 0));
          if (n <= 0) break;
          sent += static_cast<std::size_t>(n);
        }
      }
      Close(accepted);
    }
  }

  /// One request off the wire: its line, its headers and its body.
  static bool Read(Socket s, Received& out) {
    std::string raw;
    std::size_t header_end = std::string::npos;
    std::size_t length = 0;
    char chunk[4096];

    while (header_end == std::string::npos || raw.size() < header_end + 4 + length) {
      // A stalled client fails the check it is part of; it does not hang the suite.
      if (!Readable(s, 5000)) return false;
      int n = static_cast<int>(::recv(s, chunk, static_cast<int>(sizeof(chunk)), 0));
      if (n <= 0) return false;
      raw.append(chunk, static_cast<std::size_t>(n));
      if (header_end != std::string::npos) continue;

      header_end = raw.find("\r\n\r\n");
      if (header_end == std::string::npos) continue;

      std::size_t line_end = raw.find("\r\n");
      std::string line = raw.substr(0, line_end);
      std::size_t first = line.find(' ');
      std::size_t second = first == std::string::npos ? first : line.find(' ', first + 1);
      if (second == std::string::npos) return false;
      out.method = line.substr(0, first);
      out.path = line.substr(first + 1, second - first - 1);

      for (std::size_t at = line_end + 2; at < header_end;) {
        std::size_t next = raw.find("\r\n", at);
        std::string header = raw.substr(at, next - at);
        std::size_t colon = header.find(':');
        if (colon != std::string::npos) {
          std::string name = header.substr(0, colon);
          for (char& c : name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
          std::size_t start = header.find_first_not_of(' ', colon + 1);
          out.headers[name] = start == std::string::npos ? std::string() : header.substr(start);
        }
        at = next + 2;
      }

      auto declared = out.headers.find("content-length");
      if (declared != out.headers.end()) {
        for (char c : declared->second) {
          if (c < '0' || c > '9') return false;
          length = length * 10 + static_cast<std::size_t>(c - '0');
        }
      }
    }

    out.body = raw.substr(header_end + 4, length);
    return true;
  }

  Handler handler_;
  unsigned short port_ = 0;
  std::atomic<bool> stop_{false};
  std::mutex mutex_;
  std::vector<Received> received_;
  std::thread thread_;
};

// ---------------------------------------------------------------------------
// Construction is the connection
// ---------------------------------------------------------------------------

void TestConnectsOnStart() {
  Section("connects on start");

  {
    /*
     * ⚠️ THE ONE ASSERTION THAT WOULD FAIL IF THE FEATURE WERE DELETED. A
     * dashboard saying "watching for connection" is waiting on exactly this
     * request. Before it existed, a native application reached Grantry for the
     * first time when somebody typed a password — which is why the setup
     * guide used to teach sign-in before it had taught anything at all.
     */
    LoopbackListener listener;
    CHECK(listener.ok());
    if (listener.ok()) {
      grantry::Options options;
      options.publishable_key =
          "pk_test_ZW52XzRKZ2dkNHd6ZkM2OEVzc0tEYXM5bkJFcA_201cac9f982c4a70b060eb5ac7ee990d";
      options.api_base_url = listener.url();
      options.allow_insecure_loopback = true;
      options.session_store = grantry::MakeInMemorySessionStore();

      Result<std::shared_ptr<grantry::Client>> result = grantry::Client::Create(options);
      CHECK(result.ok());

      // Once. It is a hello, not a poll.
      CHECK(listener.Accepted(10) == 1);
    }
  }

  {
    // And a build that must make no unasked-for call can say so.
    LoopbackListener listener;
    CHECK(listener.ok());
    if (listener.ok()) {
      grantry::Options options;
      options.publishable_key =
          "pk_test_ZW52XzRKZ2dkNHd6ZkM2OEVzc0tEYXM5bkJFcA_201cac9f982c4a70b060eb5ac7ee990d";
      options.api_base_url = listener.url();
      options.allow_insecure_loopback = true;
      options.connect_on_start = false;
      options.session_store = grantry::MakeInMemorySessionStore();

      Result<std::shared_ptr<grantry::Client>> result = grantry::Client::Create(options);
      CHECK(result.ok());

      /*
       * Asserted against a request the client WAS asked to make, not against a
       * clock: by the time the server has seen that one, a probe started at
       * creation would already have arrived. It fails — the listener closes
       * without answering — and the failure is the point, not the problem.
       */
      if (result.ok()) (*result)->GetEnvironment();
      CHECK(listener.Accepted(10) == 1);
    }
  }

  /*
   * ⚠️ WHAT THE SETUP GUIDE'S FIRST STAGE WAITS ON. A dashboard saying
   * "watching for connection" is waiting on the request `Create` starts here
   * and on nothing else. Before it existed, a native application reached
   * Grantry for the first time when somebody typed a password — which is
   * why the guide used to teach sign-in before it had taught anything at all.
   *
   * ⚠️ WHAT IS CHECKED HERE IS THAT IT COSTS NOTHING, not that it arrives.
   * There is no server in this process to receive it, and standing one up
   * would test this file's socket code rather than the SDK's. That the request
   * is actually sent, and that the dashboard moves when it lands, is verified
   * against the running API instead. What can go wrong HERE is the part that
   * would be a crash in a shipped game: a client built and dropped while a
   * thread is still reading its members.
   */
  {
    grantry::Options options;
    options.publishable_key =
        "pk_test_ZW52XzRKZ2dkNHd6ZkM2OEVzc0tEYXM5bkJFcA_201cac9f982c4a70b060eb5ac7ee990d";
    // Nothing is listening. The probe fails, and that is the case being made:
    // a client whose first request cannot be delivered is still a client.
    options.api_base_url = "http://127.0.0.1:1";
    options.allow_insecure_loopback = true;
    options.session_store = grantry::MakeInMemorySessionStore();

    Result<std::shared_ptr<grantry::Client>> result = grantry::Client::Create(options);
    CHECK(result.ok());
    if (result.ok()) {
      // Usable, and knowing nothing about the failure: the probe reports to
      // nobody, so there is no error state for it to have left behind.
      CHECK(!(*result)->has_session());
      CHECK((*result)->environment_id() == "env_4Jggd4wzfC68EssKDas9nBEp");
    }
  }

  /*
   * ⚠️ BUILT AND DROPPED IN THE SAME BREATH, TWENTY-FIVE TIMES. This is the
   * shape of the bug the destructor's join exists to prevent: the probe runs
   * through Send, which reads the pins, the device hash and the session —
   * so a client freed while that thread ran would be a use-after-free, on a
   * thread, in a shipped build. Under a sanitizer this loop is the test; here
   * it is at least the crash.
   */
  for (int i = 0; i < 25; i++) {
    grantry::Options options;
    options.publishable_key =
        "pk_test_ZW52XzRKZ2dkNHd6ZkM2OEVzc0tEYXM5bkJFcA_201cac9f982c4a70b060eb5ac7ee990d";
    options.api_base_url = "http://127.0.0.1:1";
    options.allow_insecure_loopback = true;
    options.session_store = grantry::MakeInMemorySessionStore();

    Result<std::shared_ptr<grantry::Client>> result = grantry::Client::Create(options);
    CHECK(result.ok());
    // Dropped here, with the probe possibly mid-flight.
  }
}

// ---------------------------------------------------------------------------
// Single sign-on, which ends in the system browser
// ---------------------------------------------------------------------------

void TestStartSso() {
  Section("single sign-on");

  /*
   * ⚠️ THIS FAILED ON EVERY CALL FROM THE DAY IT WAS WRITTEN. StartSso read
   * `url` and the route has only ever answered `authorization_url`, so each
   * sign-on came back "The sign-on response carried no URL". C# and Python did
   * the same, and nothing called any of them.
   */
  CannedHttpServer server(
      200, "{\"authorization_url\":\"https://github.com/login/oauth/authorize?state=s1\"}");
  CHECK(server.ok());
  if (!server.ok()) return;

  grantry::Options options;
  options.publishable_key =
      "pk_test_ZW52XzRKZ2dkNHd6ZkM2OEVzc0tEYXM5bkJFcA_201cac9f982c4a70b060eb5ac7ee990d";
  options.api_base_url = server.url();
  options.allow_insecure_loopback = true;
  options.connect_on_start = false;
  options.session_store = grantry::MakeInMemorySessionStore();

  Result<std::shared_ptr<grantry::Client>> created = grantry::Client::Create(options);
  CHECK(created.ok());
  if (!created.ok()) return;
  grantry::Client& client = **created;

  Result<std::string> started = client.StartSso("github", "myapp://callback");
  CHECK(started.ok());
  CHECK(started.value.value_or("") == "https://github.com/login/oauth/authorize?state=s1");

  std::vector<CannedHttpServer::Received> received = server.received();
  CHECK(received.size() == 1);
  if (received.size() != 1) return;

  // The provider is the path segment; the body is the return address alone.
  CHECK(received[0].method == "POST");
  CHECK(received[0].path == "/v1/client/oauth/github/start");
  Json sent;
  CHECK(Json::Parse(received[0].body, sent));
  CHECK(sent.GetString("redirectUrl").value_or("") == "myapp://callback");
  CHECK(sent.Find("provider") == nullptr);
  CHECK(sent.Find("botToken") == nullptr);

  /*
   * ⚠️ THE ONE LEG OF A PROVIDER SIGN-IN THAT CAN CARRY A TOKEN. With bot
   * protection on, the route refuses a sign-in without one, and the provider's
   * redirect back has nowhere to put one. Empty is omitted, as SignIn omits it —
   * which the call above, taking the default, has just shown.
   */
  CHECK(client.StartSso("github", "myapp://callback", "a-challenge-answer").ok());
  received = server.received();
  CHECK(received.size() == 2);
  if (received.size() != 2) return;
  Json answered;
  CHECK(Json::Parse(received[1].body, answered));
  CHECK(answered.GetString("botToken").value_or("") == "a-challenge-answer");
}

// ---------------------------------------------------------------------------
// Redirect sign-in: the system browser, the loopback listener, PKCE and the state
// ---------------------------------------------------------------------------

/// SHA-256 by the platform directly, not through the library, then base64url.
///
/// ⚠️ INDEPENDENT ON PURPOSE. A fake that checked the verifier with the SDK's own
/// PkceChallenge would agree with a wrong one; this is BCrypt or OpenSSL called here.
std::string IndependentS256(const std::string& verifier) {
  std::vector<std::uint8_t> digest(32, 0);
#ifdef _WIN32
  BCRYPT_ALG_HANDLE sha = nullptr;
  BCryptOpenAlgorithmProvider(&sha, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
  BCryptHash(sha, nullptr, 0, reinterpret_cast<PUCHAR>(const_cast<char*>(verifier.data())),
             static_cast<ULONG>(verifier.size()), digest.data(), 32);
  BCryptCloseAlgorithmProvider(sha, 0);
#else
  EVP_Digest(verifier.data(), verifier.size(), digest.data(), nullptr, EVP_sha256(), nullptr);
#endif
  return Base64UrlEncode(digest);
}

/// Percent-encoding for a query value the test writes itself.
std::string Encode(const std::string& raw) {
  static const char* kHex = "0123456789ABCDEF";
  std::string out;
  for (unsigned char c : raw) {
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      out.push_back(static_cast<char>(c));
    } else {
      out.push_back('%');
      out.push_back(kHex[c >> 4]);
      out.push_back(kHex[c & 0x0F]);
    }
  }
  return out;
}

/// One GET, as a browser following the 302 makes it. Status 0 when nothing answered.
struct Visit {
  int status = 0;
  std::string body;
  /// Where a 3xx sends the browser; empty for anything else.
  std::string location;
};

Visit Get(const std::string& url) {
  grantry::internal::HttpRequest request;
  request.method = "GET";
  request.url = url;
  request.allow_insecure = true;
  request.timeout_seconds = 10;
  grantry::internal::HttpResponse response;
  std::string error;
  Visit visit;
  if (grantry::internal::HttpSend(request, response, error)) {
    visit.status = response.status;
    visit.body = response.body;
    auto location = response.headers.find("location");
    if (location != response.headers.end()) visit.location = location->second;
  }
  return visit;
}

bool Has(const std::string& haystack, const std::string& needle) {
  return haystack.find(needle) != std::string::npos;
}

std::map<std::string, std::string> QueryOf(const std::string& url) {
  std::map<std::string, std::string> query;
  const std::size_t question = url.find('?');
  grantry::internal::ParseQuery(question == std::string::npos ? std::string() : url.substr(question + 1),
                                query);
  return query;
}

const char kSignInUrl[] = "https://slate-plover-13cad5.grantry.dev";

/// The API a redirect sign-in talks to: the environment, the exchange, a token and the
/// signing keys. Codes are bound to a challenge and a return address, as /authorize
/// binds them, and spent once.
class RedirectApi {
 public:
  RedirectApi()
      : server_([this](const CannedHttpServer::Received& request) { return Handle(request); }) {}

  RedirectApi(const RedirectApi&) = delete;
  RedirectApi& operator=(const RedirectApi&) = delete;

  bool ok() const { return server_.ok(); }
  std::string url() const { return server_.url(); }

  /// A code as /oauth/authorize mints one.
  std::string Issue(const std::string& challenge, const std::string& redirect_uri) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string code = "code_redirect_" + std::to_string(++issued_);
    codes_[code] = std::make_pair(challenge, redirect_uri);
    return code;
  }

  int exchanges() {
    std::lock_guard<std::mutex> lock(mutex_);
    return exchanges_;
  }
  std::string last_exchange() {
    std::lock_guard<std::mutex> lock(mutex_);
    return last_exchange_;
  }
  std::string session() {
    std::lock_guard<std::mutex> lock(mutex_);
    return session_;
  }

  // Set before the client runs.
  std::string sign_in_url = kSignInUrl;
  bool refuse_exchange = false;
  bool report = false;

 private:
  CannedHttpServer::Reply Handle(const CannedHttpServer::Received& request) {
    CannedHttpServer::Reply reply;
    if (request.path == "/v1/client/environment") {
      reply.body = "{\"environment\":{\"applicationName\":\"Example\",\"issuer\":\"" + sign_in_url
                 + "\"}}";
      return reply;
    }
    if (request.path == "/v1/.well-known/jwks.json") {
      reply.body = Jwks(key_, key_.thumbprint());
      return reply;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    Json sent;
    Json::Parse(request.body, sent);

    if (request.path == "/v1/client/oauth/exchange") {
      exchanges_++;
      last_exchange_ = request.body;
      auto bound = codes_.find(sent.GetString("code").value_or(""));
      if (refuse_exchange || bound == codes_.end()
          || bound->second.first != IndependentS256(sent.GetString("codeVerifier").value_or(""))
          || bound->second.second != sent.GetString("redirectUri").value_or("")) {
        reply.status = 400;
        reply.body = "{\"error\":{\"code\":\"invalid_request\",\"message\":\"This sign-in has expired.\"}}";
        return reply;
      }
      codes_.erase(bound);
      session_ = "sess_redirect_" + std::to_string(issued_);
      reply.headers["X-Grantry-Session"] = session_;
      reply.body = std::string("{\"user\":{\"id\":\"") + kUser + "\"}"
                 + (report ? ",\"mfaRequired\":true,\"requiresPlan\":true,"
                             "\"planMessage\":\"Enter your licence key.\""
                           : "")
                 + "}";
      return reply;
    }

    if (request.path == "/v1/client/token") {
      auto presented = request.headers.find("x-grantry-session");
      if (session_.empty() || presented == request.headers.end() || presented->second != session_) {
        reply.status = 401;
        reply.body = "{\"error\":{\"code\":\"unauthorized\",\"message\":\"no session\"}}";
        return reply;
      }
      TokenSpec spec;
      spec.kid = key_.thumbprint();
      spec.nonce = sent.GetString("nonce").value_or("");
      reply.body = "{\"access_token\":\"" + Mint(key_, spec)
                 + "\",\"token_type\":\"Bearer\",\"expires_in\":60}";
      return reply;
    }

    reply.status = 404;
    reply.body = "{\"error\":{\"code\":\"not_found\",\"message\":\"no route\"}}";
    return reply;
  }

  TestKey key_;
  std::mutex mutex_;
  std::map<std::string, std::pair<std::string, std::string>> codes_;
  int issued_ = 0;
  int exchanges_ = 0;
  std::string last_exchange_;
  std::string session_;
  // ⚠️ LAST: its thread calls Handle from the moment it starts, so every member Handle
  // reads has to exist first.
  CannedHttpServer server_;
};

/// The browser the SDK opens. Each visit is one GET to the return address the SDK sent,
/// with the query a test chooses; a visit beginning `/` is a path of its own.
class RedirectBrowser {
 public:
  using Visitor = std::function<std::string(RedirectBrowser&)>;

  RedirectBrowser(RedirectApi& api, std::vector<Visitor> visits)
      : api_(api), visits_(std::move(visits)) {}

  ~RedirectBrowser() {
    if (thread_.joinable()) thread_.join();
  }

  /// The hosted sign-in's answer: the code, this request's state, the issuer.
  static std::string Answer(RedirectBrowser& browser) {
    return "code=" + Encode(browser.code) + "&state=" + Encode(browser.query["state"])
         + "&iss=" + Encode(kSignInUrl);
  }

  bool Open(const std::string& url) {
    opened = url;
    query = QueryOf(url);
    code = api_.Issue(query["code_challenge"], query["redirect_uri"]);
    // Its own thread, as a browser is its own process: the SDK is waiting on the listener.
    thread_ = std::thread([this] {
      const std::string redirect = query["redirect_uri"];
      const std::string origin = redirect.substr(0, redirect.find('/', 7));
      for (Visitor& visit : visits_) {
        const std::string built = visit(*this);
        pages_.push_back(Get(!built.empty() && built[0] == '/' ? origin + built
                                                               : redirect + "?" + built));
      }
    });
    return true;
  }

  const std::vector<Visit>& Finished() {
    if (thread_.joinable()) thread_.join();
    return pages_;
  }

  std::string opened;
  std::map<std::string, std::string> query;
  std::string code;

 private:
  RedirectApi& api_;
  std::vector<Visitor> visits_;
  std::vector<Visit> pages_;
  std::thread thread_;
};

std::shared_ptr<grantry::Client> RedirectClient(const RedirectApi& api,
                                                std::shared_ptr<grantry::SessionStore> store) {
  grantry::Options options;
  options.publishable_key = "pk_test_abcdefghijklmnop";
  options.environment_id = kEnvironment;
  options.api_base_url = api.url();
  options.allow_insecure_loopback = true;
  options.connect_on_start = false;
  options.session_store = std::move(store);
  Result<std::shared_ptr<grantry::Client>> created = grantry::Client::Create(options);
  return created.ok() ? *created.value : nullptr;
}

grantry::RedirectOptions Through(RedirectBrowser& browser) {
  grantry::RedirectOptions options;
  options.open_browser = [&browser](const std::string& url) { return browser.Open(url); };
  // Far above what a test's own browser takes, far below the SDK's ten minutes, so a
  // listener that cannot be reached fails the check instead of stalling the run.
  options.timeout_seconds = 20;
  return options;
}

void TestRedirectRules() {
  Section("redirect sign-in rules");

  using grantry::internal::CodeFromAnswer;
  using grantry::internal::ParseQuery;
  using grantry::internal::PkceChallenge;
  using grantry::internal::FinishedUrl;
  using grantry::internal::SignInUrlOpenable;

  // RFC 7636 Appendix B, the specification's own example.
  CHECK(PkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  CHECK(PkceChallenge("another-verifier-of-enough-length-to-count-here")
        == IndependentS256("another-verifier-of-enough-length-to-count-here"));

  std::map<std::string, std::string> parsed;
  CHECK(ParseQuery("code=a%2Bb&state=x+y&iss=https%3A%2F%2Fs.example&empty=", parsed));
  CHECK(parsed["code"] == "a+b");
  CHECK(parsed["state"] == "x y");
  CHECK(parsed["iss"] == "https://s.example");
  CHECK(parsed.count("empty") == 1 && parsed["empty"].empty());
  // A repeated name is an answer somebody built.
  CHECK(!ParseQuery("state=ours&state=theirs", parsed));

  std::string code;
  std::map<std::string, std::string> answer = {{"code", "c1"}, {"state", "s"}, {"iss", kSignInUrl}};
  CHECK(!CodeFromAnswer(answer, kSignInUrl, code));
  CHECK(code == "c1");

  answer["iss"] = "https://another.example";
  grantry::Error mixed = CodeFromAnswer(answer, kSignInUrl, code);
  CHECK(mixed.kind == grantry::ErrorKind::kRedirect && mixed.code == "issuer_mismatch");
  answer.erase("iss");
  CHECK(CodeFromAnswer(answer, kSignInUrl, code).code == "issuer_mismatch");

  std::map<std::string, std::string> denied = {{"error", "access_denied"}, {"iss", kSignInUrl}};
  CHECK(CodeFromAnswer(denied, kSignInUrl, code).code == "access_denied");
  denied["error"] = "<b>anything a query string likes</b>";
  CHECK(CodeFromAnswer(denied, kSignInUrl, code).code == "invalid_response");
  std::map<std::string, std::string> empty = {{"iss", kSignInUrl}};
  CHECK(CodeFromAnswer(empty, kSignInUrl, code).code == "invalid_response");

  // ⚠️ WHAT THE SHELL IS HANDED: https, or http on a development host, and nothing else.
  CHECK(SignInUrlOpenable("https://slate-plover-13cad5.grantry.dev"));
  CHECK(SignInUrlOpenable("https://grantry.example.com"));
  CHECK(SignInUrlOpenable("http://slate-plover-13cad5.localhost:3103"));
  CHECK(SignInUrlOpenable("http://127.0.0.1:3103"));
  CHECK(!SignInUrlOpenable(""));
  CHECK(!SignInUrlOpenable("file:///C:/Windows/System32/calc.exe"));
  CHECK(!SignInUrlOpenable("ms-settings:privacy"));
  CHECK(!SignInUrlOpenable("javascript:alert(1)"));
  CHECK(!SignInUrlOpenable("http://sign-in.example.test"));
  CHECK(!SignInUrlOpenable("https://user@sign-in.example.test"));
  CHECK(!SignInUrlOpenable("https://sign-in.example.test/\" --flag"));

  // The ending is the sign-in host's own page, whichever way it went.
  CHECK(FinishedUrl(kSignInUrl, true) == std::string(kSignInUrl) + "/finished?outcome=signed_in");
  CHECK(FinishedUrl(std::string(kSignInUrl) + "/", false)
        == std::string(kSignInUrl) + "/finished?outcome=failed");
}

void TestLoopbackListener() {
  Section("loopback listener");

  grantry::internal::LoopbackListener listener;
  CHECK(listener.ok());
  if (!listener.ok()) return;

  // 127.0.0.1 itself: not every interface, and nothing off this machine can reach it.
  CHECK(listener.address() == "127.0.0.1");
  CHECK(listener.redirect_uri()
        == "http://127.0.0.1:" + std::to_string(static_cast<int>(listener.port())) + "/callback");

  std::map<std::string, std::string> answer;
  std::atomic<bool> answered{false};
  std::thread waiting([&] {
    answered = listener.Wait("the-state", 10, std::function<bool()>(), answer)
            == grantry::internal::LoopbackListener::Outcome::kAnswered;
  });

  const std::string origin = "http://127.0.0.1:" + std::to_string(static_cast<int>(listener.port()));
  // Anything else on the port is turned away, and the wait goes on.
  CHECK(Get(origin + "/favicon.ico").status == 404);
  CHECK(Get(listener.redirect_uri() + "?code=theirs&state=guessed").status == 400);

  // A real request, over a socket, carrying the state it is waiting for.
  Visit page;
  std::thread browser([&] { page = Get(listener.redirect_uri() + "?code=abc&state=the-state&iss=x%3Ay"); });
  waiting.join();
  CHECK(answered);
  CHECK(answer["code"] == "abc");
  CHECK(answer["iss"] == "x:y");

  // Taken, so nothing else is let in while the browser waits on its page.
  CHECK(!listener.listening());
  CHECK(Get(origin + "/callback").status == 0);

  listener.Redirect(grantry::internal::FinishedUrl(kSignInUrl, true));
  browser.join();
  CHECK(page.status == 303);
  CHECK(page.location == std::string(kSignInUrl) + "/finished?outcome=signed_in");
}

void TestSignInWithRedirect() {
  Section("sign in with redirect");

  {
    // The round trip, held exactly as a password sign-in's session is.
    RedirectApi api;
    CHECK(api.ok());
    if (!api.ok()) return;
    std::shared_ptr<grantry::SessionStore> store = grantry::MakeInMemorySessionStore();
    std::shared_ptr<grantry::Client> client = RedirectClient(api, store);
    CHECK(client != nullptr);
    if (client == nullptr) return;

    RedirectBrowser browser(api, {RedirectBrowser::Answer});
    Result<grantry::SignInResult> result = client->SignInWithRedirect(Through(browser));
    CHECK(result.ok());
    if (result.ok()) {
      CHECK(result->mfa_challenge.empty());
      CHECK(!result->requires_plan);
    }
    CHECK(client->has_session());
    CHECK(store->Read().value_or("") == api.session());
    CHECK(!api.session().empty());

    // The authorize request: the sign-in URL, the publishable key as the client.
    CHECK(browser.opened.rfind(std::string(kSignInUrl) + "/oauth/authorize?", 0) == 0);
    CHECK(browser.query["response_type"] == "code");
    CHECK(browser.query["client_id"] == "pk_test_abcdefghijklmnop");
    CHECK(browser.query["scope"] == "openid profile email");
    CHECK(browser.query["code_challenge_method"] == "S256");
    CHECK(browser.query["redirect_uri"].rfind("http://127.0.0.1:", 0) == 0);
    CHECK(Has(browser.query["redirect_uri"], "/callback"));
    // "Continue as" for a browser already signed in, unless told otherwise.
    CHECK(browser.query["prompt"] == "select_account");

    // The exchange: the code, the verifier the challenge was made from, the same address.
    Json sent;
    CHECK(Json::Parse(api.last_exchange(), sent));
    CHECK(sent.GetString("code").value_or("") == browser.code);
    const std::string verifier = sent.GetString("codeVerifier").value_or("");
    CHECK(verifier.size() == 43);
    CHECK(IndependentS256(verifier) == browser.query["code_challenge"]);
    CHECK(sent.GetString("redirectUri").value_or("") == browser.query["redirect_uri"]);
    CHECK(api.exchanges() == 1);

    // The browser is sent on to the sign-in host's "signed in" page; then the port is gone.
    const std::vector<Visit>& pages = browser.Finished();
    CHECK(pages.size() == 1);
    if (pages.size() == 1) {
      CHECK(pages[0].status == 303);
      CHECK(pages[0].location == std::string(kSignInUrl) + "/finished?outcome=signed_in");
    }
    CHECK(Get(browser.query["redirect_uri"]).status == 0);

    // A second sign-in makes a fresh verifier and state.
    RedirectBrowser again(api, {RedirectBrowser::Answer});
    CHECK(client->SignInWithRedirect(Through(again)).ok());
    CHECK(again.query["state"] != browser.query["state"]);
    CHECK(again.query["code_challenge"] != browser.query["code_challenge"]);
  }

  {
    // The other two prompts: the sign-in form always, and no screen at all.
    RedirectApi api;
    std::shared_ptr<grantry::Client> client = RedirectClient(api, grantry::MakeInMemorySessionStore());
    RedirectBrowser login(api, {RedirectBrowser::Answer});
    grantry::RedirectOptions options = Through(login);
    options.prompt = grantry::RedirectPrompt::kLogin;
    CHECK(client->SignInWithRedirect(options).ok());
    CHECK(login.query["prompt"] == "login");

    RedirectBrowser immediate(api, {RedirectBrowser::Answer});
    options = Through(immediate);
    options.prompt = grantry::RedirectPrompt::kImmediate;
    CHECK(client->SignInWithRedirect(options).ok());
    CHECK(immediate.query.count("prompt") == 0);
  }

  {
    // The reports a password sign-in's answer carries.
    RedirectApi api;
    api.report = true;
    std::shared_ptr<grantry::Client> client = RedirectClient(api, grantry::MakeInMemorySessionStore());
    RedirectBrowser browser(api, {RedirectBrowser::Answer});
    Result<grantry::SignInResult> result = client->SignInWithRedirect(Through(browser));
    CHECK(result.ok());
    if (result.ok()) {
      CHECK(result->mfa_required);
      CHECK(result->requires_plan);
      CHECK(result->plan_message == "Enter your licence key.");
    }
  }

  {
    // ⚠️ AN ANSWER CARRYING ANOTHER STATE IS TURNED AWAY AND NEVER EXCHANGED: a page
    // that found the port, with a code of its own. Then the real answer.
    RedirectApi api;
    std::shared_ptr<grantry::Client> client = RedirectClient(api, grantry::MakeInMemorySessionStore());
    RedirectBrowser browser(
        api,
        {[](RedirectBrowser&) {
           return std::string("code=someone-elses-code&state=guessed&iss=") + Encode(kSignInUrl);
         },
         [](RedirectBrowser&) {
           return std::string("code=someone-elses-code&iss=") + Encode(kSignInUrl);
         },
         [](RedirectBrowser& b) {
           return "code=someone-elses-code&state=guessed&state=" + Encode(b.query["state"]);
         },
         RedirectBrowser::Answer});
    Result<grantry::SignInResult> result = client->SignInWithRedirect(Through(browser));
    CHECK(result.ok());
    const std::vector<Visit>& pages = browser.Finished();
    CHECK(pages.size() == 4);
    if (pages.size() == 4) {
      CHECK(pages[0].status == 400 && pages[1].status == 400 && pages[2].status == 400);
      CHECK(pages[3].status == 303);
    }
    CHECK(api.exchanges() == 1);
    Json sent;
    CHECK(Json::Parse(api.last_exchange(), sent));
    CHECK(sent.GetString("code").value_or("") == browser.code);
  }

  {
    // An answer from another issuer is refused before anything is exchanged.
    RedirectApi api;
    std::shared_ptr<grantry::SessionStore> store = grantry::MakeInMemorySessionStore();
    std::shared_ptr<grantry::Client> client = RedirectClient(api, store);
    RedirectBrowser browser(api, {[](RedirectBrowser& b) {
                              return "code=" + Encode(b.code) + "&state=" + Encode(b.query["state"])
                                   + "&iss=" + Encode("https://another.example");
                            }});
    Result<grantry::SignInResult> result = client->SignInWithRedirect(Through(browser));
    CHECK(!result.ok());
    CHECK(result.error.kind == grantry::ErrorKind::kRedirect);
    CHECK(result.error.code == "issuer_mismatch");
    CHECK(api.exchanges() == 0);
    CHECK(!store->Read().has_value());
    const std::vector<Visit>& pages = browser.Finished();
    CHECK(pages.size() == 1
          && pages[0].location == std::string(kSignInUrl) + "/finished?outcome=failed");
  }

  {
    // The hosted sign-in's own error is the code.
    RedirectApi api;
    std::shared_ptr<grantry::Client> client = RedirectClient(api, grantry::MakeInMemorySessionStore());
    RedirectBrowser browser(api, {[](RedirectBrowser& b) {
                              return "error=access_denied&state=" + Encode(b.query["state"])
                                   + "&iss=" + Encode(kSignInUrl);
                            }});
    Result<grantry::SignInResult> result = client->SignInWithRedirect(Through(browser));
    CHECK(result.error.kind == grantry::ErrorKind::kRedirect);
    CHECK(result.error.code == "access_denied");
    CHECK(api.exchanges() == 0);
  }

  {
    // A refused exchange signs nobody in, and the page says so.
    RedirectApi api;
    api.refuse_exchange = true;
    std::shared_ptr<grantry::SessionStore> store = grantry::MakeInMemorySessionStore();
    std::shared_ptr<grantry::Client> client = RedirectClient(api, store);
    RedirectBrowser browser(api, {RedirectBrowser::Answer});
    Result<grantry::SignInResult> result = client->SignInWithRedirect(Through(browser));
    CHECK(result.error.kind == grantry::ErrorKind::kApi);
    CHECK(result.error.status == 400);
    CHECK(!client->has_session());
    CHECK(!store->Read().has_value());
    const std::vector<Visit>& pages = browser.Finished();
    CHECK(pages.size() == 1
          && pages[0].location == std::string(kSignInUrl) + "/finished?outcome=failed");
  }

  {
    // Nobody coming back is a timeout, and the port closes: a closed browser sends nothing.
    RedirectApi api;
    std::shared_ptr<grantry::Client> client = RedirectClient(api, grantry::MakeInMemorySessionStore());
    std::string opened;
    grantry::RedirectOptions options;
    options.timeout_seconds = 1;
    options.open_browser = [&opened](const std::string& url) {
      opened = url;
      return true;
    };
    Result<grantry::SignInResult> result = client->SignInWithRedirect(options);
    CHECK(result.error.kind == grantry::ErrorKind::kRedirect);
    CHECK(result.error.code == "timeout");
    CHECK(Get(QueryOf(opened)["redirect_uri"]).status == 0);
    CHECK(api.exchanges() == 0);
  }

  {
    // Cancelling stops the wait and closes the port.
    RedirectApi api;
    std::shared_ptr<grantry::Client> client = RedirectClient(api, grantry::MakeInMemorySessionStore());
    std::string opened;
    std::atomic<bool> pressed{false};
    grantry::RedirectOptions options;
    options.open_browser = [&](const std::string& url) {
      opened = url;
      pressed = true;  // A Cancel button, pressed while the browser is still open.
      return true;
    };
    options.cancelled = [&pressed] { return pressed.load(); };
    Result<grantry::SignInResult> result = client->SignInWithRedirect(options);
    CHECK(result.error.kind == grantry::ErrorKind::kRedirect);
    CHECK(result.error.code == "cancelled");
    CHECK(Get(QueryOf(opened)["redirect_uri"]).status == 0);
  }

  {
    // A browser that will not open is its own failure.
    RedirectApi api;
    std::shared_ptr<grantry::Client> client = RedirectClient(api, grantry::MakeInMemorySessionStore());
    grantry::RedirectOptions options;
    options.open_browser = [](const std::string&) { return false; };
    Result<grantry::SignInResult> result = client->SignInWithRedirect(options);
    CHECK(result.error.kind == grantry::ErrorKind::kRedirect);
    CHECK(result.error.code == "browser_unavailable");
  }

  {
    // ⚠️ A SIGN-IN URL THE SHELL SHOULD NOT OPEN IS NEVER OPENED.
    RedirectApi api;
    api.sign_in_url = "file:///C:/Windows/System32/calc.exe";
    std::shared_ptr<grantry::Client> client = RedirectClient(api, grantry::MakeInMemorySessionStore());
    bool opened = false;
    grantry::RedirectOptions options;
    options.open_browser = [&opened](const std::string&) {
      opened = true;
      return true;
    };
    Result<grantry::SignInResult> result = client->SignInWithRedirect(options);
    CHECK(result.error.kind == grantry::ErrorKind::kRedirect);
    CHECK(result.error.code == "not_offered");
    CHECK(!opened);
  }
}

// ---------------------------------------------------------------------------
// Session store
// ---------------------------------------------------------------------------

void TestSessionStore() {
  Section("session store");

  std::unique_ptr<grantry::SessionStore> memory = grantry::MakeInMemorySessionStore();
  CHECK(!memory->Read().has_value());
  memory->Write("sess_abc");
  CHECK(memory->Read().value_or("") == "sess_abc");
  memory->Clear();
  CHECK(!memory->Read().has_value());

  std::string path = std::string("grantry-test-store-") + std::to_string(UnixNow());
  std::unique_ptr<grantry::SessionStore> file = grantry::MakeFileSessionStoreAt(path);

  CHECK(!file->Read().has_value());
  file->Write("sess_a_long_opaque_session_token_value");
  CHECK(file->Read().value_or("") == "sess_a_long_opaque_session_token_value");

#ifdef _WIN32
  // On Windows the bytes on disk are DPAPI ciphertext, so they must not equal
  // the token. Elsewhere the library stores plaintext under 0600 and says so.
  {
    std::FILE* handle = std::fopen(path.c_str(), "rb");
    CHECK(handle != nullptr);
    if (handle != nullptr) {
      char buffer[512] = {0};
      std::size_t read = std::fread(buffer, 1, sizeof(buffer) - 1, handle);
      std::fclose(handle);
      CHECK(read > 0);
      CHECK(std::string(buffer, read) != "sess_a_long_opaque_session_token_value");
    }
  }
#endif

  file->Clear();
  CHECK(!file->Read().has_value());
  std::remove(path.c_str());
}

// ---------------------------------------------------------------------------
// The primitives this SDK had to derive itself
// ---------------------------------------------------------------------------

/// Hex string to bytes, for reading published test vectors.
std::vector<std::uint8_t> FromHex(const std::string& text) {
  std::vector<std::uint8_t> bytes;
  bytes.reserve(text.size() / 2);
  for (std::size_t i = 0; i + 1 < text.size(); i += 2) {
    bytes.push_back(static_cast<std::uint8_t>(std::stoi(text.substr(i, 2), nullptr, 16)));
  }
  return bytes;
}

/*
 * ⚠️ THESE COMPARE AGAINST PUBLISHED VECTORS, NOT AGAINST THIS SDK.
 *
 * HKDF and the GCM key schedule are written here because the platforms disagree
 * about whether they ship one — so a test that round-tripped them against
 * themselves would prove they are self-consistent while shipping a different
 * answer than the server computes. Self-consistency is exactly the failure to
 * rule out, and only an external authority rules it out.
 */
void TestDerivations() {
  Section("derivations");

  // RFC 5869 test case 1.
  std::vector<std::uint8_t> okm;
  CHECK(Hkdf(FromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
             FromHex("000102030405060708090a0b0c"), FromHex("f0f1f2f3f4f5f6f7f8f9"), 42, okm));
  CHECK(Hex(okm)
        == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
           "34007208d5b887185865");

  /*
   * RFC 5869 test case 3, where the salt is empty.
   *
   * ⚠️ AN EMPTY SALT IS NOT THE SAME QUESTION AS A MISSING ONE. The RFC
   * defines an absent salt as HashLen zero bytes; HMAC then pads any key
   * shorter than its block size with zeros, so an empty key and thirty-two
   * zeros land on the same block. Getting that wrong produces a function that
   * works perfectly against itself and disagrees with the server every time.
   */
  CHECK(Hkdf(FromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), {}, {}, 42, okm));
  CHECK(Hex(okm)
        == "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
           "9d201395faa4b61a96c8");

  // Output longer than one hash block, so the counter is exercised.
  CHECK(Hkdf({1, 2, 3}, {4, 5, 6}, {7, 8, 9}, 64, okm));
  CHECK(okm.size() == 64);
  CHECK(!Hkdf({1, 2, 3}, {}, {}, 0, okm));

  // RFC 4231 test case 1, so HMAC itself is not taken on trust either.
  std::vector<std::uint8_t> mac;
  CHECK(HmacSha256(FromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                   {'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e'}, mac));
  CHECK(Hex(mac) == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

  CHECK(Hex(Sha256(std::vector<std::uint8_t>()))
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

void TestAesGcm() {
  Section("aes-gcm");

  // The GCM specification's own AES-256 vectors, with no additional data.
  struct Vector {
    const char* key;
    const char* iv;
    const char* plaintext;
    const char* ciphertext;
    const char* tag;
  };

  const Vector vectors[] = {
      // Case 13: empty plaintext. The tag is GHASH of nothing but the lengths.
      {"0000000000000000000000000000000000000000000000000000000000000000",
       "000000000000000000000000", "", "", "530f8afbc74536b9a963b4f1c4cb738b"},
      // Case 14: one block of zeros under a key of zeros.
      {"0000000000000000000000000000000000000000000000000000000000000000",
       "000000000000000000000000", "00000000000000000000000000000000",
       "cea7403d4d606b6e074ec5d3baf39d18", "d0d1c8a799996bf0265b98b5d48ab919"},
      // Case 15: sixty-four bytes, four full blocks.
      {"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
       "cafebabefacedbaddecaf888",
       "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
       "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
       "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
       "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
       "b094dac5d93471bdec1a502270e3cc6c"},
  };

  for (const Vector& vector : vectors) {
    std::vector<std::uint8_t> out;
    CHECK(AesGcmDecrypt(FromHex(vector.key), FromHex(vector.iv), FromHex(vector.ciphertext),
                        FromHex(vector.tag), out));
    CHECK(Hex(out) == std::string(vector.plaintext));
  }

  const Vector& subject = vectors[2];
  const std::vector<std::uint8_t> key = FromHex(subject.key);
  const std::vector<std::uint8_t> iv = FromHex(subject.iv);
  const std::vector<std::uint8_t> ciphertext = FromHex(subject.ciphertext);
  const std::vector<std::uint8_t> tag = FromHex(subject.tag);
  std::vector<std::uint8_t> out;

  // A tampered tag is refused, at every byte of it.
  for (std::size_t i = 0; i < tag.size(); i++) {
    std::vector<std::uint8_t> edited = tag;
    edited[i] ^= 0x01;
    CHECK(!AesGcmDecrypt(key, iv, ciphertext, edited, out));
  }

  /*
   * ⚠️ TAMPERED CIPHERTEXT IS THE ATTACK THIS ACTUALLY STOPS, and the reason
   * GCM is used rather than a bare stream cipher. CTR mode is malleable:
   * flipping a bit of ciphertext flips the same bit of plaintext, so without
   * the tag somebody who could not READ a value could still edit it — turning
   * "free" into any four bytes they liked.
   */
  std::vector<std::uint8_t> edited_text = ciphertext;
  edited_text[0] ^= 0x01;
  CHECK(!AesGcmDecrypt(key, iv, edited_text, tag, out));

  // The wrong key, and malformed inputs, are refused rather than guessed at.
  std::vector<std::uint8_t> other_key(32, 0x11);
  CHECK(!AesGcmDecrypt(other_key, iv, ciphertext, tag, out));
  CHECK(!AesGcmDecrypt(std::vector<std::uint8_t>(16, 0), iv, ciphertext, tag, out));
  CHECK(!AesGcmDecrypt(key, std::vector<std::uint8_t>(16, 0), ciphertext, tag, out));
  CHECK(!AesGcmDecrypt(key, iv, ciphertext, std::vector<std::uint8_t>(8, 0), out));
}

void TestPinningPolicy() {
  Section("certificate pinning");

  grantry::Options production;
  production.publishable_key = "pk_test_abcdefghijklmnop";
  production.environment_id = "env_test_1234567890";
  production.api_base_url = "https://api.grantry.dev";
  CHECK(ShouldPin(production));

  /*
   * A merchant pointing at staging must not spend an afternoon on a handshake
   * failure they did not ask for. The default protects production without
   * anybody thinking about it; everything else is opt-in.
   */
  grantry::Options staging = production;
  staging.api_base_url = "https://api.staging.example.test";
  CHECK(!ShouldPin(staging));

  // Supplying pins is itself the request to use them.
  grantry::Options self_hosted = staging;
  self_hosted.certificate_pins = {"abc=", "def="};
  CHECK(ShouldPin(self_hosted));
  CHECK(PinsFor(self_hosted).size() == 2);

  // And an explicit setting beats every inference, in both directions.
  grantry::Options refused = production;
  refused.pin_certificate = false;
  CHECK(!ShouldPin(refused));

  grantry::Options demanded = staging;
  demanded.pin_certificate = true;
  CHECK(ShouldPin(demanded));

  // A port or a trailing path must not stop the host being recognised.
  grantry::Options ported = production;
  ported.api_base_url = "https://API.Grantry.dev:443/v1";
  CHECK(ShouldPin(ported));

  /*
   * ⚠️ MORE THAN ONE BUILT-IN PIN, ALWAYS. A single pin is an outage waiting
   * for the day the key rotates, and no update can fix it because the updater
   * is behind the same pin.
   */
  std::vector<std::string> defaults = PinsFor(production);
  CHECK(defaults.size() >= 2);
  CHECK(defaults[0] != defaults[1]);

  // A placeholder that reached a release would be an application that cannot
  // connect at all, and nothing in the build refuses one the way C#'s pack does.
  for (const std::string& pin : defaults) CHECK(pin.find("REPLACE_ME") == std::string::npos);

  // The built-in set is enforced as a trust store on POSIX; anybody's own pins
  // stay pins on the server's key.
  CHECK(grantry::internal::TrustAnchorsFor(defaults) != nullptr);
  CHECK(grantry::internal::TrustAnchorsFor(PinsFor(self_hosted)) == nullptr);
  CHECK(grantry::internal::TrustAnchorsFor({}) == nullptr);
}

/*
 * ⚠️ EACH BUILT-IN PIN IS COMPUTED FROM THE ROOT IT NAMES, WITH THIS PLATFORM'S
 * OWN CRYPTO (17 October 2026). The pins were worked out with openssl; an
 * encoder here that disagreed on one key type (two RSA 4096, two ECDSA P-384)
 * would give a digest that never matches on Windows, and a bundle out of step
 * with the pins would trust roots nobody pinned on POSIX. Either way every
 * shipped build would refuse api.grantry.dev with nothing to say why.
 */
void TestBuiltInPinsAreTheirRoots() {
  Section("built-in pins are Let's Encrypt's roots");

  grantry::Options production;
  production.api_base_url = "https://api.grantry.dev";
  const std::vector<std::string> pins = PinsFor(production);
  const std::vector<std::string> computed =
      grantry::internal::PemBundleSpkiPins(grantry::internal::kDefaultTrustAnchorsPem);

  CHECK(computed.size() == 4);
  CHECK(computed == pins);

  // A bundle with a broken certificate in it is not a shorter good one.
  std::string broken = grantry::internal::kDefaultTrustAnchorsPem;
  broken.replace(broken.find("MII"), 3, "AAA");
  CHECK(grantry::internal::PemBundleSpkiPins(broken).empty());
}

/*
 * Against the real API, when GRANTRY_LIVE_TESTS=1: the CI workflow sets it, a
 * build with no network does not need it. Three requests, all public: the
 * built-in pins reach api.grantry.dev; a pin nobody holds is refused as a pin;
 * and a real, valid certificate from another authority (Google's) is refused
 * with the built-in pins, which is what proves the machine's own trust store is
 * not being consulted — a proxy's root would be in that store.
 */
void TestLivePinning() {
  const char* live = std::getenv("GRANTRY_LIVE_TESTS");
  if (live == nullptr || std::string(live) != "1") return;
  Section("pinning against the live API");

  grantry::Options production;
  production.api_base_url = "https://api.grantry.dev";
  const std::vector<std::string> built_in = PinsFor(production);

  grantry::internal::HttpRequest request;
  request.method = "GET";
  request.url = "https://api.grantry.dev/v1/.well-known/jwks.json";
  request.timeout_seconds = 20;
  request.certificate_pins = built_in;
  grantry::internal::HttpResponse response;
  std::string error;
  const bool reached = grantry::internal::HttpSend(request, response, error);
  if (!reached) std::printf("    built-in pins: %s\n", error.c_str());
  CHECK(reached);
  CHECK(response.status == 200);
  CHECK(!response.pin_refused);

  grantry::internal::HttpRequest wrong = request;
  wrong.certificate_pins = {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="};
  grantry::internal::HttpResponse refused;
  error.clear();
  CHECK(!grantry::internal::HttpSend(wrong, refused, error));
  CHECK(refused.pin_refused);

  grantry::internal::HttpRequest elsewhere = request;
  elsewhere.url = "https://www.google.com/generate_204";
  grantry::internal::HttpResponse other;
  error.clear();
  CHECK(!grantry::internal::HttpSend(elsewhere, other, error));
  CHECK(other.pin_refused);
}

}  // namespace

/*
 * The recovery codes shown again (0279), parsed by pure functions for the same
 * reason the 202 above is: this suite's only server closes the connection
 * without answering, so the shapes are tested where there is no network.
 */
void TestBackupCodeView() {
  Section("backup codes shown again");

  using grantry::BackupCodeView;
  using grantry::Proof;
  using grantry::internal::BackupCodeViewFrom;
  using grantry::internal::Json;
  using grantry::internal::ProofBody;

  // The set, with the spent one marked and still listed in its place.
  Json shown;
  CHECK(Json::Parse(
      "{\"status\":\"shown\",\"backupCodes\":["
      "{\"code\":\"AAAA2222BB\",\"usedAt\":null},"
      "{\"code\":\"CCCC3333DD\",\"usedAt\":\"2026-09-29T10:00:00.000Z\"}]}",
      shown));
  BackupCodeView view;
  CHECK(BackupCodeViewFrom(shown, view));
  CHECK(!view.regenerate_required);
  CHECK(view.codes.size() == 2);
  CHECK(view.codes[0].code == "AAAA2222BB" && !view.codes[0].spent());
  CHECK(view.codes[1].code == "CCCC3333DD" && view.codes[1].spent());
  CHECK(view.codes[1].used_at == "2026-09-29T10:00:00.000Z");

  // A set made before 0279: nothing to show, which is not "no codes".
  Json regenerate;
  CHECK(Json::Parse("{\"status\":\"regenerate\"}", regenerate));
  BackupCodeView hidden;
  CHECK(BackupCodeViewFrom(regenerate, hidden));
  CHECK(hidden.regenerate_required);
  CHECK(hidden.codes.empty());

  // ⚠️ AN UNREADABLE BODY IS FALSE, NOT AN EMPTY SET. A caller reporting "you
  // have no codes" off a body it could not parse would be inventing a fact.
  Json missing;
  CHECK(Json::Parse("{\"status\":\"shown\"}", missing));
  BackupCodeView nothing;
  CHECK(!BackupCodeViewFrom(missing, nothing));

  Json unknown;
  CHECK(Json::Parse("{\"backupCodes\":[]}", unknown));
  CHECK(!BackupCodeViewFrom(unknown, nothing));

  // One field on the wire, named by the proof, and nothing beside it.
  CHECK(ProofBody(Proof::Password("hunter2-hunter2")) == "{\"password\":\"hunter2-hunter2\"}");
  CHECK(ProofBody(Proof::AuthenticatorCode("123456")) == "{\"code\":\"123456\"}");
  CHECK(Proof::AuthenticatorCode("123456").field() == "code");
}

// ---------------------------------------------------------------------------
// The trusted device
// ---------------------------------------------------------------------------

/*
 * A device that answers the second factor is spared it for fourteen days (the
 * API's 0277). The server hands the proof back in `X-Grantry-Trusted-Device`
 * after the answer and reads it on the next sign-in; a browser keeps it in a
 * cookie, this SDK beside the session. This is the API a second factor talks to:
 * a sign-in that stops for it, the answer with a session and a token, the token
 * route and the keys — recording the trusted-device token each request carried.
 */
class TrustApi {
 public:
  TrustApi()
      : server_([this](const CannedHttpServer::Received& request) { return Handle(request); }) {}

  TrustApi(const TrustApi&) = delete;
  TrustApi& operator=(const TrustApi&) = delete;

  bool ok() const { return server_.ok(); }
  std::string url() const { return server_.url(); }

  /// The token the last request to `path` presented, or "(none)".
  std::string presented(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto found = presented_.find(path);
    return found == presented_.end() ? std::string("(no request)") : found->second;
  }

  // Set before the client runs, or between its calls.
  std::string issue = "trust_T0kenFromTheServer_43chars_abcdefghij";
  std::string drop_on;
  bool requires_plan = false;

 private:
  CannedHttpServer::Reply Handle(const CannedHttpServer::Received& request) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto trust = request.headers.find("x-grantry-trusted-device");
    presented_[request.path] = trust == request.headers.end() ? std::string("(none)") : trust->second;

    CannedHttpServer::Reply reply = Route(request);
    if (!drop_on.empty() && request.path == drop_on) {
      reply.headers["X-Grantry-Trusted-Device"] = "";
    }
    return reply;
  }

  CannedHttpServer::Reply Route(const CannedHttpServer::Received& request) {
    CannedHttpServer::Reply reply;
    if (request.path == "/v1/.well-known/jwks.json") {
      reply.body = Jwks(key_, key_.thumbprint());
      return reply;
    }
    if (request.path == "/v1/client/sign-in") {
      reply.body = "{\"mfa\":{\"token\":\"chal_1\",\"expiresInSeconds\":300}}";
      return reply;
    }
    if (request.path == "/v1/client/sign-in/identifier") {
      reply.body = "{\"exists\":true}";
      return reply;
    }
    if (request.path == "/v1/client/mfa/verify") {
      session_ = "sess_trust_" + std::to_string(++verified_);
      reply.headers["X-Grantry-Session"] = session_;
      if (!issue.empty()) reply.headers["X-Grantry-Trusted-Device"] = issue;
      reply.body = std::string("{\"backupCodesRemaining\":7")
                 + (requires_plan ? ",\"requiresPlan\":true,\"planMessage\":\"Activate a licence.\""
                                  : "")
                 + "}";
      return reply;
    }
    if (request.path == "/v1/client/token") {
      auto presented = request.headers.find("x-grantry-session");
      if (session_.empty() || presented == request.headers.end() || presented->second != session_) {
        reply.status = 401;
        reply.body = "{\"error\":{\"code\":\"unauthorized\",\"message\":\"no session\"}}";
        return reply;
      }
      Json sent;
      Json::Parse(request.body, sent);
      TokenSpec spec;
      spec.kid = key_.thumbprint();
      spec.nonce = sent.GetString("nonce").value_or("");
      reply.body = "{\"access_token\":\"" + Mint(key_, spec)
                 + "\",\"token_type\":\"Bearer\",\"expires_in\":60}";
      return reply;
    }
    if (request.path == "/v1/client/sign-out") {
      session_.clear();
      reply.headers["X-Grantry-Session"] = "";
      reply.body = "{}";
      return reply;
    }
    reply.status = 404;
    reply.body = "{\"error\":{\"code\":\"not_found\",\"message\":\"no route\"}}";
    return reply;
  }

  TestKey key_;
  std::mutex mutex_;
  std::map<std::string, std::string> presented_;
  std::string session_;
  int verified_ = 0;
  // ⚠️ LAST: its thread calls Handle from the moment it starts.
  CannedHttpServer server_;
};

std::shared_ptr<grantry::Client> TrustClient(const TrustApi& api,
                                             std::shared_ptr<grantry::SessionStore> store) {
  grantry::Options options;
  options.publishable_key = "pk_test_abcdefghijklmnop";
  options.environment_id = kEnvironment;
  options.api_base_url = api.url();
  options.allow_insecure_loopback = true;
  options.connect_on_start = false;
  options.session_store = std::move(store);
  Result<std::shared_ptr<grantry::Client>> created = grantry::Client::Create(options);
  return created.ok() ? *created.value : nullptr;
}

/// Signed in through the second factor, which handed back a trust.
bool Answered(grantry::Client& client) {
  Result<grantry::SignInResult> challenge = client.SignIn("ada@example.test", "hunter2hunter2");
  if (!challenge.ok() || challenge->mfa_challenge.empty()) return false;
  Result<grantry::SignInResult> done = client.SubmitMfa(challenge->mfa_challenge, "123456");
  return done.ok() && done->password_reset_token.empty();
}

/// A store written before the trusted-device slot: the three members it always had.
class OldStore : public grantry::SessionStore {
 public:
  std::optional<std::string> Read() override { return held_; }
  void Write(const std::string& token) override { held_ = token; }
  void Clear() override { held_.reset(); }

 private:
  std::optional<std::string> held_;
};

void TestTrustedDevice() {
  Section("trusted device");

  const std::string token = "trust_T0kenFromTheServer_43chars_abcdefghij";
  const std::string stored = std::string(kEnvironment) + "\n" + token;

  {
    // Kept after the answer, and presented by the next sign-in — the first presented none.
    TrustApi api;
    CHECK(api.ok());
    std::shared_ptr<grantry::SessionStore> store = grantry::MakeInMemorySessionStore();
    std::shared_ptr<grantry::Client> client = TrustClient(api, store);
    CHECK(client != nullptr);
    if (client) {
      CHECK(Answered(*client));
      CHECK(api.presented("/v1/client/sign-in") == "(none)");
      CHECK(store->ReadTrustedDevice().value_or("") == stored);

      client->SignIn("ada@example.test", "hunter2hunter2");
      CHECK(api.presented("/v1/client/sign-in") == token);

      // On every call, not only sign-ins: the server decides which calls are doors.
      client->LookupIdentifier("ada@example.test");
      CHECK(api.presented("/v1/client/sign-in/identifier") == token);
      // And an answer that says nothing changes nothing.
      client->LookupIdentifier("ada@example.test");
      CHECK(api.presented("/v1/client/sign-in/identifier") == token);
      CHECK(store->ReadTrustedDevice().value_or("") == stored);
    }
  }

  {
    /*
     * ⚠️ EMPTY, NOT ABSENT, MEANS LET IT GO. The server sends it when the token
     * spares nobody — forgotten, expired, a new password — and an SDK that kept
     * presenting a dead token would never learn to answer the factor again.
     */
    TrustApi api;
    std::shared_ptr<grantry::SessionStore> store = grantry::MakeInMemorySessionStore();
    std::shared_ptr<grantry::Client> client = TrustClient(api, store);
    CHECK(client != nullptr);
    if (client) {
      CHECK(Answered(*client));
      api.drop_on = "/v1/client/sign-in";
      client->SignIn("ada@example.test", "hunter2hunter2");
      CHECK(api.presented("/v1/client/sign-in") == token);
      CHECK(!store->ReadTrustedDevice().has_value());

      client->SignIn("ada@example.test", "hunter2hunter2");
      CHECK(api.presented("/v1/client/sign-in") == "(none)");
    }
  }

  {
    // ⚠️ SIGNING OUT KEEPS IT, WHICH IS THE POINT OF IT: it remembers the installation.
    TrustApi api;
    std::shared_ptr<grantry::SessionStore> store = grantry::MakeInMemorySessionStore();
    std::shared_ptr<grantry::Client> client = TrustClient(api, store);
    CHECK(client != nullptr);
    if (client) {
      CHECK(Answered(*client));
      CHECK(client->has_session());
      client->SignOut();
      CHECK(!client->has_session());
      CHECK(!store->Read().has_value());

      client->SignIn("ada@example.test", "hunter2hunter2");
      CHECK(api.presented("/v1/client/sign-in") == token);
    }
  }

  {
    // The next run presents what this one kept, from a file of its own beside the session.
    TrustApi api;
    const std::string path = std::string("grantry-test-trust-") + std::to_string(UnixNow());
    {
      std::shared_ptr<grantry::Client> first =
          TrustClient(api, std::shared_ptr<grantry::SessionStore>(grantry::MakeFileSessionStoreAt(path)));
      CHECK(first != nullptr);
      if (first) CHECK(Answered(*first));
    }

    std::shared_ptr<grantry::SessionStore> reopened(grantry::MakeFileSessionStoreAt(path));
    // ⚠️ A FILE OF ITS OWN: in the session's slot it would sign somebody out by answering.
    CHECK(reopened->Read().value_or("").rfind("sess_trust_", 0) == 0);
    CHECK(reopened->ReadTrustedDevice().value_or("") == stored);
#ifdef _WIN32
    {
      // Wrapped with DPAPI, like the session: the token is not in the file's bytes.
      std::FILE* handle = std::fopen((path + ".trusted-device").c_str(), "rb");
      CHECK(handle != nullptr);
      if (handle != nullptr) {
        char buffer[1024] = {0};
        std::size_t read = std::fread(buffer, 1, sizeof(buffer) - 1, handle);
        std::fclose(handle);
        CHECK(read > 0);
        CHECK(std::string(buffer, read).find(token) == std::string::npos);
      }
    }
#endif

    std::shared_ptr<grantry::Client> restarted = TrustClient(api, reopened);
    CHECK(restarted != nullptr);
    if (restarted) {
      restarted->SignIn("ada@example.test", "hunter2hunter2");
      CHECK(api.presented("/v1/client/sign-in") == token);
    }

    reopened->ClearTrustedDevice();
    CHECK(!reopened->ReadTrustedDevice().has_value());
    CHECK(reopened->Read().has_value());
    reopened->Clear();
    std::remove(path.c_str());
    std::remove((path + ".trusted-device").c_str());
  }

  {
    // One store per application: never another environment's token, and never a slot it cannot read.
    TrustApi api;
    const std::vector<std::string> unusable = {
        std::string("env_some_other_environment\n") + token, token,
        std::string(kEnvironment) + "\n", std::string(kEnvironment) + "\n   "};
    for (const std::string& slot : unusable) {
      std::shared_ptr<grantry::SessionStore> store = grantry::MakeInMemorySessionStore();
      store->WriteTrustedDevice(slot);
      std::shared_ptr<grantry::Client> client = TrustClient(api, store);
      CHECK(client != nullptr);
      if (client) {
        client->SignIn("ada@example.test", "hunter2hunter2");
        CHECK(api.presented("/v1/client/sign-in") == "(none)");
      }
    }
  }

  {
    // A store written before the slot still works: in memory for this run, gone at the next.
    TrustApi api;
    auto store = std::make_shared<OldStore>();
    std::shared_ptr<grantry::Client> client = TrustClient(api, store);
    CHECK(client != nullptr);
    if (client) {
      CHECK(Answered(*client));
      CHECK(store->Read().has_value());
      client->SignIn("ada@example.test", "hunter2hunter2");
      CHECK(api.presented("/v1/client/sign-in") == token);
    }
    std::shared_ptr<grantry::Client> restarted = TrustClient(api, store);
    if (restarted) {
      restarted->SignIn("ada@example.test", "hunter2hunter2");
      CHECK(api.presented("/v1/client/sign-in") == "(none)");
    }
  }

  {
    /*
     * ⚠️ THE PLAN REPORT AFTER THE FACTOR IS LEFT UNREAD HERE, ON PURPOSE — see
     * SignInResult::requires_plan. The server sends it (September 2026) and the
     * C# and Python SDKs read it; this one relies on kPlanRequired, and this pins
     * that the decision is the one documented rather than an accident.
     */
    TrustApi api;
    api.requires_plan = true;
    std::shared_ptr<grantry::Client> client = TrustClient(api, grantry::MakeInMemorySessionStore());
    CHECK(client != nullptr);
    if (client) {
      Result<grantry::SignInResult> challenge = client->SignIn("ada@example.test", "hunter2hunter2");
      CHECK(challenge.ok());
      if (challenge.ok()) {
        Result<grantry::SignInResult> done = client->SubmitMfa(challenge->mfa_challenge, "123456");
        CHECK(done.ok());
        if (done.ok()) CHECK(!done->requires_plan);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// The account calls the docs rewrite found wanting (9 October 2026)
// ---------------------------------------------------------------------------

/*
 * Each found by reading this SDK against the API for the docs: proofs only a password could
 * give, an enrolment that dropped its otpauth address, sign-up's one boolean sent as a string,
 * an identity that outlived the account it answered for, a megabyte ceiling on every download,
 * and one shared "device" for every installation without a machine anchor. This API answers
 * the account calls, records the body and method each path last received, and counts tokens.
 */
class AccountApi {
 public:
  AccountApi()
      : server_([this](const CannedHttpServer::Received& request) { return Handle(request); }) {}

  AccountApi(const AccountApi&) = delete;
  AccountApi& operator=(const AccountApi&) = delete;

  bool ok() const { return server_.ok(); }
  std::string url() const { return server_.url(); }

  /// The body the last request to `path` carried, or "(no request)".
  std::string body(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto found = bodies_.find(path);
    return found == bodies_.end() ? std::string("(no request)") : found->second;
  }

  /// The method the last request to `path` used, or "(no request)".
  std::string method(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto found = methods_.find(path);
    return found == methods_.end() ? std::string("(no request)") : found->second;
  }

  /// How many access tokens have been minted.
  int minted() {
    std::lock_guard<std::mutex> lock(mutex_);
    return minted_;
  }

  /// Whether the next mints report `requiresPlan`, as a plan-locked session's do.
  void set_requires_plan(bool value) {
    std::lock_guard<std::mutex> lock(mutex_);
    requires_plan_ = value;
  }

  /// The plans' version the long-poll answers with. Changing it is "the plans changed".
  void set_plans_version(const std::string& value) {
    std::lock_guard<std::mutex> lock(mutex_);
    plans_version_ = value;
  }

  /// How many times the long-poll has been asked.
  int polled() {
    std::lock_guard<std::mutex> lock(mutex_);
    return polled_;
  }

 private:
  CannedHttpServer::Reply Handle(const CannedHttpServer::Received& request) {
    std::lock_guard<std::mutex> lock(mutex_);
    bodies_[request.path] = request.body;
    methods_[request.path] = request.method;
    return Route(request);
  }

  CannedHttpServer::Reply Route(const CannedHttpServer::Received& request) {
    CannedHttpServer::Reply reply;
    reply.body = "{}";
    if (request.path == "/v1/.well-known/jwks.json") {
      reply.body = Jwks(key_, key_.thumbprint());
      return reply;
    }
    if (request.path == "/v1/client/sign-in") {
      session_ = "sess_ada";
      reply.headers["X-Grantry-Session"] = session_;
      return reply;
    }
    if (request.path == "/v1/client/sign-up") {
      reply.body = "{\"status\":\"pending_verification\"}";
      return reply;
    }
    if (request.path == "/v1/client/accounts/sess_grace/activate") {
      // The client keeps its session; the account in front moves, and its token says so.
      session_ = "sess_grace";
      reply.headers["X-Grantry-Session"] = session_;
      return reply;
    }
    if (request.path == "/v1/client/token") {
      auto presented = request.headers.find("x-grantry-session");
      if (session_.empty() || presented == request.headers.end() || presented->second != session_) {
        reply.status = 401;
        reply.body = "{\"error\":{\"code\":\"unauthorized\",\"message\":\"no session\"}}";
        return reply;
      }
      Json sent;
      Json::Parse(request.body, sent);
      TokenSpec spec;
      spec.kid = key_.thumbprint();
      spec.nonce = sent.GetString("nonce").value_or("");
      ++minted_;
      reply.body = "{\"access_token\":\"" + Mint(key_, spec)
                 + "\",\"token_type\":\"Bearer\",\"expires_in\":60"
                 + (requires_plan_ ? ",\"requiresPlan\":true,\"planMessage\":null}" : "}");
      return reply;
    }
    /*
     * The plans long-poll, answering at once rather than holding: what a poll whose version is current
     * gets back after its wait, without the wait.
     */
    if (request.path.rfind("/v1/client/entitlements/changes", 0) == 0) {
      ++polled_;
      const std::string marker = "since=";
      const auto at = request.path.find(marker);
      const std::string since = at == std::string::npos ? std::string() : request.path.substr(at + marker.size());
      reply.body = "{\"version\":\"" + plans_version_ + "\",\"changed\":"
                 + (since == plans_version_ ? "false" : "true") + "}";
      return reply;
    }
    if (request.path == "/v1/client/mfa/totp") {
      reply.body = "{\"id\":\"mfa_factor_1\",\"secret\":\"JBSWY3DPEHPK3PXP\","
                   "\"uri\":\"otpauth://totp/My%20App:ada%40example.test"
                   "?secret=JBSWY3DPEHPK3PXP&issuer=My%20App\"}";
      return reply;
    }
    if (request.path == "/v1/client/me/reauthentication-code") {
      reply.status = 204;
      reply.body.clear();
      return reply;
    }
    // Two products held at once, the lifetime first, as the server orders them.
    if (request.path == "/v1/client/billing/me") {
      reply.body =
          "{\"subscription\":{\"planKey\":\"permanent\",\"planName\":\"Permanent\",\"status\":\"active\","
          "\"interval\":{\"unit\":\"lifetime\",\"count\":1},\"currentPeriodEnd\":null,\"expiresInDays\":null},"
          "\"held\":[{\"planKey\":\"permanent\",\"planName\":\"Permanent\",\"status\":\"active\","
          "\"interval\":{\"unit\":\"lifetime\",\"count\":1},\"currentPeriodEnd\":null,\"expiresInDays\":null},"
          "{\"planKey\":\"cleaner\",\"planName\":\"Cleaner\",\"status\":\"active\","
          "\"interval\":{\"unit\":\"day\",\"count\":30},\"currentPeriodEnd\":\"2026-11-12T10:00:00.000Z\","
          "\"expiresInDays\":14}]}";
      return reply;
    }
    if (request.path == "/v1/client/account/devices") {
      reply.body = "{\"data\":["
                   "{\"id\":\"dev_this\",\"label\":\"E0B4902D\",\"platform\":\"windows\","
                   "\"lastSeenAt\":\"2026-10-09T10:00:00Z\",\"current\":true},"
                   "{\"id\":\"dev_other\",\"label\":\"4332EF0E\",\"platform\":\"macos\","
                   "\"lastSeenAt\":\"2026-10-01T10:00:00Z\",\"current\":false}]}";
      return reply;
    }
    if (request.path == "/v1/client/change-email" || request.path == "/v1/client/delete-account" ||
        request.path == "/v1/client/mfa/mfa_factor_1" || request.path == "/v1/client/sign-out" ||
        request.path == "/v1/client/me/verify-email/confirm") {
      return reply;
    }
    reply.status = 404;
    reply.body = "{\"error\":{\"code\":\"not_found\",\"message\":\"no route\"}}";
    return reply;
  }

  TestKey key_;
  std::mutex mutex_;
  std::map<std::string, std::string> bodies_;
  std::map<std::string, std::string> methods_;
  std::string session_;
  int minted_ = 0;
  bool requires_plan_ = false;
  std::string plans_version_ = "v1";
  int polled_ = 0;
  // ⚠️ LAST: its thread calls Handle from the moment it starts.
  CannedHttpServer server_;
};

std::shared_ptr<grantry::Client> AccountClient(const AccountApi& api) {
  grantry::Options options;
  options.publishable_key = "pk_test_abcdefghijklmnop";
  options.environment_id = kEnvironment;
  options.api_base_url = api.url();
  options.allow_insecure_loopback = true;
  options.connect_on_start = false;
  options.session_store = grantry::MakeInMemorySessionStore();
  Result<std::shared_ptr<grantry::Client>> created = grantry::Client::Create(options);
  return created.ok() ? *created.value : nullptr;
}

void TestAccountProofs() {
  Section("account proofs");
  using grantry::Proof;

  AccountApi api;
  CHECK(api.ok());
  std::shared_ptr<grantry::Client> client = AccountClient(api);
  CHECK(client != nullptr);
  if (!client) return;
  CHECK(client->SignIn("ada@example.test", "hunter2hunter2").ok());

  // The enrolment's whole answer, and no proof sent for a first one.
  Result<grantry::TotpSetup> setup = client->StartTotp("Laptop");
  CHECK(setup.ok());
  if (setup.ok()) {
    CHECK(setup->factor_id == "mfa_factor_1");
    CHECK(setup->secret == "JBSWY3DPEHPK3PXP");
    CHECK(setup->uri.rfind("otpauth://totp/", 0) == 0);
  }
  CHECK(api.body("/v1/client/mfa/totp") == "{\"name\":\"Laptop\"}");

  // Replacing a confirmed one sends the proof the server asks for, and nothing beside it.
  CHECK(client->StartTotp(std::string(), Proof::BackupCode("ABCDE-12345")).ok());
  CHECK(api.body("/v1/client/mfa/totp") == "{\"backupCode\":\"ABCDE-12345\"}");

  // An account with no password: a code to its own address, then the change made with it.
  CHECK(client->SendReauthenticationCode().ok());
  CHECK(api.method("/v1/client/me/reauthentication-code") == "POST");
  CHECK(client->ChangeEmail("new@example.test", Proof::EmailCode("482910"),
                            "http://localhost:5173/confirm").ok());
  const std::string changed = api.body("/v1/client/change-email");
  CHECK(Has(changed, "\"emailCode\":\"482910\""));
  CHECK(Has(changed, "\"newEmail\":\"new@example.test\""));
  CHECK(!Has(changed, "password"));

  // The password overload still sends the password.
  CHECK(client->ChangeEmail("new@example.test", "hunter2hunter2", "http://localhost:5173/confirm").ok());
  CHECK(Has(api.body("/v1/client/change-email"), "\"password\":\"hunter2hunter2\""));

  // A factor removed with a recovery code, when the phone is gone.
  CHECK(client->RemoveFactor("mfa_factor_1", Proof::BackupCode("ABCDE-12345")).ok());
  CHECK(api.method("/v1/client/mfa/mfa_factor_1") == "DELETE");
  CHECK(api.body("/v1/client/mfa/mfa_factor_1") == "{\"backupCode\":\"ABCDE-12345\"}");
  CHECK(client->RemoveFactor("mfa_factor_1", "hunter2hunter2").ok());
  CHECK(api.body("/v1/client/mfa/mfa_factor_1") == "{\"password\":\"hunter2hunter2\"}");

  // The machine making the call, marked as such.
  Result<std::vector<grantry::Device>> devices = client->GetDevices();
  CHECK(devices.ok() && devices->size() == 2);
  if (devices.ok() && devices->size() == 2) {
    CHECK((*devices)[0].current);
    CHECK(!(*devices)[1].current);
    CHECK((*devices)[1].platform == "macos");
  }

  /*
   * Every plan held, each with its own days left (29 October 2026): "Cleaner"'s expiry is read by
   * its key, never from whichever plan `GetSubscription` happens to name.
   */
  Result<std::vector<grantry::Subscription>> held = client->GetSubscriptions();
  CHECK(held.ok() && held->size() == 2);
  if (held.ok() && held->size() == 2) {
    CHECK((*held)[0].plan_key == "permanent");
    CHECK(!(*held)[0].expires_in_days.has_value());
    CHECK((*held)[0].current_period_end.empty());
    CHECK((*held)[1].plan_key == "cleaner");
    CHECK((*held)[1].expires_in_days == std::optional<int>(14));
    CHECK((*held)[1].interval_count == 30);
  }
  Result<grantry::Subscription> first = client->GetSubscription();
  CHECK(first.ok() && first->active && first->plan_key == "permanent");

  // Deleted with an authenticator code — last, since it signs the client out.
  CHECK(client->DeleteAccount(Proof::AuthenticatorCode("123456")).ok());
  CHECK(api.body("/v1/client/delete-account") == "{\"code\":\"123456\"}");
  CHECK(!client->has_session());
}

void TestIdentityFollowsTheAccount() {
  Section("identity follows the account");

  AccountApi api;
  std::shared_ptr<grantry::Client> client = AccountClient(api);
  CHECK(client != nullptr);
  if (!client) return;
  CHECK(client->SignIn("ada@example.test", "hunter2hunter2").ok());

  // Cached after the sign-in proved it: asking again mints nothing.
  CHECK(client->GetIdentity().ok());
  const int signed_in = api.minted();
  CHECK(client->GetIdentity().ok());
  CHECK(api.minted() == signed_in);

  // ⚠️ SWITCHING KEPT THE CACHE UNTIL 9 OCTOBER 2026, and answered for the last account.
  CHECK(client->SwitchAccount("sess_grace").ok());
  CHECK(client->GetIdentity().ok());
  CHECK(api.minted() == signed_in + 1);

  CHECK(client->SignOutOf("sess_other").ok());
  CHECK(client->GetIdentity().ok());
  CHECK(api.minted() == signed_in + 2);

  // A confirmed address is a different identity too: the cached one said unconfirmed.
  CHECK(client->ConfirmEmailVerification("123456").ok());
  CHECK(client->GetIdentity().ok());
  CHECK(api.minted() == signed_in + 3);
}

/*
 * ⚠️ A RESTORED SESSION HAD NO WAY TO LEARN IT HELD NO PLAN (11 October 2026). Only a sign-in's
 * result said so; a restore signs nobody in, and it mints, so the mint reports it beside the token
 * and the client keeps the last answer. Each mint replaces it, and signing out clears it.
 */
void TestRequiresPlanFromTheMint() {
  Section("the plan report on a mint");

  AccountApi api;
  std::shared_ptr<grantry::Client> client = AccountClient(api);
  CHECK(client != nullptr);
  if (!client) return;
  CHECK(!client->requires_plan());

  CHECK(client->SignIn("ada@example.test", "hunter2hunter2").ok());
  CHECK(client->GetIdentity().ok());
  CHECK(!client->requires_plan());

  // A switch drops the cached identity, so the next call mints and reads the report.
  api.set_requires_plan(true);
  CHECK(client->SwitchAccount("sess_grace").ok());
  CHECK(client->GetIdentity().ok());
  CHECK(client->requires_plan());

  // Absent is admitted: a plan bought since then clears it on the next mint.
  api.set_requires_plan(false);
  CHECK(client->SignOutOf("sess_other").ok());
  CHECK(client->GetIdentity().ok());
  CHECK(!client->requires_plan());

  api.set_requires_plan(true);
  CHECK(client->ConfirmEmailVerification("123456").ok());
  CHECK(client->GetIdentity().ok());
  CHECK(client->requires_plan());

  // Signing out forgets it with the session.
  client->SignOut();
  CHECK(!client->requires_plan());
}

/*
 * ⚠️ WATCHING FOR A PLAN (11 October 2026): the long-poll answers when the plans change, the client
 * mints, and the application hears of it with `requires_plan()` already agreeing. The first answer
 * is a baseline and calls nobody when nothing moved; a stopped watch calls nobody at all.
 */
void TestWatchPlans() {
  Section("watching for a plan");

  AccountApi api;
  std::shared_ptr<grantry::Client> client = AccountClient(api);
  CHECK(client != nullptr);
  if (!client) return;
  api.set_requires_plan(true);
  CHECK(client->SignIn("ada@example.test", "hunter2hunter2").ok());
  CHECK(client->GetIdentity().ok());
  CHECK(client->requires_plan());

  std::mutex heard_mutex;
  std::condition_variable heard_cv;
  int heard = 0;
  bool requiring_when_heard = true;
  auto wait_until = [&](auto done, int seconds) {
    std::unique_lock<std::mutex> lock(heard_mutex);
    return heard_cv.wait_for(lock, std::chrono::seconds(seconds), done);
  };

  client->WatchPlans([&] {
    std::lock_guard<std::mutex> lock(heard_mutex);
    ++heard;
    requiring_when_heard = client->requires_plan();
    heard_cv.notify_all();
  });

  // The baseline and at least one quiet poll after it: nothing moved, nobody called.
  for (int i = 0; i < 50 && api.polled() < 2; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(100));
  CHECK(api.polled() >= 2);
  {
    std::lock_guard<std::mutex> lock(heard_mutex);
    CHECK(heard == 0);
  }

  // A plan arrives: the next answer says so, the client mints, and the application is told.
  api.set_requires_plan(false);
  api.set_plans_version("v2");
  CHECK(wait_until([&] { return heard >= 1; }, 10));
  {
    std::lock_guard<std::mutex> lock(heard_mutex);
    CHECK(heard == 1);
    CHECK(!requiring_when_heard);
  }
  CHECK(!client->requires_plan());

  // Stopped: a change after it calls nobody.
  client->StopWatchingPlans();
  api.set_plans_version("v3");
  CHECK(!wait_until([&] { return heard >= 2; }, 3));
}

/*
 * ⚠️ WATCHING FROM LAUNCH, SIGNING IN LATER (18 October 2026). An application starts the watch
 * before anybody has signed in, the way Superino's window does. Somebody signs in with no plan and
 * is shown so; a licence moved across by the merchant's sign-up webhook lands before the watch's
 * first poll for that session. That first answer was a baseline compared with how things stood at
 * LAUNCH — signed out, so "requires no plan" — and the fresh mint said the same, so nobody was told
 * and the window sat on "no plan". The watch also slept 30 seconds at a time while signed out.
 */
void TestWatchPlansSignInAfterStart() {
  Section("watching from launch, signing in later");

  AccountApi api;
  std::shared_ptr<grantry::Client> client = AccountClient(api);
  CHECK(client != nullptr);
  if (!client) return;

  std::mutex heard_mutex;
  std::condition_variable heard_cv;
  int heard = 0;
  bool requiring_when_heard = true;
  client->WatchPlans([&] {
    std::lock_guard<std::mutex> lock(heard_mutex);
    ++heard;
    requiring_when_heard = client->requires_plan();
    heard_cv.notify_all();
  });

  // Signed in with no plan, and shown so.
  api.set_requires_plan(true);
  CHECK(client->SignIn("ada@example.test", "hunter2hunter2").ok());
  CHECK(client->GetIdentity().ok());
  CHECK(client->requires_plan());

  // The licence lands at once, before the watch has asked anything about this session.
  api.set_requires_plan(false);
  api.set_plans_version("granted");

  std::unique_lock<std::mutex> lock(heard_mutex);
  CHECK(heard_cv.wait_for(lock, std::chrono::seconds(10), [&] { return heard >= 1; }));
  CHECK(!requiring_when_heard);
  lock.unlock();
  CHECK(!client->requires_plan());
  client->StopWatchingPlans();
}

void TestSignUpAcceptedLegal() {
  Section("sign-up's boolean");

  AccountApi api;
  std::shared_ptr<grantry::Client> client = AccountClient(api);
  CHECK(client != nullptr);
  if (!client) return;

  // ⚠️ A JSON BOOLEAN, NOT THE STRING IT IS PASSED AS: the server's schema refused "true".
  std::map<std::string, std::string> fields;
  fields["emailAddress"] = "ada@example.test";
  fields["password"] = "hunter2hunter2";
  fields["acceptedLegal"] = "true";
  Result<grantry::SignInResult> signed_up = client->SignUp(fields);
  CHECK(signed_up.ok());
  if (signed_up.ok()) CHECK(signed_up->outcome == grantry::SignUpOutcome::kPendingVerification);
  const std::string sent = api.body("/v1/client/sign-up");
  CHECK(Has(sent, "\"acceptedLegal\":true"));
  CHECK(!Has(sent, "\"acceptedLegal\":\"true\""));
  CHECK(Has(sent, "\"password\":\"hunter2hunter2\""));

  fields["acceptedLegal"] = "false";
  CHECK(client->SignUp(fields).ok());
  CHECK(Has(api.body("/v1/client/sign-up"), "\"acceptedLegal\":false"));

  // Without the field, nothing is added.
  fields.erase("acceptedLegal");
  CHECK(client->SignUp(fields).ok());
  CHECK(!Has(api.body("/v1/client/sign-up"), "acceptedLegal"));
}

void TestBodyCeiling() {
  Section("body ceiling");

  // Two megabytes: more than any JSON answer may be, less than a file may.
  const std::string large(2 * 1024 * 1024, 'x');
  CannedHttpServer server(200, large);
  CHECK(server.ok());

  grantry::internal::HttpRequest request;
  request.method = "GET";
  request.url = server.url() + "/v1/client/files/file_1/download";
  request.allow_insecure = true;
  request.timeout_seconds = 10;

  // The default is still the megabyte: a hostile server cannot make a JSON read allocate more.
  grantry::internal::HttpResponse refused;
  std::string error;
  CHECK(!grantry::internal::HttpSend(request, refused, error));

  // ⚠️ A DOWNLOAD ASKS FOR MORE. Every file over a megabyte failed until 9 October 2026.
  request.max_body_bytes = 64 * 1024 * 1024;
  grantry::internal::HttpResponse read;
  error.clear();
  CHECK(grantry::internal::HttpSend(request, read, error));
  CHECK(read.body.size() == large.size());
}

void TestDeviceFallback() {
  Section("device fallback");
  using grantry::internal::AnchorOrFallback;

  // The machine's own anchor wins, and nothing is written.
  std::shared_ptr<grantry::SessionStore> memory = grantry::MakeInMemorySessionStore();
  CHECK(AnchorOrFallback("S-1-5-21-1-2-3", *memory) == "S-1-5-21-1-2-3");
  CHECK(!memory->ReadDeviceFallback().has_value());

  // ⚠️ WITHOUT ONE, A RANDOM IDENTIFIER KEPT FOR NEXT TIME — not the constant "no-anchor" that
  // made every such installation one device to the server until 9 October 2026.
  const std::string first = AnchorOrFallback(std::string(), *memory);
  CHECK(first.rfind("fallback:", 0) == 0);
  CHECK(first != "no-anchor");
  CHECK(memory->ReadDeviceFallback().value_or("") == first);
  CHECK(AnchorOrFallback(std::string(), *memory) == first);

  // Another installation is another device.
  std::shared_ptr<grantry::SessionStore> elsewhere = grantry::MakeInMemorySessionStore();
  CHECK(AnchorOrFallback(std::string(), *elsewhere) != first);

  // Kept across runs by the file store, in a file of its own beside the session.
  const std::string path = std::string("grantry-test-device-") + std::to_string(UnixNow());
  std::string kept;
  {
    std::shared_ptr<grantry::SessionStore> file(grantry::MakeFileSessionStoreAt(path));
    kept = AnchorOrFallback(std::string(), *file);
  }
  std::shared_ptr<grantry::SessionStore> reopened(grantry::MakeFileSessionStoreAt(path));
  CHECK(AnchorOrFallback(std::string(), *reopened) == kept);
  // ⚠️ NOT IN THE SESSION'S SLOT, where it would be presented as a session.
  CHECK(!reopened->Read().has_value());
  std::remove((path + ".device").c_str());

  // A store written before the slot keeps nothing: a new device each run, never a shared one.
  OldStore old;
  const std::string unkept = AnchorOrFallback(std::string(), old);
  CHECK(unkept.rfind("fallback:", 0) == 0);
  CHECK(AnchorOrFallback(std::string(), old) != unkept);
}

/*
 * ⚠️ ONE CLIENT VERIFIES FROM SEVERAL THREADS, AND THE KEY CACHE WAS NOT GUARDED
 * (12 October 2026). GetIdentity serialised its own mints, but a variable or file
 * read verified beside it, and WatchPlans mints on a thread of its own — while
 * GetKey handed out a pointer into a map that a fetch replaces wholesale. Sixteen
 * threads meet a cold cache together here: every one verifies, and the signing
 * keys are fetched once rather than once each.
 */
void TestJwksAcrossThreads() {
  Section("signing keys across threads");

  TestKey key;
  std::atomic<int> fetches{0};
  JwksCache cache(
      [&](std::string& body, std::string&) {
        ++fetches;
        // Long enough that every thread arrives while the first fetch is still out.
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        body = Jwks(key, "k1");
        return true;
      },
      3600, {});
  TokenVerifier verifier(&cache, kIssuer, 30, {});

  // Minted up front: the test key is not what is under test.
  constexpr int kThreads = 16;
  std::vector<std::string> tokens;
  std::vector<std::string> nonces;
  for (int i = 0; i < kThreads; i++) {
    TokenSpec spec;
    spec.kid = "k1";
    spec.nonce = "a-nonce-for-thread-" + std::to_string(i) + "-long-enough-to-be-real";
    nonces.push_back(spec.nonce);
    tokens.push_back(Mint(key, spec));
  }

  std::atomic<int> verified{0};
  std::vector<std::thread> threads;
  for (int i = 0; i < kThreads; i++) {
    threads.emplace_back([&, i] {
      if (verifier.Verify(tokens[i], kEnvironment, nonces[i]).ok()) ++verified;
    });
  }
  for (std::thread& thread : threads) thread.join();

  CHECK(verified.load() == kThreads);
  CHECK(fetches.load() == 1);
  CHECK(cache.fetch_count() == 1);
}

/*
 * ⚠️ THE TRANSPORT PROBE LATCHED EVERY FAILURE (until 12 October 2026). With
 * pinning on — the default for the real API — a client whose first proof failed
 * for any reason refused every call for the rest of its life, so an application
 * started offline stayed offline after the network came back. Now only a pin
 * that does not match is latched; anything else fails that one call, sends
 * nothing past the probe, and is proved again on the next.
 */
void TestTransportProbeRetries() {
  Section("transport probe");

  std::atomic<int> jwks_asked{0};
  CannedHttpServer server([&](const CannedHttpServer::Received& request) {
    CannedHttpServer::Reply reply;
    if (request.path == "/v1/.well-known/jwks.json") {
      // The first answer is more than any JSON read may be: a transport failure, not a pin's.
      reply.body = jwks_asked++ == 0 ? std::string(2 * 1024 * 1024, 'x') : "{\"keys\":[]}";
      return reply;
    }
    if (request.path == "/v1/client/environment") {
      reply.body = "{\"environment\":{\"applicationName\":\"Probe\"}}";
      return reply;
    }
    reply.status = 404;
    reply.body = "{}";
    return reply;
  });
  CHECK(server.ok());
  if (!server.ok()) return;

  grantry::Options options;
  options.publishable_key = "pk_test_abcdefghijklmnop";
  options.environment_id = kEnvironment;
  options.api_base_url = server.url();
  options.allow_insecure_loopback = true;
  options.connect_on_start = false;
  // Pinning on, so the probe runs. Over plain HTTP there is no certificate to
  // compare, which is what lets this exercise everything but the comparison.
  options.pin_certificate = true;
  options.certificate_pins = {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="};
  options.session_store = grantry::MakeInMemorySessionStore();
  Result<std::shared_ptr<grantry::Client>> created = grantry::Client::Create(options);
  CHECK(created.ok());
  if (!created.ok()) return;
  std::shared_ptr<grantry::Client> client = *created.value;

  auto environment_requests = [&] {
    int count = 0;
    for (const auto& request : server.received()) {
      if (request.path == "/v1/client/environment") count++;
    }
    return count;
  };

  Result<grantry::Environment> first = client->GetEnvironment();
  CHECK(!first.ok());
  CHECK(first.error.kind == grantry::ErrorKind::kTransport);
  // Nothing went out past the probe that failed.
  CHECK(environment_requests() == 0);

  Result<grantry::Environment> second = client->GetEnvironment();
  CHECK(second.ok());
  CHECK(jwks_asked.load() == 2);
  CHECK(environment_requests() == 1);

  // Proved once, then not asked again.
  CHECK(client->GetEnvironment().ok());
  CHECK(jwks_asked.load() == 2);
}

/// Remove a folder by its UTF-8 name, as the store's own code names it.
void RemoveFolder(const std::string& utf8) {
#ifdef _WIN32
  const int length = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
  std::wstring wide(static_cast<std::size_t>(length), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &wide[0], length);
  RemoveDirectoryW(wide.c_str());
#else
  ::rmdir(utf8.c_str());
#endif
}

/*
 * ⚠️ A SESSION IN A FOLDER WHOSE NAME IS NOT ASCII WAS NEVER SAVED ON WINDOWS
 * (until 12 October 2026). The folder was made through the wide API from UTF-8,
 * and the file was then opened with std::fopen — which reads a narrow path in
 * the ANSI code page — so `ü` became `Ã¼`, a folder that did not exist, and the
 * write failed in silence. Every user whose profile is called José signed in on
 * every launch. Written as escapes so no editor can change what is tested.
 */
void TestFileStoreUnicodeFolder() {
  Section("session file in a non-ASCII folder");

  const std::string folder =
      std::string("grantry-test-\xC3\xBC\xC5\x81-") + std::to_string(UnixNow());
  const std::string path = folder + "/session";
  {
    std::shared_ptr<grantry::SessionStore> store(grantry::MakeFileSessionStoreAt(path));
    store->Write("sess_unicode");
  }

  std::shared_ptr<grantry::SessionStore> reopened(grantry::MakeFileSessionStoreAt(path));
  CHECK(reopened->Read().value_or("") == "sess_unicode");

  // Replaced in place: the second value, whole, and no temporary left beside it.
  reopened->Write("sess_second");
  std::shared_ptr<grantry::SessionStore> third(grantry::MakeFileSessionStoreAt(path));
  CHECK(third->Read().value_or("") == "sess_second");
  CHECK(!grantry::internal::ReadFileBytes(path + ".tmp").has_value());

  third->Clear();
  CHECK(!third->Read().has_value());
  grantry::internal::RemoveFile(path + ".device");
  RemoveFolder(folder);
}

/*
 * ⚠️ A CALLBACK THAT THROWS RAN ON A THREAD OF THE SDK'S OWN, where an escaping
 * exception is std::terminate: the application ended because its redraw had a
 * bug (until 12 October 2026). It is caught and dropped now, and the watch goes
 * on to call again at the next change.
 */
void TestWatchPlansCallbackThrows() {
  Section("a watch whose callback throws");

  AccountApi api;
  std::shared_ptr<grantry::Client> client = AccountClient(api);
  CHECK(client != nullptr);
  if (!client) return;
  CHECK(client->SignIn("ada@example.test", "hunter2hunter2").ok());

  std::atomic<int> calls{0};
  client->WatchPlans([&calls] {
    ++calls;
    throw std::runtime_error("the application's own bug");
  });

  auto wait_for = [](const std::function<bool()>& done) {
    for (int i = 0; i < 100 && !done(); ++i) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return done();
  };

  CHECK(wait_for([&] { return api.polled() >= 2; }));
  api.set_plans_version("v2");
  CHECK(wait_for([&] { return calls.load() >= 1; }));
  api.set_plans_version("v3");
  CHECK(wait_for([&] { return calls.load() >= 2; }));
  client->StopWatchingPlans();
}

/*
 * ⚠️ A CONNECTION DROPPED PART-WAY THROUGH A BODY WAS A SUCCESS ON WINDOWS
 * (until 12 October 2026): both reads broke out of the loop and returned true
 * with whatever had arrived. This server promises a thousand bytes, sends a
 * dozen and hangs up.
 */
void TestTruncatedBody() {
  Section("a body cut short");

#ifdef _WIN32
  using Socket = SOCKET;
  const Socket invalid = INVALID_SOCKET;
  auto close_socket = [](Socket s) { ::closesocket(s); };
  WSADATA data;
  WSAStartup(MAKEWORD(2, 2), &data);
#else
  using Socket = int;
  const Socket invalid = -1;
  auto close_socket = [](Socket s) { ::close(s); };
#endif

  Socket listener = ::socket(AF_INET, SOCK_STREAM, 0);
  CHECK(listener != invalid);
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
#ifdef _WIN32
  int length = sizeof(address);
#else
  socklen_t length = sizeof(address);
#endif
  const bool bound = ::bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0 &&
                     ::listen(listener, 1) == 0 &&
                     ::getsockname(listener, reinterpret_cast<sockaddr*>(&address), &length) == 0;
  CHECK(bound);

  std::thread server([&] {
    Socket accepted = ::accept(listener, nullptr, nullptr);
    if (accepted == invalid) return;
    std::string head;
    char chunk[1024];
    while (head.find("\r\n\r\n") == std::string::npos) {
      int n = static_cast<int>(::recv(accepted, chunk, static_cast<int>(sizeof(chunk)), 0));
      if (n <= 0) break;
      head.append(chunk, static_cast<std::size_t>(n));
    }
    const std::string reply =
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n"
        "Connection: close\r\n\r\n{\"partial\":";
    ::send(accepted, reply.data(), static_cast<int>(reply.size()), 0);
    close_socket(accepted);
  });

  grantry::internal::HttpRequest request;
  request.method = "GET";
  request.url = "http://127.0.0.1:" + std::to_string(ntohs(address.sin_port)) + "/v1/client/x";
  request.allow_insecure = true;
  request.timeout_seconds = 10;
  grantry::internal::HttpResponse response;
  std::string error;
  CHECK(!grantry::internal::HttpSend(request, response, error));
  CHECK(!error.empty());

  server.join();
  close_socket(listener);
#ifdef _WIN32
  WSACleanup();
#endif
}

/*
 * The build challenge (migration 0362): this process reads a slice of its own file and answers
 * HMAC-SHA256 keyed by the slice's SHA-256, over the server's nonce. The server's arithmetic is held
 * against a value Python computed, and the slice against the executable's own first bytes.
 */
void TestBuildChallenge() {
  Section("the build challenge");

  // The proof's arithmetic, as the server does it (lib/build-challenge.ts).
  std::vector<std::uint8_t> mac;
  const std::string slice = "grantry-slice";
  const std::string nonce = "fresh-nonce-123";
  CHECK(grantry::internal::HmacSha256(grantry::internal::Sha256(slice),
                                      std::vector<std::uint8_t>(nonce.begin(), nonce.end()), mac));
  CHECK(grantry::internal::Hex(mac) ==
        "fc3c0abe3211a69aad149e6e0bf6334ccf17a15bcf6a6b40d61890b788758a0a");

  // The slice is this program's own file: an executable's magic at the start.
  std::vector<std::uint8_t> head;
  CHECK(grantry::internal::ReadApplicationSlice(0, 4, head));
#ifdef _WIN32
  CHECK(head.size() == 4 && head[0] == 'M' && head[1] == 'Z');
#elif defined(__APPLE__)
  CHECK(head.size() == 4);
#else
  CHECK(head.size() == 4 && head[0] == 0x7F && head[1] == 'E' && head[2] == 'L' && head[3] == 'F');
#endif

  // The same slice twice is the same bytes, and a slice it cannot read whole is refused.
  std::vector<std::uint8_t> first;
  std::vector<std::uint8_t> second;
  CHECK(grantry::internal::ReadApplicationSlice(512, 256, first));
  CHECK(grantry::internal::ReadApplicationSlice(512, 256, second));
  CHECK(first == second);
  std::vector<std::uint8_t> refused;
  CHECK(!grantry::internal::ReadApplicationSlice(-1, 16, refused));
  CHECK(!grantry::internal::ReadApplicationSlice(0, 0, refused));
  CHECK(!grantry::internal::ReadApplicationSlice(0, 70000, refused));
  CHECK(!grantry::internal::ReadApplicationSlice(std::int64_t(1) << 40, 16, refused));
}

int main() {
#ifndef _WIN32
  // The fake servers here write to clients that hang up on purpose — the body
  // ceiling, the transport probe — and a write to a closed socket is SIGPIPE,
  // which ends the suite rather than failing a check.
  std::signal(SIGPIPE, SIG_IGN);
#endif
  std::printf("grantry-cpp %s\n\n", grantry::Version());

  TestEncoding();
  TestBuildChallenge();
  TestDerivations();
  TestAesGcm();
  TestPinningPolicy();
  TestBuiltInPinsAreTheirRoots();
  TestLivePinning();
  TestJson();
  TestPasswordUpdate();
  TestBackupCodeView();
  TestVerification();
  TestSignedResources();
  TestDeviceAnchor();
  TestOptions();
  TestConnectsOnStart();
  TestStartSso();
  TestRedirectRules();
  TestLoopbackListener();
  TestSignInWithRedirect();
  TestSessionStore();
  TestTrustedDevice();
  TestAccountProofs();
  TestIdentityFollowsTheAccount();
  TestRequiresPlanFromTheMint();
  TestWatchPlans();
  TestWatchPlansSignInAfterStart();
  TestSignUpAcceptedLegal();
  TestBodyCeiling();
  TestDeviceFallback();
  TestJwksAcrossThreads();
  TestTransportProbeRetries();
  TestFileStoreUnicodeFolder();
  TestWatchPlansCallbackThrows();
  TestTruncatedBody();

  std::printf("\n%d checks, %d failures\n", g_checks, g_failures);
  return g_failures == 0 ? 0 : 1;
}
