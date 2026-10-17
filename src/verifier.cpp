#include "internal.hpp"

#include <algorithm>
#include <cstring>

namespace grantry {

namespace {

Error Fail(VerificationFailure reason, std::string message) {
  Error error;
  error.kind = ErrorKind::kVerification;
  error.verification = reason;
  error.message = std::move(message);
  return error;
}

std::vector<std::string> Split(const std::string& text, char separator) {
  std::vector<std::string> parts;
  std::size_t start = 0;
  while (true) {
    std::size_t position = text.find(separator, start);
    if (position == std::string::npos) {
      parts.push_back(text.substr(start));
      return parts;
    }
    parts.push_back(text.substr(start, position - start));
    start = position + 1;
  }
}

bool Contains(const std::vector<std::string>& values, const std::string& needle) {
  return std::find(values.begin(), values.end(), needle) != values.end();
}

/// `aud` is a string or an array of strings, per RFC 7519.
///
/// Both shapes are handled because a verifier that only understands the string
/// form silently rejects every token from a server that grew a second audience
/// — which looks, from the client, exactly like an attack.
bool AudienceMatches(const internal::Json& claims, const std::string& expected) {
  const internal::Json* aud = claims.Find("aud");
  if (aud == nullptr) return false;

  if (aud->is_string()) return aud->string == expected;

  if (aud->is_array()) {
    for (const internal::Json& entry : aud->array) {
      if (entry.is_string() && entry.string == expected) return true;
    }
  }
  return false;
}

std::optional<std::string> OptionalString(const internal::Json& claims,
                                          const std::string& key) {
  return claims.GetString(key);
}

}  // namespace

TokenVerifier::TokenVerifier(internal::JwksCache* jwks, std::string issuer,
                             int clock_skew_seconds, std::vector<std::string> pins)
    : jwks_(jwks),
      issuer_(std::move(issuer)),
      clock_skew_seconds_(clock_skew_seconds),
      pins_(std::move(pins)) {}

Status TokenVerifier::VerifyEnvelope(const std::string& token,
                                     const std::string& expected_audience,
                                     const std::string& expected_nonce,
                                     std::int64_t maximum_lifetime,
                                     internal::Json& payload) {
  Status status;

  std::vector<std::string> parts = Split(token, '.');
  if (parts.size() != 3) {
    status.error = Fail(VerificationFailure::kMalformed, "The token was not a compact JWS.");
    return status;
  }

  /*
   * ⚠️ THE HEADER IS DECODED AND THE ALGORITHM IS CHECKED BEFORE ANYTHING ELSE
   * IS TOUCHED.
   *
   * Order matters here for a reason that is easy to miss: an `alg: none` token
   * has an EMPTY signature segment, so a verifier that decodes all three parts
   * up front rejects it as malformed — refused, but for the wrong reason, and
   * the operator reading the log learns "bad base64" rather than "something
   * handed us an unsigned token". Policy first, parsing second.
   */
  std::vector<std::uint8_t> header_bytes;
  if (!internal::Base64UrlDecode(parts[0], header_bytes)) {
    status.error = Fail(VerificationFailure::kMalformed,
                        "The token's header was not valid base64url.");
    return status;
  }

  internal::Json header;
  if (!internal::Json::Parse(std::string(header_bytes.begin(), header_bytes.end()), header)) {
    status.error = Fail(VerificationFailure::kMalformed, "The token's header was not JSON.");
    return status;
  }

  std::string algorithm = header.GetString("alg").value_or(std::string());
  std::string kid = header.GetString("kid").value_or(std::string());

  /*
   * ⚠️ THE ALGORITHM COMES FROM POLICY, NEVER FROM THE TOKEN.
   *
   * This one comparison is the algorithm-confusion attack. A verifier that
   * dispatches on the header's `alg` accepts `none` — no signature at all — and
   * accepts `HS256`, where the "secret" is the RSA public key the attacker
   * simply downloaded from the JWKS.
   */
  if (algorithm != "RS256") {
    status.error = Fail(VerificationFailure::kUnexpectedAlgorithm,
                        "The token was signed with \"" + algorithm
                            + "\"; this SDK only accepts RS256.");
    return status;
  }

  if (kid.empty()) {
    status.error = Fail(VerificationFailure::kMalformed,
                        "The token header carried no key id.");
    return status;
  }

  std::vector<std::uint8_t> payload_bytes;
  std::vector<std::uint8_t> signature;
  if (!internal::Base64UrlDecode(parts[1], payload_bytes)
      || !internal::Base64UrlDecode(parts[2], signature) || signature.empty()) {
    status.error = Fail(VerificationFailure::kMalformed,
                        "The token was not valid base64url.");
    return status;
  }

  std::string jwks_error;
  internal::SigningKey found_key;
  if (!jwks_->GetKey(kid, found_key, jwks_error)) {
    status.error = Fail(VerificationFailure::kUnknownKey,
                        jwks_error.empty()
                            ? "No published signing key matches \"" + kid + "\"."
                            : jwks_error);
    return status;
  }
  const internal::SigningKey* key = &found_key;

  if (!pins_.empty() && !Contains(pins_, key->thumbprint)) {
    // Belt and braces: the cache filters pinned keys on fetch, so reaching here
    // means the two disagree. Refuse rather than reconcile.
    status.error = Fail(VerificationFailure::kUnpinnedKey,
                        "The signing key is not one of the pinned thumbprints.");
    return status;
  }

  // Everything up to this point is untrusted input. Nothing from the payload is
  // read until the signature says the payload is ours.
  std::string signing_input = parts[0] + "." + parts[1];
  std::vector<std::uint8_t> message(signing_input.begin(), signing_input.end());

  if (!internal::RsaSha256Verify(key->modulus, key->exponent, message, signature)) {
    status.error = Fail(
        VerificationFailure::kBadSignature,
        "The token's signature did not verify. Treat this as an attack, not a retryable error.");
    return status;
  }

  internal::Json claims;
  if (!internal::Json::Parse(std::string(payload_bytes.begin(), payload_bytes.end()), claims)) {
    status.error = Fail(VerificationFailure::kMalformed, "The token's payload was not JSON.");
    return status;
  }

  std::string issuer = claims.GetString("iss").value_or(std::string());
  if (issuer != issuer_) {
    status.error = Fail(VerificationFailure::kWrongIssuer,
                        "The token was issued by \"" + issuer + "\", not \"" + issuer_ + "\".");
    return status;
  }

  if (!AudienceMatches(claims, expected_audience)) {
    status.error = Fail(
        VerificationFailure::kWrongAudience,
        "The token belongs to a different application. Every environment shares one "
        "signing key, so the audience is what distinguishes them.");
    return status;
  }

  std::optional<std::int64_t> exp = claims.GetInt("exp");
  if (!exp.has_value()) {
    status.error = Fail(VerificationFailure::kMalformed, "The token carried no expiry.");
    return status;
  }

  std::int64_t now = internal::UnixNow();

  /*
   * ⚠️ THE SIXTY-SECOND TTL IS THE ENTITLEMENT-REVOCATION MECHANISM,
   * AND NOTHING ON THIS SIDE USED TO ENFORCE IT.
   *
   * A plan and its features ride on this token, and the only reason a cancelled
   * subscription stops working within a minute is that the token expires and
   * the next one says something different. Reading `exp` straight off the
   * payload and caching until then meant a token minted with a distant expiry
   * would be trusted for exactly as long as it claimed — turning one signing
   * bug, or one compromised key, into a permanent licence.
   *
   * The ceiling is the caller's: fifteen minutes for an access token, which is
   * fifteen times what the server issues and leaves room to lengthen the real
   * TTL without shipping new clients, and two minutes for a resource envelope,
   * which the server mints for thirty seconds. Refused rather than
   * clamped: clamping would keep working with a token that should never have
   * existed and hide the fact that something is minting them. Measured from now
   * rather than from `iat`, because `iat` is a claim the same signer chose.
   */
  if (*exp + clock_skew_seconds_ < now) {
    status.error = Fail(VerificationFailure::kExpired, "The token has expired.");
    return status;
  }

  if (*exp - now > maximum_lifetime + clock_skew_seconds_) {
    status.error = Fail(
        VerificationFailure::kLifetimeTooLong,
        "The token claims a lifetime this SDK will not trust. Access tokens are minutes long "
        "by design; a long-lived one defeats the revocation model and is treated as an attack.");
    return status;
  }

  std::optional<std::int64_t> nbf = claims.GetInt("nbf");
  if (!nbf.has_value()) nbf = claims.GetInt("iat");
  if (nbf.has_value() && *nbf - clock_skew_seconds_ > now) {
    status.error = Fail(VerificationFailure::kExpired,
                        "The token is not valid yet. Check this machine's clock.");
    return status;
  }

  /*
   * ⚠️ THE REPLAY CHECK, AND THE REASON IT IS NOT OPTIONAL WHEN A NONCE WAS
   * SENT.
   *
   * Every other claim here is true of the SESSION rather than of this request,
   * so a token captured from a real, paying user verifies perfectly on any
   * machine for its full sixty seconds. Feeding one recording to every cracked
   * copy of an application would work, and the signature check would happily
   * agree each time. The nonce is the only claim that says "minted in answer to
   * the request you just made" — so a missing one is as damning as a wrong one.
   */
  if (!expected_nonce.empty()) {
    std::optional<std::string> returned = claims.GetString("nonce");
    if (!returned.has_value() || !internal::FixedTimeEquals(*returned, expected_nonce)) {
      status.error = Fail(
          VerificationFailure::kReplayedNonce,
          "The token did not carry back this request's nonce. It is a replay of a "
          "response minted for a different request.");
      return status;
    }
  }

  payload = std::move(claims);
  return status;
}

/// The ceiling on an access token, in seconds.
///
/// Fifteen times what the server issues, so the real TTL can be lengthened
/// without shipping new clients, while still bounding what a bad token can buy
/// to minutes rather than years.
static constexpr std::int64_t kMaximumTokenLifetimeSeconds = 15 * 60;

/// The ceiling on a signed variable or file envelope, in seconds.
///
/// Tighter, because an envelope says less: it is a statement about what one
/// value was at one moment, and the server mints it for thirty seconds. Two
/// minutes leaves room for that to change without shipping new clients, while
/// keeping a captured envelope worthless by the time anybody has looked at it.
static constexpr std::int64_t kMaximumResourceLifetimeSeconds = 2 * 60;

Result<Identity> TokenVerifier::Verify(const std::string& token,
                                       const std::string& expected_audience,
                                       const std::string& expected_nonce) {
  Result<Identity> result;

  internal::Json claims;
  Status verified = VerifyEnvelope(token, expected_audience, expected_nonce,
                                   kMaximumTokenLifetimeSeconds, claims);
  if (!verified.ok()) {
    result.error = verified.error;
    return result;
  }

  // Re-read rather than threaded back out. These are the same claims the checks
  // above ran over, and they were covered by a signature already verified.
  const std::int64_t exp_value = claims.GetInt("exp").value_or(0);

  Identity identity;
  identity.access_token_ = token;
  identity.user_id_ = claims.GetString("sub").value_or(std::string());
  identity.session_id_ = claims.GetString("sid").value_or(std::string());
  identity.environment_id_ = claims.GetString("env").value_or(std::string());
  identity.email_verified_ = claims.GetBool("ev");
  identity.expires_at_ = exp_value;

  /*
   * ⚠️ FALLS BACK TO `exp` MINUS THE LIFETIME, NEVER TO THE LOCAL CLOCK.
   *
   * A token without `iat` is unusual but legal, and defaulting to time(nullptr)
   * would quietly hand back the very clock this value exists to replace — the
   * one case where it matters most would be the one case it fails at.
   */
  const std::optional<std::int64_t> issued = claims.GetInt("iat");
  identity.server_time_ =
      issued.has_value() ? *issued : exp_value - kMaximumTokenLifetimeSeconds;

  identity.plan_key_ = OptionalString(claims, "pln");
  identity.features_ = claims.GetStringArray("fea");
  /*
   * ⚠️ `pls` ONLY WHEN MORE THAN ONE PLAN IS HELD — the API leaves it off
   * otherwise — so its absence is one plan or none, never "unknown".
   */
  identity.plan_keys_ = claims.GetStringArray("pls");
  if (identity.plan_keys_.empty() && identity.plan_key_.has_value()) {
    identity.plan_keys_.push_back(*identity.plan_key_);
  }
  identity.requirements_ = claims.GetStringArray("req");

  result.value = std::move(identity);
  return result;
}

Status TokenVerifier::VerifyResource(const std::string& envelope,
                                     const ResourceExpectation& expected) {
  internal::Json claims;
  Status status = VerifyEnvelope(envelope, expected.audience, expected.nonce,
                                 kMaximumResourceLifetimeSeconds, claims);
  if (!status.ok()) return status;

  const std::string kind = claims.GetString("kind").value_or(std::string());
  const std::string key = claims.GetString("key").value_or(std::string());

  if (kind != expected.kind || key != expected.key) {
    status.error = Fail(VerificationFailure::kWrongResource,
                        "The signature covers " + kind + " \"" + key + "\", not "
                            + expected.kind + " \"" + expected.key
                            + "\". A signature moved from one resource onto another is a "
                              "substitution attempt.");
    return status;
  }

  if (!expected.subject.empty()) {
    const std::string subject = claims.GetString("sub").value_or(std::string());
    if (!internal::FixedTimeEquals(subject, expected.subject)) {
      status.error = Fail(VerificationFailure::kWrongResource,
                          "The signature was minted for a different user. It is a replay of "
                          "somebody else's response.");
      return status;
    }
  }

  /*
   * ⚠️ THE LAST CHECK, AND THE ONE THE OTHERS EXIST TO MAKE MEANINGFUL.
   * Everything above establishes that this envelope is ours, fresh, for this
   * application, this user and this key. This line is where that finally says
   * something about the VALUE: the bytes the caller is holding hash to what the
   * server signed.
   */
  const std::string digest = claims.GetString("dig").value_or(std::string());
  if (!internal::FixedTimeEquals(digest, expected.digest)) {
    status.error = Fail(VerificationFailure::kContentMismatch,
                        "The value did not match the one Grantry signed. Something between "
                        "this application and the API changed it.");
    return status;
  }

  return status;
}

// ---------------------------------------------------------------------------
// Identity predicates
// ---------------------------------------------------------------------------

bool Identity::has_feature(const std::string& key) const {
  return Contains(features_, key);
}

bool Identity::has_plan(const std::string& key) const {
  return Contains(plan_keys_, key);
}

// ---------------------------------------------------------------------------
// JWKS cache
// ---------------------------------------------------------------------------

namespace internal {

namespace {
// See the class comment: an unknown `kid` is attacker-controlled, so the
// refetch it triggers has to have a floor under it.
constexpr std::int64_t kMinimumRefreshSeconds = 60;

/// The smallest RSA modulus this library will verify against.
///
/// ⚠️ A 512-BIT KEY FACTORS ON A LAPTOP. Accepting whatever the JWKS serves
/// would let anybody who can serve one hand this client a key they can also
/// forge with — a downgrade attack that needs no patching at all.
constexpr std::size_t kMinimumModulusBytes = 256;  // 2048 bits
}  // namespace

JwksCache::JwksCache(std::string url, int lifetime_seconds, std::vector<std::string> pins,
                     int timeout_seconds, bool allow_insecure,
                     std::vector<std::string> certificate_pins)
    : JwksCache(
          [url, timeout_seconds, allow_insecure,
           certificate_pins = std::move(certificate_pins)](std::string& body, std::string& error) {
            HttpRequest request;
            request.method = "GET";
            request.url = url;
            request.timeout_seconds = timeout_seconds;
            request.allow_insecure = allow_insecure;
            // ⚠️ THE TRANSPORT'S PINS TOO. This fetch decides which keys every
            // token is checked against, so it is the last request that should
            // trust whatever certificate the machine's store accepts.
            request.certificate_pins = certificate_pins;

            HttpResponse response;
            if (!HttpSend(request, response, error)) return false;
            if (response.status < 200 || response.status >= 300) {
              error = "Could not fetch the signing keys.";
              return false;
            }
            body = response.body;
            return true;
          },
          lifetime_seconds, std::move(pins)) {}

JwksCache::JwksCache(Fetcher fetcher, int lifetime_seconds, std::vector<std::string> pins)
    : fetcher_(std::move(fetcher)),
      lifetime_seconds_(lifetime_seconds),
      pins_(std::move(pins)) {}

bool JwksCache::GetKey(const std::string& kid, SigningKey& out, std::string& error) {
  std::lock_guard<std::mutex> lock(mutex_);

  std::int64_t now = UnixNow();
  bool fresh = now - fetched_at_ < lifetime_seconds_;

  auto found = keys_.find(kid);
  if (fresh && found != keys_.end()) {
    out = found->second;
    return true;
  }

  if (now - last_attempt_at_ < kMinimumRefreshSeconds) {
    // Inside the floor. Answer from what is cached, even if it is stale — the
    // alternative is letting forged tokens set this client's request rate.
    if (found == keys_.end()) return false;
    out = found->second;
    return true;
  }

  if (!Fetch(error)) return false;

  found = keys_.find(kid);
  if (found == keys_.end()) return false;
  out = found->second;
  return true;
}

int JwksCache::fetch_count() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return fetch_count_;
}

/// Called with `mutex_` held.
bool JwksCache::Fetch(std::string& error) {
  last_attempt_at_ = UnixNow();
  fetch_count_++;

  std::string body;
  if (!fetcher_(body, error)) return false;

  Json document;
  if (!Json::Parse(body, document)) {
    error = "The JWKS was not JSON.";
    return false;
  }

  const Json* keys = document.Find("keys");
  if (keys == nullptr || !keys->is_array()) {
    error = "The JWKS had no \"keys\" array.";
    return false;
  }

  std::map<std::string, SigningKey> parsed;
  for (const Json& entry : keys->array) {
    if (entry.GetString("kty").value_or(std::string()) != "RSA") continue;

    std::optional<std::string> n = entry.GetString("n");
    std::optional<std::string> e = entry.GetString("e");
    std::optional<std::string> kid = entry.GetString("kid");
    if (!n.has_value() || !e.has_value() || !kid.has_value()) continue;

    /*
     * ⚠️ AN `alg` OF ANYTHING BUT RS256 IS SKIPPED, not adapted to. Verifying a
     * key that advertises a different algorithm as RS256 anyway would be
     * deciding the algorithm from the key rather than from policy.
     */
    std::optional<std::string> alg = entry.GetString("alg");
    if (alg.has_value() && *alg != "RS256") continue;

    SigningKey key;
    if (!Base64UrlDecode(*n, key.modulus)) continue;
    if (!Base64UrlDecode(*e, key.exponent)) continue;
    if (key.modulus.size() < kMinimumModulusBytes) continue;

    key.kid = *kid;
    key.thumbprint = RsaThumbprint(*n, *e);

    if (!pins_.empty()
        && std::find(pins_.begin(), pins_.end(), key.thumbprint) == pins_.end()) {
      continue;
    }

    parsed[key.kid] = std::move(key);
  }

  /*
   * ⚠️ AN EMPTY PARSE MUST NOT REPLACE A WORKING CACHE.
   *
   * Every key in the document can be skipped for ordinary reasons: a response
   * served mid-rotation, a key type this SDK does not implement, a pin list
   * that matches none of them. Assigning unconditionally turned any of those
   * into an emptied cache — and because the refetch floor is a minute, the
   * next sixty seconds of verification would fail and be reported to the
   * application as an attack. Keeping the previous keys is strictly better:
   * they were valid a moment ago, and a genuinely rotated-away key fails as an
   * unknown kid, which is the honest answer.
   */
  if (parsed.empty() && !keys_.empty()) {
    // Reported as success: the fetch worked, the document was simply unusable,
    // and the caller's next lookup falls back to the keys already held.
    return true;
  }

  keys_ = std::move(parsed);
  fetched_at_ = UnixNow();
  return true;
}

}  // namespace internal
}  // namespace grantry
