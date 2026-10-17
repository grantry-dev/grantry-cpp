// Grantry — identity, access and entitlements for native applications.
//
// ## Read sdks/SECURITY.md before building anything on this
//
// The short version: this library's job is not to tell you whether the user is
// allowed. A boolean returned into a binary the attacker owns is a boolean the
// attacker owns. Its job is to obtain a SIGNED STATEMENT from the server and
// hand it to you intact, so the decision can be made somewhere they do not
// control — your own backend.
//
// ## Why there are no third-party dependencies
//
// A desktop SDK that drags in libcurl and OpenSSL is one a games studio cannot
// ship: every shared library is another thing to reconcile against whatever the
// engine already loaded, another CVE to chase, and on Windows another DLL to
// put beside the executable. So the transport and the cryptography come from
// the operating system:
//
//   Windows   WinHTTP for TLS (Schannel, system trust store) and BCrypt/CNG
//             for RSA and SHA-256. Both are in-box on every supported version.
//   POSIX     libcurl and OpenSSL, which are the system libraries there.
//
// One header, one implementation per platform, and no package manager.
//
// ## Threading
//
// A `Client` is safe to use from several threads. Everything mutable behind it
// is guarded, and the token cache is refreshed under a lock so twenty threads
// asking at once produce one request rather than twenty.

#ifndef GRANTRY_GRANTRY_HPP
#define GRANTRY_GRANTRY_HPP

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace grantry {

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

enum class ErrorKind {
  kNone = 0,
  /// The library was configured in a way that cannot work.
  kConfiguration,
  /// The network call failed, or TLS did.
  kTransport,
  /// The API refused the request. See `Error::status`.
  kApi,
  /// Nobody is signed in.
  kNotSignedIn,
  /// The application is closed for maintenance. Show a wait screen, not an error.
  ///
  /// Its own kind rather than a `kApi` with `status == 503`, because a 503 also
  /// comes from a load balancer with nothing behind it — and telling a user
  /// "we are doing maintenance" when the truth is "the server is down" is a
  /// lie this library would be inventing. Only the API sends the code that
  /// produces this kind.
  ///
  /// ⚠️ `Error::message` IS STILL UNVERIFIED, even though it is normally the
  /// sentence the merchant typed. Render it as plain text — never as markup,
  /// and never as a link the user can follow.
  kMaintenance,
  /// A response failed verification. TREAT AS AN ATTACK — see below.
  kVerification,
  /// The caller passed something this library will not send.
  ///
  /// A mistake in the calling code, not a decision by the server — the request
  /// was never made. Appended to the end of this enum deliberately, so that
  /// adding it did not renumber the kinds an already-compiled caller stores.
  kInvalidArgument,
  /// Signed in, but holding no plan this application accepts.
  ///
  /// ⚠️ THE SESSION IS REAL AND SIGNING IN AGAIN WILL NOT HELP. Treating
  /// this as an authentication failure sends somebody round a loop they have
  /// already completed. Show your activate-a-code screen and call `Activate`.
  ///
  /// ⚠️ THE SERVER REFUSES, NOT THIS LIBRARY. Variables, files, relays and
  /// profile calls all come back this way while it applies, so a build that
  /// ignores the kind gains nothing — what still works is `Activate`,
  /// `GetIdentity` and `SignOut`.
  ///
  /// Appended for the same reason `kInvalidArgument` was: adding it must not
  /// renumber the kinds an already-compiled caller stores.
  kPlanRequired,
  /// A redirect sign-in did not come back as a sign-in. `Error::code` says why,
  /// from a vocabulary shared with the C# and Python SDKs:
  ///
  ///   timeout               nobody came back before the timeout. Closing the
  ///                         browser looks exactly like this: a closed tab sends
  ///                         nothing.
  ///   cancelled             `RedirectOptions::cancelled` answered true.
  ///   issuer_mismatch       the answer named another sign-in URL (RFC 9207).
  ///                         Nothing was exchanged.
  ///   invalid_response      the answer carried no code and no error.
  ///   browser_unavailable   the browser could not be opened.
  ///   not_offered           the environment publishes no sign-in URL, or one this
  ///                         SDK will not open.
  ///   listener_unavailable  no loopback port could be opened.
  ///
  /// Anything else is the hosted sign-in's own OAuth error, passed through:
  /// `access_denied` (Cancel on "Continue as" too), `login_required`,
  /// `server_error`.
  ///
  /// Once the code reaches the API, a refusal is `kApi` like any other sign-in's:
  /// an expired code, a device limit, an unrecognised build. Appended, like the
  /// two before it.
  kRedirect,
};

/// Which verification check failed. Only meaningful for `kVerification`.
enum class VerificationFailure {
  kNone = 0,
  kMalformed,
  /// The header named an algorithm other than RS256.
  ///
  /// The algorithm-confusion attack lives here: a verifier that believes the
  /// token about how to check the token accepts `alg: none`, and accepts an
  /// HMAC keyed with the very public key it was meant to verify against.
  kUnexpectedAlgorithm,
  kUnknownKey,
  kBadSignature,
  kWrongIssuer,
  /// The token belongs to a different application on the same instance.
  kWrongAudience,
  kExpired,
  /// The nonce did not match the one this request generated.
  ///
  /// The signal that a response was replayed. Every other claim in a token is
  /// true of the SESSION rather than the request, so a recording from a real
  /// subscriber verifies perfectly — this is the check it fails.
  kReplayedNonce,
  kUnpinnedKey,
  /// The token claimed a lifetime this SDK will not trust.
  ///
  /// Access tokens are seconds long by design: their expiry is what makes a
  /// cancelled subscription stop working promptly. One claiming hours or days
  /// defeats that, so it is refused rather than accepted for a shorter
  /// period — a token that should not exist is evidence, not something to
  /// work around.
  kLifetimeTooLong,
  /// The envelope covered a different resource than the one asked for.
  ///
  /// A signature is only a statement about the thing it names. Without this
  /// check one valid envelope could be pasted onto every other variable's
  /// response, and the scheme would degrade to "some value, somewhere, was
  /// signed once". The same reason covers a subject naming another user.
  kWrongResource,
  /// The value did not hash to what the signature said it would.
  ///
  /// The substitution this whole mechanism exists to catch: a genuine, current
  /// envelope delivered alongside a value somebody swapped.
  kContentMismatch,
  /// The response carried no signature, and this caller is signed in.
  ///
  /// ⚠️ AN ABSENT SIGNATURE IS A FAILURE, NEVER A PASS. Treating one as
  /// "nothing to check" makes the entire defence removable by deleting a
  /// field — which is precisely what an interception proxy is for.
  kMissingSignature,
};

struct Error {
  ErrorKind kind = ErrorKind::kNone;
  VerificationFailure verification = VerificationFailure::kNone;
  /// HTTP status, when `kind == kApi`.
  int status = 0;

  /// Guesses left before the thing being guessed at is destroyed.
  ///
  /// -1 means the server did not say, which is the case on nearly every route.
  /// 0 means this attempt was the last one and whatever was being guessed at is
  /// now spent — for a second factor, that means starting again from SignIn().
  ///
  /// ⚠️ THE ONE PIECE OF AN ERROR YOU MAY PUT ON SCREEN, because it is the
  /// one piece that is not a server-chosen sentence. `message` below is
  /// unsigned and must not be rendered; this is a number, so the worst a
  /// hostile responder can do is lie about a count the user can also see for
  /// themselves.
  int attempts_remaining = -1;

  /// ⚠️ SERVER-CONTROLLED AND UNVERIFIED WHEN `kind == kApi`. The error body
  /// carries no signature, so anything able to answer this SDK decides what
  /// this says. Do not put it in front of a user — switch on `kind` and
  /// `status` and write your own copy.
  std::string message;

  /// The API's own name for a refusal when `kind == kApi` — `device_limit_reached`,
  /// `device_required`, `application_unrecognised`, `invalid_credentials` and the
  /// rest — and why a redirect sign-in stopped when `kind == kRedirect`. Empty for
  /// every other kind.
  ///
  /// ⚠️ SAFE TO SWITCH ON, UNLIKE `message`. It comes from the same unsigned
  /// body, but it is a fixed vocabulary rather than a sentence: the worst a
  /// hostile responder can do is pick a different branch of code the application
  /// already wrote. It was parsed and then dropped until the native-settings audit
  /// of 25 September 2026, so a C++ application could not tell a device limit
  /// from an unrecognised build — both `kApi` with status 403 — while C# and
  /// Python could.
  std::string code;

  explicit operator bool() const { return kind != ErrorKind::kNone; }
};

/// A value or an error. Deliberately not exceptions.
///
/// Games and audio applications routinely build with exceptions disabled, and a
/// library that cannot be linked into `-fno-exceptions` is a library those
/// projects cannot use at all.
template <typename T>
struct Result {
  std::optional<T> value;
  Error error;

  bool ok() const { return !error && value.has_value(); }
  const T& operator*() const { return *value; }
  const T* operator->() const { return &*value; }
};

/// A result with nothing to return.
struct Status {
  Error error;
  bool ok() const { return !error; }
};

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// A verified statement about who is signed in and what they may do.
///
/// ⚠️ ONLY THE LIBRARY CAN PRODUCE ONE. There is no public constructor: the
/// only way to hold an `Identity` is to have been handed it after a signature
/// verified. That is what stops unverified JSON being used as if it were a
/// token.
///
/// ⚠️ AND THE PREDICATES BELOW ARE NOT A SECURITY BOUNDARY ON THIS MACHINE.
/// `has_feature` compiles to a branch, and a branch is one byte in a patched
/// binary. What is worth something is `access_token()`: send it to your own
/// server and verify it there.
class Identity {
 public:
  const std::string& access_token() const { return access_token_; }
  const std::string& user_id() const { return user_id_; }
  const std::string& session_id() const { return session_id_; }
  const std::string& environment_id() const { return environment_id_; }
  bool email_verified() const { return email_verified_; }
  /// Unix seconds. Sixty from minting, by design.
  std::int64_t expires_at() const { return expires_at_; }

  /// The server's clock, at the moment this identity was minted. Unix seconds.
  ///
  /// ⚠️ USE THIS, NOT time(), FOR ANYTHING THAT EXPIRES. A trial ending, a
  /// licence lapsing, a time-limited unlock: every one of those decided from
  /// the local clock is decided from a number the user can change in their
  /// system settings, and winding the clock back is the oldest licensing bypass
  /// there is. It costs an attacker nothing and needs no tooling.
  ///
  /// This value arrived inside a signature verified against the server's key,
  /// so it cannot be moved without breaking that signature.
  ///
  /// ⚠️ IT IS A TIMESTAMP, NOT A TICKING CLOCK — accurate to the moment
  /// the token was minted, at most sixty seconds ago. For elapsed time within a
  /// session, measure from this with a monotonic timer.
  std::int64_t server_time() const { return server_time_; }

  /// The plan the user is on. ⚠️ One of several when the application sells
  /// one-time purchases — the product that lasts longest. Ask `has_plan`,
  /// which reads every plan held.
  const std::optional<std::string>& plan_key() const { return plan_key_; }
  const std::vector<std::string>& features() const { return features_; }

  /// Every plan the user holds — several products at once when the
  /// application sells one-time purchases, otherwise the one plan or none.
  const std::vector<std::string>& plan_keys() const { return plan_keys_; }

  /**
   * What the environment still demands of this account, from the signed
   * `req` claim. Empty when nothing is owed.
   *
   * ⚠️ THE ONLY CHANNEL A NATIVE APPLICATION HAS FOR THIS. None of the three
   * native SDKs calls GET /v1/client/me, so `requiresCompletion` is invisible
   * to all of them and this claim is the whole signal. Values are the API's
   * vocabulary: email, username, emailVerification, password, mfa.
   */
  const std::vector<std::string>& requirements() const { return requirements_; }

  /// Does the user's plan grant a feature?
  bool has_feature(const std::string& key) const;

  /// Does the user hold a named plan or product? Any plan held, not only
  /// `plan_key`: somebody who bought a month of one product and a lifetime of
  /// another holds both.
  bool has_plan(const std::string& key) const;

 private:
  friend class TokenVerifier;
  Identity() = default;

  std::string access_token_;
  std::string user_id_;
  std::string session_id_;
  std::string environment_id_;
  bool email_verified_ = false;
  std::int64_t expires_at_ = 0;
  std::int64_t server_time_ = 0;

  std::optional<std::string> plan_key_;
  std::vector<std::string> features_;
  std::vector<std::string> requirements_;
  std::vector<std::string> plan_keys_;
};

// ---------------------------------------------------------------------------
// Session storage
// ---------------------------------------------------------------------------

/// Where the long-lived session token is kept between runs.
///
/// ⚠️ WHAT YOU ARE STORING IS THE USER'S CREDENTIAL, not a cache. Anybody who
/// reads it can act as that user for up to thirty days, from any machine.
class SessionStore {
 public:
  virtual ~SessionStore() = default;
  virtual std::optional<std::string> Read() = 0;
  virtual void Write(const std::string& token) = 0;
  virtual void Clear() = 0;

  /// A second slot beside the session: the token that spares this installation
  /// the second factor for fourteen days after it answered one. The server
  /// hands it back after the answer; kept here, the next launch's sign-in is
  /// spared too.
  ///
  /// ⚠️ NOT PURE, SO A STORE WRITTEN BEFORE THEM STILL COMPILES AND WORKS. These
  /// defaults keep nothing, and the client then holds the token in memory for
  /// the life of the process: a restart answers the factor again, the safe
  /// direction. Both stores made below override them.
  ///
  /// ⚠️ IT IS A CREDENTIAL, THOUGH A LESSER ONE THAN THE SESSION. On its own it
  /// signs nobody in; beside a stolen password it skips the second factor. Keep
  /// it wherever the session is kept, never anywhere looser.
  virtual std::optional<std::string> ReadTrustedDevice() { return std::nullopt; }
  virtual void WriteTrustedDevice(const std::string& value) { (void)value; }
  virtual void ClearTrustedDevice() {}

  /// A third slot: a random identifier that stands in for the machine where the platform
  /// offers none to read, so device locking can still tell one installation from another.
  ///
  /// ⚠️ NOT PURE, AS ABOVE: these defaults keep nothing, and the client then makes a new
  /// identifier each run — every launch a new device, the direction that costs a seat rather
  /// than sharing one. Both stores made below keep it.
  virtual std::optional<std::string> ReadDeviceFallback() { return std::nullopt; }
  virtual void WriteDeviceFallback(const std::string& value) { (void)value; }
};

/// A file, encrypted with OS-held key material where the platform has any.
///
/// On Windows the token is wrapped with DPAPI at `CRYPTPROTECT_UI_FORBIDDEN`
/// scope, so the ciphertext is meaningless to another local account and to
/// anybody who copies the file off the machine.
///
/// ⚠️ ELSEWHERE THIS IS FILE PERMISSIONS ALONE, AND SAYS SO. The right answers
/// are the login keychain on macOS and the Secret Service on Linux, and both
/// need a dependency this library deliberately does not take. What you get is a
/// `0600` file — which stops another unprivileged user reading it and does not
/// stop anything running as that user. Implement `SessionStore` over the
/// platform keychain if that is not enough for your product.
std::unique_ptr<SessionStore> MakeFileSessionStore(const std::string& application_name);

/// A store at an explicit path.
std::unique_ptr<SessionStore> MakeFileSessionStoreAt(const std::string& path);

/// In memory only — for tests, kiosks and shared machines.
std::unique_ptr<SessionStore> MakeInMemorySessionStore();

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

struct Options {
  /// The environment's publishable key, beginning `pk_`.
  ///
  /// Public by design: it ships in web bundles and grants nothing on its own.
  /// A key beginning `sk_` is refused at construction — a secret key in a
  /// desktop binary is the whole environment handed to anybody who runs
  /// `strings` on the executable.
  std::string publishable_key;

  /// For example `https://api.grantry.dev`. HTTPS unless loopback, and no user
  /// name or password in it — `Create` refuses a URL carrying either.
  std::string api_base_url = "https://api.grantry.dev";

  /// Refuse to talk to anything not presenting Grantry's own public key.
  ///
  /// ⚠️ THIS IS THE CONTROL THAT STOPS AN INTERCEPTION PROXY. HTTPToolkit,
  /// Fiddler and Charles all work the same way: install a root certificate on
  /// the machine, and the application's own TLS becomes readable. The user owns
  /// the trust store, so an ordinary HTTPS client cannot refuse. Pinning does —
  /// the handshake is checked against a key we published rather than against
  /// whatever the machine trusts, and a proxy has no way to present it.
  ///
  /// ⚠️ THE PIN IS ON THE PUBLIC KEY, NOT THE CERTIFICATE. Pinning a leaf
  /// means every renewal bricks every shipped build — a self-inflicted outage
  /// on somebody else's ninety-day schedule. The SPKI survives renewal because
  /// the key does.
  ///
  /// Unset means "on for the real API, off for anything else", so production is
  /// protected without anybody having to think about it and a staging host
  /// still works. Set it explicitly to override either way.
  std::optional<bool> pin_certificate;

  /// Additional SPKI pins, base64 SHA-256, for a self-hosted deployment.
  ///
  /// Ignored unless pinning resolves to on. Supply at least two — the key in
  /// use and a backup held offline — or the first unplanned rotation takes the
  /// application down with it.
  std::vector<std::string> certificate_pins;

  /// Ask the API to encrypt variable payloads under a per-session key.
  ///
  /// A second wrapper inside TLS. It does not defeat a proxy watching the whole
  /// exchange — the key derives from the session token, which that proxy also
  /// sees — but it does defeat a capture of the response alone, and bodies
  /// sitting in a log, a crash dump or a HAR file.
  ///
  /// ⚠️ IT IS NOT A SUBSTITUTE FOR THE SIGNATURE, WHICH IS ALWAYS CHECKED.
  /// Encryption protects secrecy, which nobody can guarantee on a machine the
  /// attacker owns. The signature protects integrity, which we can.
  bool encrypt_variable_payloads = true;

  /// The environment this application belongs to, for example `env_...`.
  ///
  /// ⚠️ REQUIRED, AND FOR A SECURITY REASON RATHER THAN CONVENIENCE.
  ///
  /// This is the expected `aud` claim. Asking the SERVER for it would make the
  /// audience check worthless, because the party who decides which server you
  /// talk to would also be deciding what that server must claim to be.
  /// Concretely: anybody able to redirect this SDK could answer "your
  /// environment is env_theirs", relay to the real Grantry with their own key,
  /// and hand back a genuinely-signed token for their own environment.
  /// Signature, issuer, audience and nonce would all verify.
  ///
  /// It is public information — it rides in every token — so shipping it in the
  /// binary costs nothing.
  std::string environment_id;

  /// The issuer stamped on every access token.
  ///
  /// ⚠️ A CONSTANT, NOT DERIVED FROM `api_base_url` AND NOT FETCHED. Deriving
  /// it from the server being talked to makes the check circular: whoever
  /// chooses the server would also be choosing what it must claim to be.
  std::string issuer = "https://grantry.dev";

  /// Names the default session store's folder. Not sent anywhere: the
  /// User-Agent is `grantry-cpp/<version>`, and `X-Grantry-Sdk` says the same.
  std::string application_name;

  /// Where the session lives. Defaults to `MakeFileSessionStore`.
  std::shared_ptr<SessionStore> session_store;

  /// Permit plain HTTP when the API host is loopback — `localhost`, `[::1]` or
  /// an address in 127.0.0.0/8, written as one. Development only.
  ///
  /// There is no option that disables TLS for a real host, because there is no
  /// legitimate reason to want one and every reason somebody would ask.
  bool allow_insecure_loopback = false;

  /// RFC 7638 thumbprints of the signing keys, if you want to pin.
  ///
  /// Empty means "trust whatever the JWKS endpoint serves over TLS". Pinning
  /// narrows that, so an attacker who can present a valid certificate for the
  /// API host still cannot swap the signing key.
  ///
  /// ⚠️ IT DOES NOT DEFEND A PATCHED BINARY, which can rewrite this list. Pin
  /// more than one and rotate by adding before removing; a single pinned key is
  /// an outage the day it rotates.
  std::vector<std::string> pinned_key_thumbprints;

  /// Tolerance for a client clock that disagrees with the server's, in seconds.
  ///
  /// Access tokens live sixty seconds, so this cannot be generous without
  /// swallowing the lifetime whole.
  int clock_skew_seconds = 30;

  /// How long a fetched JWKS is reused, in seconds.
  int jwks_cache_seconds = 6 * 60 * 60;

  /// Network timeout, in seconds.
  int timeout_seconds = 30;

  /// Reach the API once, in the background, as soon as the client exists.
  ///
  /// A web application announces itself the moment it loads, because its
  /// provider fetches the environment on mount. A native one had no such
  /// moment: nothing left the process until somebody typed a password, which
  /// could be days after the SDK was wired up. Their dashboard sat on
  /// "watching for connection" the whole time, and the only way to move it was
  /// to sign in — which is why the setup guide used to teach sign-in before
  /// it had taught anything else.
  ///
  /// So construction is the connection: one GET of the public environment
  /// route, on a thread.
  ///
  /// ⚠️ IT NEVER BLOCKS Create() AND NEVER REPORTS ANYTHING. The answer is
  /// dropped, error and all: an application that starts on a train must still
  /// start, and nothing in the SDK reads what it fetches. The destructor joins
  /// the thread, so a client is never torn down with a request still running
  /// against its own memory — which is also why the probe uses a short
  /// timeout of its own rather than `timeout_seconds`, so shutting down while
  /// a server hangs cannot hold the process for half a minute.
  ///
  /// Set it false for a build that must make no call it was not asked to make.
  bool connect_on_start = true;
};

/// One file the caller may download.
struct File {
  /// Pass this to Download.
  std::string id;

  /// What the merchant called it.
  ///
  /// ⚠️ NEVER BUILD A PATH FROM THIS WITHOUT SANITISING. It is whatever
  /// the merchant typed, so it can contain separators and traversal; joining it
  /// to a directory is how a download becomes an arbitrary file write.
  std::string name;

  std::int64_t size_bytes = 0;

  /// SHA-256 of the stored bytes, lowercase hex.
  ///
  /// ⚠️ CHECK IT AFTER DOWNLOADING, especially before executing what you
  /// received. TLS protects the transfer; it says nothing about whether this is
  /// the file the merchant uploaded.
  std::string checksum;

  /// What the merchant's browser claimed at upload. Advisory only.
  std::string content_type;
};

/// One machine this account is activated on.
///
/// ⚠️ THERE IS NO ANCHOR HERE, only a label. The server stores an HMAC of
/// what the client reported, and returning any of it would hand a patched build
/// the string to replay from another machine.
struct Device {
  std::string id;
  /// The short form a person reads out on a support call.
  std::string label;
  /// "windows", "macos", "linux", or "unknown".
  std::string platform;
  std::string last_seen_at;
  /// Whether this is the machine making the call: the one a "release" button must not offer
  /// without saying so, since releasing it signs this installation out of its seat.
  bool current = false;
};

/// One address on the account that is not the primary one.
///
/// ⚠️ THE PRIMARY ADDRESS IS NOT IN THIS LIST. It lives on `Identity::email`
/// because every unique index and every sign-in lookup reads that column; this
/// covers the others. A screen showing "email addresses" has to draw both.
///
/// Only meaningful where the merchant allows additional addresses. With the
/// setting off, every route behind these is refused.
struct EmailAddress {
  /// Pass this to `RemoveEmailAddress`, not the address itself.
  std::string id;
  std::string email;
  /// Whether the code mailed to it has been redeemed.
  bool verified = false;
  std::string created_at;
};

/// One account signed in on this client.
///
/// Only meaningful when the merchant enabled multi-session. With it off,
/// `GetAccounts` reports the one signed-in account and `SwitchAccount` is
/// refused by the server.
///
/// ⚠️ `session_id` IS A HANDLE, NOT A CREDENTIAL. A session's token exists
/// only as a hash on the server; switching mints the target a new one and
/// returns it in the session header. So a background account's token is never
/// in this process, and nothing here can be replayed.
struct Account {
  std::string session_id;
  /// Whether this is the account the client is acting as.
  bool is_current = false;
  std::string user_id;
  std::string email;
  /**
   * The handle this person chose, when the environment uses them.
   *
   * ⚠️ NOT ON THE IDENTITY, AND THAT IS DELIBERATE. The signed token carries
   * what authority depends on — user id, plan, features — and a username is
   * none of those, so it would have to be re-minted on every change and signed
   * for nothing. It is display text and it arrives here, with the rest of the
   * display text.
   *
   * Empty when the environment does not use usernames, or this account has not
   * set one.
   */
  std::string username;
  /*
   * ⚠️ `name` WAS HERE AND IS GONE. Grantry does not hold a name for an end
   * user any more — the column, the OAuth mapping that filled it and the
   * account screen that edited it all went together. Read `email` or
   * `username` for something to show.
   */
  std::string last_active_at;
};

/// The accounts on this client, and whether switching is allowed.
struct AccountList {
  /// Whether the application allows more than one signed-in account.
  ///
  /// ⚠️ DECIDE WHETHER TO SHOW A SWITCHER FROM THIS, not from
  /// `accounts.size()`. With the setting off there is exactly one account and
  /// a switch is refused, so a control driven off the count would appear the
  /// moment somebody happened to have two — and then fail when pressed.
  bool multi_session = false;
  std::vector<Account> accounts;
};

/// A published legal document.
///
/// Carries both a link and the text: a native application often cannot open a
/// browser, or should not — a kiosk, a game in exclusive fullscreen — so the
/// text is there to render in place.
///
/// ⚠️ THE TEXT IS THE MERCHANT'S AND IS NOT VERIFIED. Render it as plain
/// text or as the markup you expect, never as HTML handed to a browser control.
struct LegalDocument {
  std::string key;
  std::string url;
  std::string text;
  /// Worth recording alongside an acceptance: "they agreed" is not a defensible
  /// record without "to which version".
  std::string version;
};

/// Which of the caller's own attributes to block.
///
/// ⚠️ THE CALLER NAMES A KIND, NEVER A VALUE. The server reads the address
/// off the connection and the device off the header it already holds, so there
/// is no way to aim Block at anybody but the machine it runs on.
enum class BlockTarget {
  /// The address this request arrived from.
  kIpAddress = 0,
  /// The device anchor this build reports. Native only.
  kDevice = 1,
};

/// One variable, as the server chose to deliver it.
///
/// ⚠️ VERIFIED BEFORE IT REACHES YOU, and that is a change from earlier
/// releases. Every read made with a session is signed by the API and checked
/// here against Grantry's published key, so a value that arrives unsigned, or
/// signed for another user, key or request, is refused rather than returned.
///
/// ⚠️ VERIFIED IS NOT SECRET. Somebody running your binary can still read
/// this out of its memory once the check has passed, and no SDK can prevent
/// that. What they cannot do is substitute one.
struct Variable {
  std::string key;
  std::string value;
  /// Belongs to the signed-in user rather than to the application.
  bool per_user = false;
  /// Whether SetVariable will be accepted for this key.
  ///
  /// Reported so an application can skip a round trip it knows will be refused.
  /// It is not the control — the server checks again, because this flag came
  /// over the same unverified channel as the value.
  bool writable = false;
};

/// Which door is open to somebody who has no account yet.
enum class AccessMode {
  /// Anybody may create an account.
  kOpen,
  /// Accounts are created from an invitation only.
  kInviteOnly,
  /// No sign-ups; addresses are collected for later.
  kWaitlist,
};

/// What the password field will accept.
///
/// ⚠️ STATE THE RULES, DO NOT MAKE PEOPLE GUESS AT THEM. A form that only
/// refuses is a form somebody works through one rule at a time, and WCAG 3.3.2
/// asks for the requirement up front. Publishing it costs nothing an attacker
/// does not already have: one sign-up attempt reveals the same rules.
///
/// ⚠️ AND THIS IS THE LIST TO RENDER WHEN A SIGN-IN COMES BACK WITH
/// `SignInResult::password_reset_token`. The server's own `reasons` are NOT
/// exposed there, deliberately — see that field.
///
/// ⚠️ WHETHER BREACHED PASSWORDS ARE REJECTED IS NOT HERE, AND WILL NOT BE.
/// The server does not publish it: it is a statement about Grantry's
/// infrastructure rather than about the customer's choice of password, and it
/// is not a rule a form can usefully state in advance. It is the one refusal
/// reason that arrives on the wire instead — `SignInResult::password_breached`.
struct PasswordPolicy {
  /// Characters, counted as code points rather than bytes.
  int min_length = 0;
  bool require_uppercase = false;
  bool require_lowercase = false;
  bool require_number = false;
  bool require_symbol = false;
  /// zxcvbn score, 0–4. Zero means the merchant sets no strength floor.
  int min_strength = 0;
};

/// What a sign-in screen needs to know before anybody has signed in.
///
/// This exists so your first screen can be worded correctly. Offering "create
/// an account" on an application running a waitlist sends every new user into a
/// refusal with no hint that the other door exists.
///
/// ⚠️ IT IS PRESENTATION, NEVER PERMISSION. Nothing here grants anything and
/// nothing here is checked by this SDK. The server decides every one of these
/// questions again on the call itself, so a patched build that forces kOpen
/// gets exactly the same refusal from SignUp as an honest one.
///
/// ⚠️ AND IT GOES STALE. A merchant who switches modes does not re-issue
/// your binary, so read it at launch rather than baking it in, and still handle
/// the refusal on both paths.
///
/// Everything here is already visible on the merchant's own sign-in page, which
/// is the test for whether an unauthenticated caller may read it. The settings
/// that are NOT here — whether an account may be deleted, whether an email
/// may be changed — are absent on purpose: see DeleteAccount.
struct Environment {
  /// The application's name, for window titles and copy.
  std::string application_name;

  /// Which door is open.
  ///
  /// ⚠️ A MODE THIS BUILD DOES NOT RECOGNISE READS AS kOpen, deliberately.
  /// An old binary meeting a newer server should fall back to the screen
  /// offering the most doors and let the server close the ones that are shut.
  AccessMode access_mode = AccessMode::kOpen;

  /// Whether the environment is closed for maintenance right now.
  ///
  /// ⚠️ IT OUTRANKS EVERYTHING ELSE HERE: while it is true no door is open,
  /// whatever `access_mode` says, and every other call in this SDK answers
  /// `kMaintenance`. Read it before you draw a screen and show a wait screen
  /// instead. Until it was published the only way to find out was to fill in
  /// the form and be turned away, which is the worst moment to be told.
  ///
  /// ⚠️ AND IT IS THE ONE FIELD HERE THAT IS NOT MERELY PRESENTATION — the
  /// server enforces it on every other route. That does not make reading it a
  /// substitute for handling the refusal: it can be switched on a second after
  /// you read it, and open sessions end with it.
  ///
  /// ⚠️ A BOOL RATHER THAN AN ENUM, DELIBERATELY, EVEN THOUGH THE WIRE CARRIES
  /// A STRING. There is exactly one level of closed — the softer "stop new
  /// sign-ins" rung was removed, because a merchant reaching for it during an
  /// incident believed they had closed while everybody already inside kept
  /// working. A two-value enum would model a distinction that does not exist,
  /// and it would invite `mode != kOff`; there is no "not off" to write here.
  ///
  /// ⚠️ ABSENT AND UNRECOGNISED BOTH READ AS OPEN — same direction as
  /// `access_mode` above, and here the cost of the other direction is worse. A
  /// server on the previous release does not send this field at all, so a
  /// build that read silence as closed would black out every application
  /// at it: an outage caused by upgrading the CLIENT.
  bool closed_for_maintenance = false;

  /// Which identifiers sign-in accepts: "email", "username".
  ///
  /// Label your identifier box from this. "Email" on an application that also
  /// takes usernames is a support ticket waiting to happen.
  std::vector<std::string> identifiers;

  /// Whether an account here is created WITHOUT a password.
  ///
  /// True means the second step of a sign-in is an emailed code —
  /// SendSignInCode, then VerifySignInCode — rather than a password box.
  ///
  /// ⚠️ INVERTED FROM THE WIRE, WHICH SENDS `passwordSignUp`, AND THE NAME IS
  /// THE POINT. The dangerous reading is "we were not told, so there is no
  /// password": it mails a sign-in code to every user of every environment
  /// that still has one, starting with any server too old to publish the
  /// field. Named this way round, absent is `false` is "there are passwords" —
  /// the same safe direction as `closed_for_maintenance` above, and with no
  /// `!password_sign_up` left for anybody to write.
  ///
  /// ⚠️ AND IT DECIDES WHICH STEP TO OFFER, NOT WHAT AN ACCOUNT HAS. It is a
  /// fact about the SIGN-UP FORM: somebody may have added a password to their
  /// own account afterwards, and SendSignInCode works for accounts that have
  /// one. So it chooses what you ask for FIRST, and nothing more.
  ///
  /// ⚠️ IT ALSO DECIDES WHAT SignUp MAY SEND. With this true the server
  /// refuses a sign-up carrying a password rather than ignoring it — quietly
  /// dropping one would leave somebody believing they had set a credential,
  /// and finding out at the next sign-in. Omit the field; do not send it
  /// empty.
  bool passwordless_sign_up = false;

  /// Whether the sign-up form must collect a username.
  bool username_required = false;

  /*
   * ⚠️ THERE IS NO collect_name / require_name HERE ANY MORE, AND A NAME BOX ON
   * YOUR SIGN-UP FORM WILL NOW BE IGNORED. Sign-up stopped asking for a name;
   * the two settings behind it were dropped from the server in migration 0127,
   * so the field they gated is gone from the response rather than always false.
   * ⚠️ AND `User::name` IS GONE TOO NOW. It outlived the settings by a while;
   * the column behind it was dropped, along with the OAuth mapping that filled
   * it. Nothing in Grantry holds a name for an end user.
   */

  /// Whether a new account must confirm its address before it can sign in.
  ///
  /// Worth reading so the screen after sign-up says "check your email" rather
  /// than dropping the user at a form that will refuse them.
  bool require_email_verification = false;

  // ⚠️ NO portal_url ANY MORE (slice 4b of docs/hosted-sign-in.md). It was the
  // hosted portal, where a native application sent somebody to pay. That page
  // went with the portal: billing is the web application's own now, in
  // <UserProfile /> and its checkout, and a native application still takes no
  // payment itself.

  /// What the password field will accept. See PasswordPolicy.
  ///
  /// ⚠️ ALL ZEROES AND ALL FALSE IS "WE WERE NOT TOLD", which a server on an
  /// older release genuinely does not tell us. Draw no requirement list rather
  /// than one claiming a minimum length of zero.
  PasswordPolicy password_policy;
};

/// How a sign-up ended.
///
/// ⚠️ NOT EVERY SUCCESSFUL SIGN-UP PRODUCES A SESSION, and an application
/// that assumes otherwise breaks the day its merchant turns on email
/// verification. Three different screens follow from these three values.
enum class SignUpOutcome {
  /// The account exists and this process is signed in.
  kSignedIn,

  /// The account cannot be used until the emailed CODE is confirmed.
  ///
  /// ⚠️ FINISH IT WITH ConfirmEmail() — THIS IS NOT A DEAD END. It used
  /// to be one: nothing in this SDK could act on the outcome, so a native
  /// application could start a sign-up it had no way to complete. The
  /// account does not exist until the code is confirmed.
  ///
  /// ⚠️ THIS IS ALSO THE ANSWER WHEN THE ADDRESS IS ALREADY TAKEN, and the
  /// two are indistinguishable on purpose. Whoever owns the address gets an
  /// email either way — a confirmation code, or a note that an account
  /// already exists — so the honest screen is the same for both: "check your
  /// email". Do not try to tell them apart.
  kPendingVerification,

  /// The application is not taking sign-ups; the address went on the waitlist.
  ///
  /// The server does this rather than refusing, so a sign-up form that meets a
  /// closed door still does something useful with what the person typed.
  ///
  /// ⚠️ THIS IS THE ONLY WAY TO REACH THE WAITLIST FROM HERE, AND THE ABSENCE
  /// OF A SEPARATE JOIN METHOD IS DELIBERATE. Sign-up already collects the
  /// address when the door is closed, so a second call doing the same thing was
  /// a second door into one room — and a native application, which the user has
  /// already downloaded, is not where a waitlist belongs.
  kWaitlisted,
};

/// What a relay's endpoint answered.
struct RelayResult {
  /// The HTTP status the endpoint returned.
  ///
  /// ⚠️ A 3xx MEANS IT REDIRECTED AND WE DID NOT FOLLOW. A redirect is a
  /// second URL nobody validated, and following one is the most common way a
  /// server-side request check is defeated.
  int status = 0;

  /// The reply, when the merchant asked for it. Usually empty.
  ///
  /// ⚠️ NOT VERIFIED AND NOT NECESSARILY THE MERCHANT'S. It is whatever the
  /// endpoint sent. Treat it as untrusted input.
  std::string body;

  /// The reply was longer than the ceiling and was cut short.
  bool truncated = false;
};

/// One price a plan can be bought at.
struct Price {
  std::string id;
  /// "recurring" or "one_time".
  std::string mode;
  /// "month", "year", and so on.
  std::string interval_unit;
  int interval_count = 1;

  /// Minor units — cents, pence.
  ///
  /// ⚠️ NEVER A DECIMAL, AND NEVER PARSED BACK FROM ONE. Format it for
  /// display and keep the integer.
  std::int64_t amount = 0;

  std::string currency;
  std::string label;
};

/// A plan a user could subscribe to.
///
/// ⚠️ ONLY THE PUBLICLY AVAILABLE ONES, and only their live prices. A plan
/// somebody is grandfathered onto is not something a pricing screen offers.
struct Plan {
  std::string id;
  /// The stable key, which is what an entitlement names.
  std::string key;
  std::string name;
  std::string description;
  std::vector<Price> prices;
};

/// What the signed-in user is currently paying for.
///
/// ⚠️ DISPLAY DATA, NEVER THE GATE. What a user may do is decided by the
/// signed access token — `Identity::plan_key` and `features` — which is minted
/// fresh every minute and cannot be forged. This is the unsigned billing view,
/// good for a countdown or a receipt and for nothing else. An application that
/// unlocked a feature because THIS said so would be trusting an answer instead
/// of a proof.
struct Subscription {
  /// False when the user is on the environment's default free plan.
  bool active = false;

  std::string plan_key;
  std::string plan_name;
  /// "trialing", "active" or "past_due".
  std::string status;

  /// "day", "week", "month", "year" or "lifetime".
  std::string interval_unit;
  int interval_count = 1;

  /// ISO 8601, and EMPTY FOR A LIFETIME.
  ///
  /// ⚠️ EMPTY MEANS "NEVER ENDS", NOT "UNKNOWN". A lifetime subscription
  /// stores no end date at all — see migration 0093 — so a countdown must
  /// check this before it subtracts, or it renders the epoch.
  ///
  /// Left as text rather than parsed: dates arrive from the server in one
  /// format, and every language this SDK is consumed from has a better parser
  /// than one written here would be.
  std::string current_period_end;

  /// Whether it is set to stop at the end of the current period.
  bool cancel_at_period_end = false;
};

/// One second factor on the account.
struct Factor {
  /// Pass this to RemoveFactor.
  std::string id;

  /// Always "totp" today, and it is still worth reading.
  ///
  /// SMS went in migration 0131 and took the only other member with it, but the
  /// server keeps this a set rather than a boolean because a passkey or a
  /// hardware key is a plausible next one. A screen that switches on it widens
  /// without a rename; one that assumes an authenticator app draws the wrong
  /// icon the day a second kind arrives.
  std::string type;

  /// What the user called it when they enrolled.
  std::string name;

  /// Whether the user has proved they hold it.
  ///
  /// ⚠️ FALSE IS AN ENROLMENT SOMEBODY ABANDONED, AND IT GATES NOTHING. The
  /// list carries them — StartTotp writes the row and only ConfirmTotp fills in
  /// the confirmation — so a screen drawn straight from this offers to remove
  /// an authenticator that was never switched on, and tells a user they are
  /// protected when they are not. Filter on it before you count factors.
  bool confirmed = false;

  /// ISO 8601, empty when it has never been used to sign in.
  std::string last_used_at;
  std::string created_at;
};

/// The account's second factors, and what this application will let it do.
struct FactorList {
  std::vector<Factor> factors;

  /// How many unspent recovery codes are left.
  int backup_codes_remaining = 0;

  /// Whether this application is entitled to enrol a new factor at all.
  ///
  /// ⚠️ PRESENTATION, NEVER PERMISSION — the same rule as everything on
  /// Environment. The server enforces it on enrolment regardless; this exists
  /// so a screen does not offer an Add button that comes back 403.
  ///
  /// ⚠️ AND IT SAYS NOTHING ABOUT THE FACTORS ALREADY THERE. Those keep
  /// working, keep gating sign-in and stay removable whatever this says: an
  /// account that was secured properly must not be locked out because a
  /// merchant's plan lapsed.
  bool can_enrol = false;

  /// Whether the merchant issues recovery codes.
  ///
  /// ⚠️ REFUSED AT THE MINT, NEVER AT THE SPEND. With this off,
  /// RegenerateBackupCodes is refused and SubmitMfa still accepts a code
  /// somebody printed last year — a merchant switching the feature off must not
  /// strand a user who has just lost their phone.
  bool backup_codes_enabled = false;
};

/// What proves it is the account holder before a sensitive change: the password,
/// a current code from the authenticator app, a code mailed to the account, or a
/// recovery code. Each factory says which calls take it; the server refuses the rest.
///
/// ⚠️ A TYPE WITH TWO FACTORIES, NOT TWO OPTIONAL STRINGS, SO THE CALL CANNOT
/// BE MADE WITHOUT ONE. Replacing the set took no proof until 0279, and every
/// existing caller of RegenerateBackupCodes has to be asked for one now — a
/// signature change fails at build time where an optional argument would have
/// failed at run time. "Neither" and "both" cannot be written either.
///
/// ⚠️ A BACKUP CODE ONLY WHERE A FACTOR IS REMOVED OR REPLACED. There the
/// device is gone and the codes are all that is left; showing or replacing the
/// codes themselves refuses one, since there the thing being shown IS the set,
/// and one leaked code would otherwise buy the other nine. The server decides
/// per call; each factory says where it is taken.
///
/// ⚠️ ASK AT THE MOMENT IT IS NEEDED AND DO NOT KEEP IT. The server checks it
/// in the same request and grants no window afterwards, and an authenticator
/// code works once.
class Proof {
 public:
  /// The signed-in account's password.
  static Proof Password(std::string password) {
    return Proof("password", std::move(password));
  }

  /// Six digits from the authenticator app — the proof an account with no
  /// password (one that signs in with Google, say) has to give.
  static Proof AuthenticatorCode(std::string code) {
    return Proof("code", std::move(code));
  }

  /// A code mailed to the account's own address by `SendReauthenticationCode`: the proof an
  /// account with neither a password nor an authenticator can give. Taken by `ChangeEmail` and
  /// `DeleteAccount`; the second-factor calls refuse it, since an inbox is not the factor.
  static Proof EmailCode(std::string code) {
    return Proof("emailCode", std::move(code));
  }

  /// One of the account's recovery codes: the proof for removing or replacing an
  /// authenticator whose phone is gone. Only those take it.
  static Proof BackupCode(std::string code) {
    return Proof("backupCode", std::move(code));
  }

  /// The body field the server reads it from.
  const std::string& field() const { return field_; }
  const std::string& value() const { return value_; }

 private:
  Proof(std::string field, std::string value)
      : field_(std::move(field)), value_(std::move(value)) {}

  std::string field_;
  std::string value_;
};

/// An authenticator enrolment begun: what a QR code is drawn from.
///
/// ⚠️ THE SECRET AND THE ADDRESS LEAVE THE SERVER EXACTLY ONCE, HERE. Render them, let them
/// be scanned, let them go — see StartTotp.
struct TotpSetup {
  /// The factor's id, for ConfirmTotp's error messages and RemoveFactor.
  std::string factor_id;
  /// The base32 secret, for a person typing it into an app by hand.
  std::string secret;
  /// The `otpauth://totp/...` address a QR code encodes, naming the application and the account
  /// as the authenticator app will list them. Draw the QR code from this, not from the secret.
  std::string uri;
};

/// One recovery code, as ViewBackupCodes shows it.
struct BackupCode {
  std::string code;

  /// ISO 8601 of when it was spent; empty while it still works.
  ///
  /// ⚠️ A SPENT CODE NEVER WORKS AGAIN. It is listed so somebody can match the
  /// list they printed against it — and notice one they did not use — not so
  /// it can be copied or saved.
  std::string used_at;

  bool spent() const { return !used_at.empty(); }
};

/// What ViewBackupCodes answers.
struct BackupCodeView {
  /// Every code in the set, spent ones included, in the order enrolment showed
  /// them. Empty when regenerate_required.
  std::vector<BackupCode> codes;

  /// Nothing can be shown: no set, or a set made before codes could be shown
  /// again (0279).
  ///
  /// ⚠️ NOT "YOU HAVE NO CODES". Such a set was stored as hashes alone; its
  /// codes still work at SubmitMfa, and the only way to SEE codes is a new set
  /// from RegenerateBackupCodes, which destroys them. Say so before offering it.
  bool regenerate_required = false;
};

struct SignInResult {
  /// The environment requires a second factor this user has not enrolled.
  ///
  /// ⚠️ TOLD, NOT ENFORCED AS A REFUSAL. The session is real and the user is
  /// signed in — the server reports this so the application can send them to
  /// enrolment rather than locking out people who signed up before the policy
  /// existed.
  bool mfa_required = false;

  /// This account does not hold a plan the application requires.
  ///
  /// ⚠️ NEVER SET BY SubmitMfa, AND THAT IS A DECISION RATHER THAN AN
  /// OVERSIGHT. It was taken when `POST /v1/client/mfa/verify` answered
  /// `{ backupCodesRemaining }` alone and this SDK read the report off it
  /// anyway: a field always false on the second-factor path while working on
  /// every other one, so an account with a second factor and no accepted plan
  /// reached the main window and was then refused by everything in it.
  ///
  /// The server has sent `requiresPlan` and `planMessage` on that route since
  /// September 2026, and the C# and Python SDKs read them there. This one still
  /// does not, because the plan restriction is REAL on that path — the server
  /// applies it to the session it creates there like any other — and the
  /// authority for it is `ErrorKind::kPlanRequired`, which comes back from the
  /// first call the restriction actually refuses. Handle that kind and the
  /// activate screen appears on every path, on an older server, and when a plan
  /// lapses mid-session; branch only on this flag and it appears on some.
  ///
  /// ⚠️ TOLD, NOT ENFORCED AS A REFUSAL — exactly like mfa_required. The
  /// session is real and the user IS signed in; they simply have no
  /// subscription the merchant accepts. Show an activate-a-code screen instead
  /// of your main window.
  ///
  /// ⚠️ REFUSING THE SESSION WOULD HAVE BEEN THE OBVIOUS DESIGN AND IT IS THE
  /// WRONG ONE. Activate() needs a session, so a refusal would leave somebody
  /// who just bought a licence unable to redeem it.
  ///
  /// ⚠️ AND THIS IS NOT AN ANTI-PIRACY CONTROL. A patched build can ignore it
  /// and draw its main window anyway. What it cannot do is obtain anything
  /// behind the gate: no subscription-gated variable, no subscription-gated
  /// file, and no access token naming a plan this account does not hold.
  bool requires_plan = false;

  /// The merchant's own sentence about it, when they wrote one.
  ///
  /// ⚠️ NOT VERIFIED, like every other server-supplied string. Render it as
  /// plain text: never markup, never a link the user can follow.
  std::string plan_message;

  /// A second factor is needed before there is a session at all.
  ///
  /// ⚠️ NOT THE SAME THING AS mfa_required, AND CONFUSING THE TWO IS THE BUG
  /// THIS FIELD EXISTS TO PREVENT. `mfa_required` means the environment WANTS a
  /// factor this account has not enrolled: the session is real. This means the
  /// account HAS a confirmed factor and the password alone proved nothing —
  /// there is no session and nothing to read until SubmitMfa() is called.
  ///
  /// Non-empty here means you are NOT signed in. A second screen, not an error.
  ///
  /// ⚠️ `sms_available` STOOD HERE AND WENT WITH THE FACTOR — see migration
  /// 0131. The challenge is now a token and a lifetime and nothing else, so
  /// there is no method to choose between: the code comes from the
  /// authenticator app, or one of the backup codes comes off a piece of paper.
  std::string mfa_challenge;

  /// The password was RIGHT, and is no longer acceptable. Redeem this token.
  ///
  /// ⚠️ NON-EMPTY MEANS YOU ARE NOT SIGNED IN — the same contract as
  /// `mfa_challenge`, and modelled on it for that reason. There is no session,
  /// no user, and nothing to read until the token is spent.
  ///
  /// ⚠️ AND IT ARRIVES ON A 2xx, WHICH IS WHY EVERY SDK GOT THIS WRONG. The
  /// server answers HTTP 202 — the credential was correct, so this is not an
  /// authentication failure and a 401 would send the user back to retype a
  /// password that is already right. A transport that treats any 2xx as
  /// "signed in" then falls through to reading an identity, finds no session,
  /// and reports NOT SIGNED IN: an unexplained sign-out at the exact moment
  /// the correct screen is "choose a new password".
  ///
  /// It means the plaintext was re-checked against the CURRENT policy at
  /// sign-in — the only moment it exists — and failed. Either the merchant
  /// tightened the rules after this password was set, or it has since turned up
  /// in a breach corpus.
  ///
  /// ⚠️ TREAT IT AS A PASSWORD. It is a real, single-use, short-lived
  /// password-reset token — the same one the emailed flow issues, minted here
  /// so that no second endpoint was needed. Spend it with
  /// `ResetPassword(token, new_password)`; never log it, never persist it, and
  /// hold it no longer than the screen that collects the new password.
  ///
  /// ⚠️ IT IS HANDED OVER DIRECTLY RATHER THAN EMAILED BECAUSE WHOEVER HOLDS
  /// IT HAS ALREADY PROVED THEY KNOW THE CURRENT PASSWORD — and, when the
  /// account has one, the second factor as well. A trip through the inbox
  /// would prove nothing further.
  std::string password_reset_token;

  /// Only meaningful beside `password_reset_token`: the password is breached.
  ///
  /// ⚠️ THE ONLY REFUSAL REASON WORTH CARRYING, AND THE SERVER'S OWN LIST IS
  /// DELIBERATELY NOT EXPOSED. Every other reason — too short, needs a digit,
  /// needs a symbol, too weak — is already `Environment::password_policy`, so
  /// a screen that renders the policy states them all with no wire format to
  /// track. This one is not derivable from anything published: whether an
  /// environment rejects breached passwords is not in the policy and never
  /// will be.
  ///
  /// ⚠️ AND THE LIST IS ABSENT AFTER A SECOND FACTOR ANYWAY, so a screen
  /// built on it would be right on one path and blank on the other. The
  /// verdict is decided at sign-in and only a boolean rides on the MFA
  /// challenge — which is exactly why the requirement list has to come from
  /// the policy rather than from the refusal.
  ///
  /// ⚠️ SO FALSE MEANS "NOT SAID", NOT "NOT BREACHED" — and that is the safe
  /// direction. Telling somebody their password appeared in a breach when the
  /// server never said so is alarming and wrong; staying silent leaves them
  /// reading the ordinary requirement list, which applies either way.
  bool password_breached = false;

  /// Recovery codes left, or -1 when the response did not say.
  ///
  /// ⚠️ -1 IS NOT ZERO, AND CONFLATING THEM ANNOUNCES A LOCKOUT THAT HAS NOT
  /// HAPPENED. Only a completed `SubmitMfa` carries this — `/v1/client/mfa/verify`
  /// answers `{ backupCodesRemaining }` — so every other path leaves it at -1.
  ///
  /// Worth showing when it is low. Running out of recovery codes is otherwise
  /// invisible until the day somebody loses their phone and discovers there is
  /// no way back into the account; `RegenerateBackupCodes` is the fix, and it
  /// has to be offered before that day rather than after it.
  ///
  /// ⚠️ THE COUNT IS REPORTED AFTER AN ORDINARY SIX-DIGIT CODE TOO, not only
  /// after a backup code was spent. That is what makes it usable as a prompt:
  /// somebody who enrolled a year ago and has quietly spent eight of ten codes
  /// finds out on an ordinary sign-in.
  int backup_codes_remaining = -1;

  /// How the sign-up ended. Always kSignedIn for a sign-in.
  ///
  /// Check it before sending the user to your main screen: anything other than
  /// kSignedIn means the account may well exist and simply cannot be used yet.
  SignUpOutcome outcome = SignUpOutcome::kSignedIn;
};

/// What the sign-in page shows somebody the browser is already signed in as.
///
/// ⚠️ "CONTINUE AS" BY DEFAULT. The browser keeps its own sign-in on the sign-in
/// page, and `SignOut` ends this application's session, never the browser's. So
/// without a screen, signing out and signing in again went straight back to the
/// same account, with no way to choose another; and on a shared computer, to
/// whoever used the browser last.
enum class RedirectPrompt {
  /// "Continue as": who is signed in, Continue, and "Not you?" to sign out and
  /// sign in as somebody else. Somebody signed out sees the sign-in form, as ever.
  kSelectAccount,
  /// The sign-in form, even over an account the browser holds.
  kLogin,
  /// No screen: a browser signed in answers at once, as that account.
  kImmediate,
};

/// How `SignInWithRedirect` waits, and how it opens the browser.
struct RedirectOptions {
  /// What the sign-in page shows somebody already signed in there. See
  /// `RedirectPrompt`.
  RedirectPrompt prompt = RedirectPrompt::kSelectAccount;

  /// How long to wait for the person to come back from the browser, in seconds.
  /// Ten minutes by default, the time the web SDK gives a started sign-in.
  int timeout_seconds = 600;

  /// Opens the sign-in page. Empty means the system's own browser: ShellExecute on
  /// Windows, `open` on macOS, `xdg-open` elsewhere. Return false when it could not
  /// be opened; the call then fails with `browser_unavailable`.
  ///
  /// ⚠️ THE SYSTEM BROWSER, NEVER AN EMBEDDED WEB VIEW. A view inside your process
  /// can read what is typed into it, which is exactly what the hosted screens
  /// exist to keep away from an application, and social providers refuse to run
  /// inside one. It must not throw: this library is built to link into
  /// `-fno-exceptions` code and does not catch.
  std::function<bool(const std::string& url)> open_browser;

  /// Asked five times a second while waiting; answer true to stop, and the call
  /// fails with `cancelled` and closes the port. Wire it to a Cancel button.
  std::function<bool()> cancelled;
};

/// The library's entry point. One per process.
class Client {
 public:
  /// Constructs a client, or reports why it could not.
  static Result<std::shared_ptr<Client>> Create(Options options);

  virtual ~Client() = default;

  /// Whether a session token is held. NOT a security check.
  ///
  /// ⚠️ TRUE MEANS "THERE IS A STRING IN THE STORE", nothing more. Use it to
  /// decide whether to show a sign-in screen and nothing else.
  virtual bool has_session() const = 0;

  /// The environment this client is pinned to.
  ///
  /// Read from the publishable key, which carries it. Useful for a log line or
  /// a support screen, and for confirming a build is pointed where you think.
  ///
  /// ⚠️ IT IS NOT ASKED OF THE SERVER, and that is the whole point. It is
  /// what a signed token's audience is checked against, so a value the server
  /// supplied would make that check circular — anybody who could redirect
  /// this SDK would also be deciding which environment it trusts.
  virtual const std::string& environment_id() const = 0;

  /// Load a stored session and confirm the server still honours it.
  ///
  /// Returns false when there was none, or it has been revoked — in which case
  /// the store is cleared so the next launch does not retry a dead token.
  ///
  /// A session the server holds at "no plan" is still restored, because it may
  /// still redeem a code; ask `requires_plan()` afterwards for which screen to
  /// show.
  virtual Result<bool> Restore() = 0;

  /// Whether the server said, the last time it minted a token, that this
  /// session holds no plan the application requires.
  ///
  /// The way a RESTORED session learns it. A sign-in reports it on its result
  /// (`requires_plan`); a session restored at launch signs nobody in, so before
  /// this it learned only from the first call refused with
  /// `ErrorKind::kPlanRequired` — after the application had already drawn its
  /// main window. `Restore()` and `GetIdentity()` mint, so ask after either.
  ///
  /// ⚠️ A HINT FOR WHICH SCREEN TO SHOW, NEVER A GATE. It is read from the
  /// token response's body, beside the signed token rather than inside it, so
  /// anything able to answer the SDK decides it. A forged `false` reaches a
  /// main window whose every plan-gated call the server still refuses.
  virtual bool requires_plan() const = 0;

  /// Watch for the signed-in person's plans changing, and call back when they do.
  ///
  /// A plan bought in a browser, a renewal that failed, a licence redeemed on
  /// another machine: the server answers a long-poll
  /// (`GET /v1/client/entitlements/changes`) the moment the plans this person
  /// holds change, this client mints afresh — so `requires_plan()`,
  /// `GetIdentity()` and every plan-gated call agree with the change — and then
  /// `on_change` runs. Without it an application learns at its next mint,
  /// which a session restored at launch makes on demand and not before.
  ///
  /// ⚠️ ON A THREAD OF THE SDK'S OWN. `on_change` runs there, not on your UI
  /// thread: marshal back before touching a window. It must not call
  /// `WatchPlans` or `StopWatchingPlans`. An exception thrown out of it is
  /// caught and dropped, where the library is built with exceptions; without
  /// them, do not throw.
  ///
  /// ⚠️ CAPTURE THE CLIENT WEAKLY, OR NOT AT ALL. The watch keeps `on_change`
  /// for as long as it runs, and it runs until it is stopped — which releasing
  /// the last reference to the client does. A callback holding a
  /// `shared_ptr<Client>` is that last reference, so the client is never
  /// released and the watch never stops.
  ///
  /// The first answer is a baseline, not a change: `on_change` runs for it
  /// only if `requires_plan()` moved between this call and that answer, so a
  /// plan that arrived while the application was starting is not lost.
  ///
  /// Calling it again replaces the watch. Errors back off, up to a minute
  /// between attempts, and honour a 429's `Retry-After`; nothing is reported,
  /// because the next mint will say whatever the watch missed.
  virtual void WatchPlans(std::function<void()> on_change) = 0;

  /// Stop watching. Returns at once.
  ///
  /// ⚠️ IT NEVER WAITS ON THE NETWORK. A poll in flight cannot be interrupted
  /// on every platform, so it is left to finish (normally the server's hold,
  /// twelve seconds today; forty at most, against a server that never answers)
  /// on its own thread, holding the client alive until it does; its answer is
  /// then dropped. Releasing the last reference to the client does the same,
  /// and the client may then be destroyed on that thread rather than yours.
  ///
  /// ⚠️ "NO CALLBACK AFTER STOP" HOLDS FOR EVERY CALLBACK NOT ALREADY STARTED.
  /// One that began a moment before this was called can still be running when
  /// it returns, because waiting for it here would deadlock any callback that
  /// marshals synchronously to the thread calling this. Make `on_change` safe to
  /// run once more after you stop.
  ///
  /// ⚠️ A DLL THAT CAN BE UNLOADED MUST NOT UNLOAD WHILE A POLL IS IN FLIGHT.
  /// The thread runs this library's code until the poll ends, so FreeLibrary
  /// (or dlclose) in that window unmaps code a thread is executing. Stop the
  /// watch and release the client well before unloading, or never unload —
  /// which is what a DLL loaded for the life of the process does anyway.
  virtual void StopWatchingPlans() = 0;

  /// What the sign-in screen needs to know before anybody has signed in.
  ///
  /// Call this before drawing your first screen, so the screen is worded for
  /// the application it is actually talking to.
  ///
  /// ⚠️ IT IS PRESENTATION, NEVER PERMISSION, and it goes stale — see
  /// Environment. Handle the refusal on every path regardless of what it says.
  virtual Result<Environment> GetEnvironment() = 0;

  /// Is there an account for this identifier?
  ///
  /// For a screen that asks for the identifier first: somebody with no account
  /// becomes a sign-up with what they already typed, instead of being asked for
  /// the password of an account that is not there and refused one screen later,
  /// after they have gone looking for a password that was never set.
  ///
  /// Whether an unknown identifier goes to sign-up at all is the calling
  /// application's decision, not an environment setting — the choice
  /// `<SignIn withSignUp>` makes on the web. The route always answers.
  ///
  /// ⚠️ A REFUSAL IS NOT "NO ACCOUNT". Reading one as `false` would send a
  /// real user to a sign-up that then collides with the account they already
  /// have. Nothing in the failure path may be turned into a boolean; see below.
  ///
  /// ⚠️ IT PUBLISHES ACCOUNT EXISTENCE TO ANYBODY HOLDING THE PUBLISHABLE KEY,
  /// which ships inside every binary you release. That is a deliberate trade
  /// rather than an oversight: a form has to answer "should this be a sign-up"
  /// somehow, and every way of answering it discloses the same bit. `SignIn` is
  /// untouched and still refuses an unknown identifier and a wrong password
  /// identically, which is the disclosure that would actually be worth
  /// something to somebody working through a list.
  ///
  /// ⚠️ `true` MEANS "GO TO THE PASSWORD SCREEN", NOT "A PASSWORD WILL WORK".
  /// The question is about the ACCOUNT: one that signs in only through Google
  /// answers true and has no password at all, and a suspended account answers
  /// true as well — it exists, and sending that person to sign-up would collide
  /// with it. Signing in is still what decides whether they get in.
  ///
  /// ⚠️ RATE-LIMITED HARDER THAN SIGN-IN, ON ITS OWN FAIL-CLOSED BUCKET —
  /// twenty in fifteen minutes from one address. Call it when the form is
  /// submitted, never on a keystroke.
  ///
  /// kApi/400 means the value matched no shape this environment accepts, which
  /// is a message under the identifier box rather than a decision about
  /// sign-up. kMaintenance is reachable here like anywhere else: the security
  /// gate — blocklist, bot challenge, maintenance — runs before the lookup, so
  /// this is not a door around it.
  ///
  /// `bot_token` answers the merchant's bot challenge, exactly as `SignIn`'s
  /// does. Leave it empty unless they have turned one on.
  virtual Result<bool> LookupIdentifier(const std::string& identifier,
                                        const std::string& bot_token = "") = 0;

  /// Sign in with an email address, username or phone number.
  ///
  /// `bot_token` answers the merchant's bot challenge. Leave it empty unless
  /// they have turned one on.
  ///
  /// ⚠️ WITHOUT IT THERE IS NO WAY TO ANSWER BOT PROTECTION AT ALL. The
  /// server refuses any sign-in carrying no token the moment Turnstile or
  /// hCaptcha is switched on, so a native build with nowhere to put one fails
  /// for every user with "Complete the verification challenge and try again"
  /// and no challenge on screen — exactly the way the hosted pages did before
  /// they grew one. An application with an embedded browser can solve the
  /// challenge there and pass the token; one without should leave the setting
  /// off, and now has a parameter that says so rather than a signature that
  /// pretends the question does not exist.
  ///
  /// ⚠️ THREE OUTCOMES SUCCEED AND ONLY ONE OF THEM IS A SESSION. Check them
  /// in this order and treat none of them as an error:
  ///
  ///   `mfa_challenge` non-empty        → SubmitMfa. No session yet.
  ///   `password_reset_token` non-empty → ResetPassword. No session, and the
  ///                                      password was CORRECT — see the field.
  ///   otherwise                        → signed in.
  virtual Result<SignInResult> SignIn(const std::string& identifier,
                                      const std::string& password,
                                      const std::string& bot_token = "") = 0;

  /// Sign in on the environment's hosted screens, in the system browser, and come
  /// back signed in.
  ///
  /// ANOTHER way in, beside `SignIn` and the other custom-flow calls, never instead
  /// of them (docs/hosted-sign-in.md §6). The person signs in on the hosted
  /// screens, with the environment's identifiers, social providers and second
  /// factor, and in a browser that already knows them. The application never sees
  /// a password.
  ///
  /// How it works (RFC 8252). A listener opens on 127.0.0.1, on a port the operating
  /// system picks. The browser goes to the environment's sign-in URL with a PKCE
  /// challenge (S256) and a random state, and comes back to
  /// `http://127.0.0.1:<port>/callback` with a one-time code. Only a request
  /// carrying this call's state is taken; anything else is turned away and the wait
  /// goes on. The code is exchanged, with the verifier that never left this process,
  /// for a session. That session is kept exactly as `SignIn` keeps one: in the
  /// session store, proved by minting a token before this returns. The page left in
  /// the browser tells the person whether it worked, and to return to the
  /// application.
  ///
  /// The result is `SignIn`'s, read the same way: `mfa_required`, `requires_plan`
  /// and `plan_message`. There is never a challenge to answer. The second factor was
  /// asked for on the hosted screens.
  ///
  /// ⚠️ IT BLOCKS UNTIL THE PERSON COMES BACK, so call it from a worker thread. And
  /// CLOSING THE BROWSER CANNOT BE SEEN FROM HERE. A closed tab sends nothing, so
  /// this waits out `timeout_seconds` and fails with `kRedirect`/`timeout`. Show
  /// "Continue in your browser" with a Cancel button, and have
  /// `RedirectOptions::cancelled` report it. A browser that finishes after that
  /// reaches nothing, and nobody is signed in.
  ///
  /// Fails with `kRedirect` when nothing usable came back (see that kind), and with
  /// `kApi` when the exchange is refused as a sign-in would be.
  virtual Result<SignInResult> SignInWithRedirect(
      const RedirectOptions& options = RedirectOptions()) = 0;

  /// Email a code that signs somebody in.
  ///
  /// The other door, for an environment whose sign-up sets no password — see
  /// `Environment::passwordless_sign_up` — and an alternative for an account
  /// that has one. Until this existed, turning that setting on produced an
  /// application nobody could sign in to.
  ///
  /// ⚠️ IT ANSWERS IDENTICALLY WHETHER OR NOT THE ACCOUNT EXISTS, so there is
  /// nothing here to branch on and nothing to time. This door is reachable by
  /// anybody holding the publishable key, which ships inside every binary you
  /// release, and a different answer for a real address would turn it into a
  /// register of the merchant's users. Say "check your email" either way.
  ///
  /// ⚠️ WHICH IS WHY IT RETURNS `Status` AND NOT `Result<bool>`. There is no
  /// boolean here to read, and the first thing anybody handed one would do is
  /// draw a different screen for `false` — rebuilding the oracle the fixed
  /// answer exists to deny.
  ///
  /// ⚠️ AND THE CODE GOES TO THE ADDRESS ON THE ACCOUNT, NEVER TO WHAT WAS
  /// TYPED. They may have signed in by username; and even for an address,
  /// mailing the typed string would let anybody request a code for an account
  /// and have it delivered somewhere of their choosing that merely resolves to
  /// the same row. The server does not report which address it used, because
  /// saying so would name an account — so your screen must not name one
  /// either. "Check your email", not the string in the box.
  ///
  /// `bot_token` answers the merchant's bot challenge, exactly as `SignIn`'s
  /// does. Leave it empty unless they have turned one on.
  virtual Status SendSignInCode(const std::string& identifier,
                                const std::string& bot_token = "") = 0;

  /// Redeem an emailed sign-in code for a session.
  ///
  /// ⚠️ THE ADDRESS IS REQUIRED BESIDE THE CODE AND IT IS NOT REDUNDANT. Six
  /// digits alone is a space small enough to sweep; pinning the attempt to one
  /// address means an attacker has to know whose account they are guessing at.
  ///
  /// ⚠️ AND IT IS THE ADDRESS THE CODE WENT TO — the account's, which is not
  /// necessarily what was typed into SendSignInCode. Somebody who signed in by
  /// username has no code to verify under that username, so ask them for the
  /// address rather than sending the identifier back.
  ///
  /// ⚠️ TEN MINUTES AND ONE USE, the shortest-lived token this API mints. It
  /// is the only one that opens a session rather than granting a chance to set
  /// a password, so it is not a link and it does not survive being read twice.
  ///
  /// ⚠️ A REFUSED CODE IS `kApi` WITH `status == 401`, NEVER `kNotSignedIn` —
  /// that kind means this process holds no session at all, which is a
  /// different screen. Wrong, expired, already spent, and belonging to another
  /// account are one 401 by design: telling them apart would say whether a
  /// code was ever issued for that address, which is exactly the disclosure
  /// SendSignInCode spends a fixed answer to avoid. Write one sentence for all
  /// four, and offer to send another.
  ///
  /// The session is proved the way `SignIn`'s is — a token is minted and
  /// verified before this returns — so a 200 from something that cannot sign
  /// for Grantry is not a sign-in. `mfa_required` is reported here as it is
  /// there.
  virtual Result<SignInResult> VerifySignInCode(const std::string& email,
                                                const std::string& code) = 0;

  /// Finish a sign-in that stopped for a second factor.
  ///
  /// `challenge` comes from SignInResult::mfa_challenge. Pass either the six
  /// digits from the authenticator app, or one backup code — never both.
  ///
  /// ⚠️ THE SERVER REFUSES A REQUEST CARRYING BOTH OR NEITHER, so this sends
  /// exactly one: a non-empty `backup_code` wins and `code` is not sent
  /// alongside it. Leaving both empty is a 400, not a sign-in.
  ///
  /// ⚠️ THE CHALLENGE IS SHORT-LIVED AND SINGLE-USE. A wrong code costs an
  /// attempt but leaves it alive, so a typo does not send the user back to the
  /// password screen; success spends it.
  ///
  /// ⚠️ THE REFUSAL SAYS HOW MANY ATTEMPTS REMAIN, deliberately — read it
  /// from `Error::attempts_remaining` and write the sentence yourself. It used
  /// to say to show the server's message, which contradicted `Error::message`'s
  /// own warning two hundred lines above: an application cannot both render
  /// that string and refuse to render it. The count is now a number for exactly
  /// this reason.
  ///
  /// Somebody who mistyped cannot otherwise tell whether one more wrong guess
  /// sends them back to the password screen, so do show it.
  ///
  /// ⚠️ PASSING THE SECOND FACTOR STILL DOES NOT GUARANTEE A SESSION. This
  /// answers 202 with `password_reset_token` when the password checked at
  /// sign-in no longer meets the policy: the verdict was parked on the
  /// challenge and is delivered here, because handing a reset token to
  /// somebody who had only typed a password would have been an MFA bypass
  /// wearing a security feature's clothes. Check the token before you check
  /// anything else, exactly as after `SignIn`.
  ///
  /// ⚠️ AND `reasons` DOES NOT COME BACK ON THIS PATH — only the boolean
  /// `password_breached`. Render `Environment::password_policy` for the rest.
  ///
  /// Reports `backup_codes_remaining` on success; does NOT report
  /// `requires_plan`, and the note on that field says what to do instead.
  ///
  /// A correct answer also hands this installation a trusted-device token,
  /// kept beside the session (SessionStore::WriteTrustedDevice) and presented on
  /// every call after: its next sign-in on this machine is not asked for the
  /// factor for fourteen days. Signing out keeps it; the server takes it back
  /// when it stops sparing anybody.
  virtual Result<SignInResult> SubmitMfa(const std::string& challenge,
                                         const std::string& code,
                                         const std::string& backup_code =
                                             std::string()) = 0;

  /// Begin enrolling an authenticator app. Returns the secret for a QR code.
  ///
  /// ⚠️ THE SECRET LEAVES THE SERVER EXACTLY ONCE, HERE. Nothing returns it
  /// again — a user who loses it before confirming starts over, which removes
  /// any way to fetch a live second-factor secret with a stolen session.
  ///
  /// ⚠️ SO DO NOT PERSIST IT. Render it, let them scan it, let it go.
  /// Writing it to disk recreates the hole the server just closed.
  ///
  /// ⚠️ A PROOF ONLY TO REPLACE A CONFIRMED AUTHENTICATOR. A first enrolment takes none; a
  /// second, which would swap out the phone already trusted, asks for the password, a current
  /// code or a recovery code (Proof::Password, ::AuthenticatorCode, ::BackupCode) and is kApi
  /// with `status == 401` without one.
  ///
  /// ⚠️ IT RETURNED THE SECRET ALONE UNTIL 9 OCTOBER 2026, dropping the `otpauth://` address
  /// that names the application in the authenticator app. Draw the QR code from `uri`.
  virtual Result<TotpSetup> StartTotp(const std::string& label = std::string(),
                                      const std::optional<Proof>& proof = std::nullopt) = 0;

  /// Confirm an authenticator enrolment, and collect the recovery codes.
  ///
  /// ⚠️ UNTIL THIS SUCCEEDS THE FACTOR DOES NOTHING, which is what makes an
  /// abandoned enrolment safe.
  ///
  /// ⚠️ THE CODES ARE HANDED OVER HERE, WHICH IS WHY THIS RETURNS THEM. It
  /// used to return `Status` and never read the body — so the one moment a
  /// user could have written down the way back into their own account was the
  /// moment the SDK threw it away. Show them, and do not move on until the user
  /// says they have them: ViewBackupCodes can show them again, but only behind
  /// the password or the very phone they exist to replace.
  ///
  /// ⚠️ AND AN EMPTY LIST IS A SUCCESS, NOT A FAILURE. The server mints codes
  /// only when the account holds none: somebody re-enrolling an authenticator
  /// keeps the set they already have, and reissuing silently would invalidate
  /// the sheet in their drawer. Draw the codes when there are some and go
  /// straight to "done" when there are not — never an error, and never an
  /// empty list presented as one.
  virtual Result<std::vector<std::string>> ConfirmTotp(const std::string& code) = 0;

  /// The account's second factors, and what this application will let it do.
  ///
  /// ⚠️ READ `can_enrol` AND `backup_codes_enabled` BEFORE DRAWING BUTTONS,
  /// for the reason on FactorList: the server enforces both regardless, and a
  /// control that 403s when pressed is worse than one that was never offered.
  virtual Result<FactorList> ListFactors() = 0;

  /// Mint a fresh set of recovery codes, destroying the old one.
  ///
  /// ⚠️ THE OLD SET IS DEAD THE INSTANT THIS RETURNS, so a caller that fails
  /// to show what came back has taken away the way into the account and put
  /// nothing in its place. This is the whole reason the call exists; treat a
  /// success the user never saw as a failure.
  ///
  /// ⚠️ IT TAKES A PROOF SINCE 0279, AS ViewBackupCodes DOES. Replacing the set
  /// for nothing made showing it behind a password decoration: a borrowed
  /// session would mint ten fresh codes instead of reading the old ones. A
  /// wrong proof is kApi with `status == 401` and the set is untouched.
  ///
  /// Refused when the merchant does not issue recovery codes — see
  /// `FactorList::backup_codes_enabled`.
  virtual Result<std::vector<std::string>> RegenerateBackupCodes(const Proof& proof) = 0;

  /// Show the account's recovery codes again, after proving it is them.
  ///
  /// ⚠️ THE PROOF IS CHECKED IN THIS REQUEST AND SPENT BY IT. There is no
  /// window afterwards, so every view asks again, and an authenticator code
  /// works once — the one that signed somebody in a moment ago is refused.
  ///
  /// ⚠️ SHOW THE SPENT ONES AS SPENT AND SAVE ONLY THE REST, and read
  /// `regenerate_required` before anything — see BackupCodeView. A wrong proof
  /// is kApi with `status == 401`; codes the server cannot read are a 500, and
  /// they still work at sign-in.
  virtual Result<BackupCodeView> ViewBackupCodes(const Proof& proof) = 0;

  /// Take a second factor off the account.
  ///
  /// ⚠️ IT COSTS THE PASSWORD, AND THAT IS THE POINT OF THE CALL. A session
  /// proves "signed in at some point", possibly on a laptop somebody walked
  /// past; turning off the second factor is the most valuable thing an
  /// attacker holding a borrowed session can do. A wrong password is kApi with
  /// `status == 401` and the factor is untouched.
  ///
  /// ⚠️ NOT GATED ON THE PLAN, DELIBERATELY. Enrolment is; removal is not.
  /// Somebody who secured their account properly must be able to undo it
  /// whatever their vendor's billing does afterwards.
  virtual Status RemoveFactor(const std::string& factor_id,
                              const std::string& password) = 0;

  /// The same, with whatever proof the account can give: the password, a current code, or a
  /// recovery code when the phone is gone (Proof::Password, ::AuthenticatorCode, ::BackupCode).
  ///
  /// ⚠️ AN ACCOUNT WITH NO PASSWORD COULD NOT REMOVE A FACTOR UNTIL 9 OCTOBER 2026: the call
  /// above was the only one, and one that signs in with Google has nothing to put in it.
  virtual Status RemoveFactor(const std::string& factor_id, const Proof& proof) = 0;

  /// Create an account.
  ///
  /// Which fields an environment requires is configured in the dashboard, so
  /// this takes a map rather than a fixed signature. The server is the
  /// authority and will say which field is missing.
  virtual Result<SignInResult> SignUp(const std::map<std::string, std::string>& fields) = 0;

  /// Finish a sign-up that stopped for email confirmation.
  ///
  /// ⚠️ THE ACCOUNT IS CREATED HERE, NOT AT SignUp. The form writes a
  /// reservation; this is what turns it into a user. Somebody who never
  /// comes back leaves no row behind, which is the point of the design — so
  /// an application that reports kPendingVerification and stops has not
  /// signed anybody up at all.
  ///
  /// ⚠️ THE ADDRESS TRAVELS WITH THE CODE, AND THE SERVER REQUIRES IT. Six
  /// digits is a million possibilities; a lookup on the code alone would let
  /// a caller guess their way into somebody else's pending sign-up. Five
  /// wrong codes destroys the reservation and the sign-up starts again.
  ///
  /// ⚠️ A CODE, NOT A LINK, AND THAT IS WHY IT IS A METHOD. A link opens in
  /// whatever browser the mail app prefers, so the session lands somewhere
  /// the application cannot reach — which for a native build is nowhere at
  /// all. Confirming in-process is the only shape that works.
  virtual Result<SignInResult> ConfirmEmail(const std::string& email,
                                            const std::string& code) = 0;

  /// Send a code that confirms the SIGNED-IN account's own address.
  ///
  /// ⚠️ NOT ConfirmEmail ABOVE, DESPITE THE NAMES. That one finishes a
  /// SIGN-UP: there is no session, the account does not exist yet, and the
  /// address travels with the code because nothing else identifies it. This
  /// pair acts on the account already signed in here and takes no address at
  /// all — the subject is the session, like every other `/me` call.
  ///
  /// It exists because an environment that does not REQUIRE verification never
  /// offers the step: sign-up creates the account, signs it in, and nothing
  /// ever asks again. "Not required" is not "forbidden", and an address nobody
  /// confirmed cannot be sent a password reset with any confidence.
  ///
  /// ⚠️ ALREADY CONFIRMED IS A SUCCESS, NOT A REFUSAL, AND `false` IS THE
  /// ANSWER. `ok()` is true with the value false: nothing was sent because
  /// there was nothing to send. A screen offering this step can race a reload,
  /// a second window, or an `Identity` read a moment earlier — and reporting a
  /// failure for the state the person wanted is the bug this shape avoids. Do
  /// not draw a code box for it.
  ///
  /// `true` means a code is on its way; finish with ConfirmEmailVerification.
  virtual Result<bool> SendEmailVerification() = 0;

  /// Confirm the signed-in account's address with the code from the email.
  ///
  /// ⚠️ THE CODE MUST BE ONE MAILED TO THIS SESSION'S ACCOUNT. Six digits is a
  /// small enough space that somebody sweeping it would otherwise land on a
  /// live code belonging to a stranger and confirm their own address with it,
  /// so the server checks who it was issued to and refuses the rest.
  ///
  /// ⚠️ AND THAT REFUSAL IS `kApi` WITH `status == 401`, NOT `kNotSignedIn`.
  /// The session is fine; the code is wrong, expired, spent or somebody
  /// else's, and those are one answer on purpose — the same shape
  /// VerifySignInCode refuses with. Ask again rather than sending anybody back
  /// to a sign-in screen they do not need.
  virtual Status ConfirmEmailVerification(const std::string& code) = 0;

  /* --- additional addresses -------------------------------------------------
   *
   * ⚠️ FOUR ROUTES THAT EXISTED SINCE MIGRATION 0124 AND HAD NO CLIENT IN ANY
   * SDK. The API, the repository and the hosted portal all had the feature;
   * nothing an integrator installs could reach it.
   *
   * ⚠️ THE PRIMARY ADDRESS IS NOT ONE OF THESE. It is changed with ChangeEmail
   * and confirmed with the pair above; these are the others.
   * ----------------------------------------------------------------------- */

  /// Every address on this account besides the primary one.
  ///
  /// ⚠️ ASK THE ENVIRONMENT FIRST. This is refused with a 403 when the merchant
  /// has additional addresses switched off, and calling it anyway puts a 403 in
  /// their log on every load of an account screen — in among the real ones.
  ///
  /// ⚠️ THE SUBJECT IS THE SESSION, NEVER AN ARGUMENT. There is no user id to
  /// pass, so there is no version of this call that reads somebody else's
  /// addresses.
  virtual Result<std::vector<EmailAddress>> GetEmailAddresses() = 0;

  /// Claim an address for this account and mail a code to it.
  ///
  /// ⚠️ IT ANSWERS THE SAME WAY WHETHER THE ADDRESS WAS FREE OR ALREADY
  /// BELONGS TO SOMEBODY ELSE, and the server means it: a signed-in visitor
  /// could otherwise walk a list of addresses through this route and learn who
  /// is registered — the enumeration the whole sign-up path is built to refuse,
  /// reopened on an authenticated one.
  ///
  /// ⚠️ SO DO NOT REPORT "ADDED". Report that a code may be waiting in that
  /// inbox. The person who owns the address is the one who finds out, because
  /// they are the one who does or does not receive it.
  virtual Status AddEmailAddress(const std::string& email) = 0;

  /// Redeem the code mailed to one of those addresses.
  ///
  /// ⚠️ ONE REFUSAL FOR EVERY WAY THIS FAILS — wrong, expired, spent, or for an
  /// address on another account. Write one sentence and offer to send another
  /// with AddEmailAddress.
  virtual Status VerifyEmailAddress(const std::string& email,
                                    const std::string& code) = 0;

  /// Drop one of those addresses, by the id from GetEmailAddresses.
  ///
  /// ⚠️ THE PRIMARY ADDRESS CANNOT BE REMOVED THIS WAY, and the server refuses
  /// rather than leaving an account with no way to sign in or be recovered.
  /// Change it with ChangeEmail instead.
  virtual Status RemoveEmailAddress(const std::string& email_id) = 0;

  /// A verified statement of who is signed in and what they may do.
  ///
  /// Mints a fresh access token when the cached one is near expiry, and
  /// verifies every token offline — signature, algorithm, issuer, audience,
  /// expiry, and the nonce this call generated.
  ///
  /// Call it per operation rather than caching the result. The token is good
  /// for a minute by design, so a cancelled subscription stops working within a
  /// minute rather than whenever the process restarts.
  virtual Result<Identity> GetIdentity() = 0;

  /// What the signed-in user is currently paying for, if anything.
  ///
  /// ⚠️ FOR SHOWING, NOT FOR DECIDING. See `Subscription`: the gate is the
  /// signed token, and this is the unsigned billing view beside it.
  ///
  /// `active == false` is the ordinary answer for somebody on the free plan.
  virtual Result<Subscription> GetSubscription() = 0;

  /// The plans a user could subscribe to, with their prices.
  ///
  /// Needs no session: a pricing screen is read before anybody has an account.
  ///
  /// ⚠️ FOR DISPLAY. Nothing here grants anything, and the plan a user
  /// actually holds comes from GetIdentity(), which is signed. Deciding what
  /// somebody may do by matching against this list would be deciding it from an
  /// unsigned response.
  ///
  /// Empty when the merchant has not enabled billing for individual accounts.
  virtual Result<std::vector<Plan>> GetPlans() = 0;

  /// Read one variable by key.
  ///
  /// ⚠️ THERE IS NO METHOD THAT LISTS THEM, AND THE ABSENCE IS THE POINT.
  /// A listing hands back the merchant's whole configuration to anybody who
  /// can sign up, and the NAMES alone are worth having before the values
  /// are. Your application always knows its own keys.
  ///
  /// A key that does not exist and one that is withheld answer identically,
  /// because telling them apart rebuilds the listing one request at a time.
  ///
  /// ⚠️ THE VALUE IS VERIFIED BEFORE IT IS RETURNED. `if (GetVariable("tier")
  /// == "pro")` can no longer be defeated by editing a response in a proxy: the
  /// API signs every read made with a session, and a failed check is an error
  /// with `verification` set, never a value.
  virtual Result<Variable> GetVariable(const std::string& key) = 0;

  /// Write one of the signed-in user's variables.
  ///
  /// Only works for a key the merchant created against this user AND marked
  /// writable. It cannot create a key, touch a server variable, or reach
  /// somebody else's.
  ///
  /// ⚠️ WHATEVER IS WRITTEN HERE, THE USER CHOSE. A patched build writes
  /// whatever it likes, so a value read back out of this must never decide what
  /// somebody may do. Save slots and preferences are the point; entitlements
  /// are not.
  ///
  /// A refusal is `kApi` with status 403, and the reasons — no such key, not
  /// writable, not yours — are deliberately indistinguishable.
  virtual Status SetVariable(const std::string& key, const std::string& value) = 0;

  /// Redeem an activation code against the signed-in account.
  ///
  /// The code a customer was given when they bought. Redeeming puts this
  /// account on whatever the merchant attached to it, and the next GetIdentity
  /// reflects it.
  ///
  /// ⚠️ IT APPLIES TO THE SIGNED-IN ACCOUNT AND TAKES NO OTHER SUBJECT.
  /// There is no username parameter, so there is no version of this that
  /// upgrades somebody else — a shape other licensing platforms do expose,
  /// from a binary the attacker controls.
  ///
  /// ⚠️ A WRONG CODE AND A MALFORMED ONE ANSWER IDENTICALLY, so a script
  /// cannot learn the format for free.
  ///
  /// ⚠️ THIS IS THE ONE CALL A PLAN-RESTRICTED SESSION CAN STILL MAKE. With
  /// plan locking on and no accepted plan held, every other call returns
  /// `ErrorKind::kPlanRequired` — and this is the way out. That is precisely
  /// why sign-in succeeds instead of being refused.
  virtual Status Activate(const std::string& code) = 0;

  /// Suspend the signed-in account. THIS CANNOT BE UNDONE FROM HERE.
  ///
  /// For anti-tamper: when the application concludes it is being debugged or
  /// patched, this locks the account doing it. Every session ends and the
  /// credentials stop working until the merchant reverses it.
  ///
  /// ⚠️ THERE IS NO UNSUSPEND IN THIS SDK, DELIBERATELY. A self-punishment
  /// a patched binary can reverse is not a punishment.
  ///
  /// ⚠️ AND IT ACTS ONLY ON THE SIGNED-IN ACCOUNT. No subject parameter
  /// exists, so it cannot be aimed at anybody else.
  ///
  /// ⚠️ BE SURE BEFORE CALLING IT. A false positive locks out a paying
  /// customer, and they will contact you rather than go away.
  virtual Status Suspend(const std::string& reason = std::string()) = 0;

  /// Block this machine or address. THIS CANNOT BE UNDONE FROM HERE.
  ///
  /// The heavier companion to Suspend: suspending stops one account, blocking
  /// stops anybody from this machine or address, including new sign-ups.
  ///
  /// ⚠️ THE VALUE IS NEVER SENT. You choose a kind; the server supplies
  /// the value from what it already observes. If this took a value, one patched
  /// binary and a loop would put the merchant's whole customer base on their
  /// own blocklist.
  ///
  /// Self-reported blocks expire after thirty days, because a false positive
  /// should not cost a customer their address permanently.
  virtual Status Block(BlockTarget target = BlockTarget::kIpAddress,
                       const std::string& reason = std::string()) = 0;

  /// Describe one file by id.
  ///
  /// ⚠️ THERE IS NO METHOD THAT LISTS FILES, for the same reason there is
  /// none for variables: the names are reconnaissance. If you want a
  /// downloads UI, publish the ids in a variable — which is itself gated —
  /// rather than making every file discoverable.
  virtual Result<File> GetFile(const std::string& file_id) = 0;

  /// Download a file by id.
  ///
  /// ⚠️ THE BYTES COME THROUGH THE API, NOT FROM A LINK. Every download
  /// re-answers "may this caller have this file, right now", so revoking a plan
  /// or deleting the file stops the next fetch — and there is no URL to pass
  /// around that would keep working.
  ///
  /// ⚠️ THE CHECKSUM IS VERIFIED FOR YOU, AND A MISMATCH IS AN ERROR. This
  /// used to be advice; it is now what the method does. Before the bytes are
  /// returned, the SDK fetches the file's signed description, checks that
  /// envelope against Grantry's published key, hashes what actually arrived and
  /// compares. Substituting the payload therefore means producing a matching
  /// SHA-256, and substituting the checksum means holding the signing key.
  ///
  /// That costs one extra round trip, which is the right trade for a method
  /// whose result an application is likely to execute.
  ///
  /// ⚠️ AND BOUNDED: anything larger than the ceiling is refused rather
  /// than buffered, because a caller must not decide how much memory this
  /// process spends. Stream to disk yourself if you ship files that large.
  virtual Result<std::vector<std::uint8_t>> Download(const std::string& file_id) = 0;

  /// Change the signed-in account's email address.
  ///
  /// ⚠️ THE ADDRESS DOES NOT MOVE UNTIL THE NEW ONE IS CONFIRMED, which is
  /// what stops a momentary session takeover redirecting every future password
  /// reset to an address the attacker controls.
  ///
  /// ⚠️ WHETHER IT IS ALLOWED AT ALL IS THE SERVER'S DECISION. This SDK does
  /// not read the setting and does not hide the call: a client enforcing policy
  /// would be enforcing it in a binary the attacker owns. Show the button;
  /// handle the refusal.
  ///
  /// ⚠️ AND DO NOT REPORT "THAT ADDRESS IS TAKEN". A taken address and a
  /// free one answer identically, deliberately.
  virtual Status ChangeEmail(const std::string& new_email,
                             const std::string& current_password,
                             const std::string& redirect_url) = 0;

  /// The same, with whatever proof the account can give: the password, a current code, or a
  /// code mailed by SendReauthenticationCode (Proof::Password, ::AuthenticatorCode,
  /// ::EmailCode). A recovery code is refused here.
  ///
  /// ⚠️ AN ACCOUNT WITH NO PASSWORD COULD NOT CHANGE ITS ADDRESS UNTIL 9 OCTOBER 2026, for the
  /// reason on RemoveFactor's.
  virtual Status ChangeEmail(const std::string& new_email, const Proof& proof,
                             const std::string& redirect_url) = 0;

  /// Mail the account's own address a code, for Proof::EmailCode: the proof an account with
  /// neither a password nor an authenticator can give to ChangeEmail and DeleteAccount.
  ///
  /// ⚠️ TO THE ADDRESS ON THE ACCOUNT, NEVER ONE OF THE CALLER'S CHOOSING — there is nothing
  /// here to name one. Refused (kApi) when the account has no address, and rate-limited as a
  /// sign-in is.
  virtual Status SendReauthenticationCode() = 0;

  /// Replace the signed-in account's profile picture.
  ///
  /// ⚠️ THE SUBJECT IS THE SESSION, NEVER AN ARGUMENT. There is no user id to
  /// pass, so there is no version of this call that reaches somebody else's
  /// picture — the rule every `/v1/client/self` route follows.
  ///
  /// ⚠️ THE SERVER DECIDES WHAT THESE BYTES ARE, by reading them. PNG, JPEG,
  /// GIF and WebP are accepted, up to 2 MB; anything else is refused. This SDK
  /// deliberately declares `application/octet-stream` rather than guessing,
  /// because a claim the server has to ignore is worse than no claim.
  ///
  /// ⚠️ AND THE PREVIOUS URL STOPS WORKING. Every upload mints a new one, so a
  /// replaced picture is not still reachable by anyone holding the old link.
  /// Keep what this returns; do not cache the old value.
  virtual Result<std::string> ChangeAvatar(
      const std::vector<std::uint8_t>& image,
      const std::string& file_name = "avatar") = 0;

  /// Remove the signed-in account's profile picture.
  ///
  /// ⚠️ THIS ALSO CLEARS A PICTURE THAT CAME FROM A SOCIAL SIGN-IN. Removing
  /// the upload but leaving the Google one would silently restore a photograph
  /// the person had already replaced, which reads as a failed delete.
  virtual Status RemoveAvatar() = 0;

  /// Delete the signed-in account. NOT REVERSIBLE.
  ///
  /// ⚠️ THE CURRENT PASSWORD IS REQUIRED AND THE SERVER CHECKS IT. A session
  /// left open on a shared machine must not be enough to destroy an account.
  ///
  /// ⚠️ WHETHER IT IS ALLOWED AT ALL IS THE SERVER'S DECISION.
  virtual Status DeleteAccount(const std::string& current_password) = 0;

  /// The same, with whatever proof the account can give — the ones ChangeEmail takes.
  virtual Status DeleteAccount(const Proof& proof) = 0;

  /// The machines this account is activated on.
  virtual Result<std::vector<Device>> GetDevices() = 0;

  /// Release one of this account's own devices.
  ///
  /// ⚠️ MOST MERCHANTS HAVE THIS OFF, AND THAT IS THE DEFAULT. Somebody who
  /// can release freely has no device limit at all — "release and re-add" is
  /// an unlimited allowance with extra steps. A merchant granting a budget is
  /// choosing convenience over that, and the server counts it over a window.
  ///
  /// ⚠️ THE ID IS REQUIRED. Further down the stack an absent id means every
  /// device, so omitting it would sign the user out of every machine they own.
  virtual Status ReleaseDevice(const std::string& device_id) = 0;

  /// A legal document by key.
  virtual Result<LegalDocument> GetLegalDocument(const std::string& key) = 0;

  /// Start a "forgot password" flow for an address.
  ///
  /// Needs no session — the whole point is that the person cannot get one. A
  /// message goes to the address with a single-use link that expires; nothing
  /// changes until that link is followed.
  ///
  /// ⚠️ IT ANSWERS THE SAME WHETHER THE ADDRESS HAS AN ACCOUNT OR NOT, and
  /// that is the security property. Do not build "no account with that address"
  /// from the response, and do not time the call and infer it: somebody working
  /// through a list of addresses must not learn which are the merchant's
  /// customers.
  ///
  /// ⚠️ THE REDIRECT URL MUST BE ONE THE MERCHANT ALLOWLISTED. It is where
  /// the emailed link lands, so an unchecked one would be an open redirect with
  /// a valid reset token attached. The server refuses anything not on the list.
  ///
  /// For most native applications this is the whole flow: call it, then tell
  /// the user to check their email and finish in the browser.
  virtual Status RequestPasswordReset(const std::string& email,
                                      const std::string& redirect_url) = 0;

  /// Finish a "forgot password" flow with the token from the email.
  ///
  /// Also needs no session. The token stands in for one, so treat it exactly as
  /// you would a password: never log it, and hold it no longer than the call.
  ///
  /// ⚠️ IT IS ALSO HOW A FORCED PASSWORD UPDATE IS REDEEMED. `SignIn` and
  /// `SubmitMfa` can hand back `password_reset_token`, which is the same kind
  /// of token this consumes — that is precisely why no second endpoint exists
  /// for the forced case. Pass it here with whatever the user typed into your
  /// new-password box.
  ///
  /// ⚠️ AND IT DOES NOT LEAVE YOU SIGNED IN, ON EITHER PATH. The server does
  /// open a session at the end of a successful reset, and this SDK drops it —
  /// deliberately, because that session is not something a `Status` can hand
  /// back and is not always there to hand back: an account holding a confirmed
  /// second factor gets a fresh MFA challenge from this route instead, with no
  /// session at all. One rule that is true on every path beats a return value
  /// that is right on two of three. Send the user to your sign-in screen; the
  /// password they have just chosen is the one that works there.
  ///
  /// ⚠️ EVERY EXISTING SESSION ON THE ACCOUNT DIES, INCLUDING THIS
  /// PROCESS'S. A reset is what somebody does when they think another person
  /// has their password, so leaving that person signed in somewhere would
  /// defeat the exercise. Send the user to your sign-in screen afterwards.
  ///
  /// ⚠️ AN EXPIRED, SPENT AND FABRICATED TOKEN ALL ANSWER IDENTICALLY. Show
  /// one message for all three and offer to send another email.
  virtual Status ResetPassword(const std::string& token,
                               const std::string& new_password) = 0;

  /// Change — or set for the first time — the signed-in account's password.
  ///
  /// ⚠️ THE CURRENT PASSWORD IS REQUIRED WHENEVER THE ACCOUNT HAS ONE, and
  /// the server checks it rather than trusting that you asked. A session proves
  /// "signed in at some point, on some device"; taking an account over
  /// permanently is a bigger step than anything else a borrowed session can do,
  /// and the password is what separates the two.
  ///
  /// Pass an empty current password only for an account that has none yet —
  /// one that signed up through a provider.
  ///
  /// ⚠️ sign_out_other_sessions DEFAULTS TO TRUE, AND LEAVE IT THERE. It is
  /// what stops a borrowed session quietly adding a credential while the real
  /// owner stays signed in none the wiser. This process keeps its own session.
  virtual Status ChangePassword(const std::string& current_password,
                                const std::string& new_password,
                                bool sign_out_other_sessions = true) = 0;

  /// Ask Grantry to send an outbound request configured in the dashboard.
  ///
  /// The URL, the headers and the shape of the body live on the server. This
  /// application knows an id and passes arguments; it never sees where the
  /// request goes or what authorisation it carries.
  ///
  /// ⚠️ THAT IS THE ENTIRE POINT. The alternative is a webhook URL and its
  /// token compiled into a binary your customer owns.
  ///
  /// ⚠️ THE IDENTITY IN THE BODY IS FILLED IN SERVER-SIDE. A template using
  /// {{user.email}} gets the address from the session, not from anything passed
  /// here — so a patched build can lie about its arguments and still cannot
  /// send a notification claiming to be somebody else. Do not pass identity
  /// through `args`.
  ///
  /// ⚠️ AND THE REPLY IS USUALLY EMPTY. The merchant decides per relay
  /// whether the response body comes back, and the default is that it does not.
  ///
  /// kApi/404 covers both "no such relay" and "not for you", deliberately.
  virtual Result<RelayResult> SendRelay(
      const std::string& relay_id,
      const std::map<std::string, std::string>& args =
          std::map<std::string, std::string>()) = 0;

  /// Begin single sign-on, and get the URL to send the user to.
  ///
  /// ⚠️ OPEN IT IN THE SYSTEM BROWSER, NOT AN EMBEDDED WEBVIEW. An embedded
  /// view is a window your process controls, so it can read what the user types
  /// into the identity provider — every major provider refuses them for that
  /// reason. It also denies the user their existing session and password
  /// manager.
  ///
  /// The URL is single-use and short-lived. Do not cache it, and do not build
  /// one by hand: the state it carries ties the callback to this request.
  ///
  /// `bot_token` answers the merchant's bot challenge, exactly as `SignIn`'s
  /// does. Leave it empty unless they have turned one on.
  ///
  /// ⚠️ THIS IS THE ONLY LEG OF A PROVIDER SIGN-IN THAT CAN CARRY ONE. The
  /// provider's redirect back has nowhere to put a token, so with bot
  /// protection on the server refuses to start a sign-in without it.
  virtual Result<std::string> StartSso(const std::string& provider,
                                       const std::string& redirect_url,
                                       const std::string& bot_token = "") = 0;

  /// Every account signed in on this client, and which one is active.
  ///
  /// Multi-session is a per-application setting. Most native applications leave
  /// it off, in which case this reports one account and `SwitchAccount` is
  /// refused — check `AccountList::multi_session` before offering a switcher.
  ///
  /// ⚠️ THE LIST IS SCOPED BY THE TOKEN YOU PRESENT. There is no
  /// identifier in the request naming a client or a group, so this cannot be
  /// pointed at somebody else's machine.
  virtual Result<AccountList> GetAccounts() = 0;

  /// Make another account on this client the active one.
  ///
  /// ⚠️ THE SESSION TOKEN CHANGES, AND THIS SDK HANDLES THAT FOR YOU. The
  /// server mints the target a fresh token rather than handing back the one it
  /// was created with — which is why a background account's credential is
  /// never in this process — and returns it in the session header, which is
  /// captured the same way rotation already is.
  ///
  /// ⚠️ ANY CACHED IDENTITY IS NOW SOMEBODY ELSE'S. Access tokens,
  /// entitlements and the user id all belong to the account that WAS active.
  /// Call `GetIdentity` again before deciding anything on them.
  ///
  /// kApi/403 when the application allows one account at a time; kApi/404 when
  /// the id is not an account signed in on this client.
  virtual Status SwitchAccount(const std::string& session_id) = 0;

  /// Leave ONE account, keeping the others signed in.
  ///
  /// The per-account sign-out a switcher offers. If the named account was the
  /// active one, the client is handed to another account it holds rather than
  /// being signed out of everything.
  ///
  /// ⚠️ THIS IS NOT `SignOut` AND MUST NOT BE WIRED TO A SIGN-OUT BUTTON.
  /// Somebody pressing sign-out means they are no longer signed in; leaving
  /// them signed in as their other account is how a shared machine leaks one.
  virtual Status SignOutOf(const std::string& session_id) = 0;

  /// End the session, here and on the server.
  ///
  /// The local store is cleared even if the network call fails: somebody who
  /// pressed sign-out on a shared machine and got an error would otherwise walk
  /// away from a signed-in application.
  ///
  /// ⚠️ THIS LEAVES EVERY ACCOUNT ON THIS CLIENT, not merely the active
  /// one. Under multi-session a client can hold several; a sign-out that left
  /// the rest signed in would be a sign-out that did not sign anybody out. Use
  /// `SignOutOf` to leave one.
  virtual Status SignOut() = 0;
};

/// Library version, for logs and support.
const char* Version();

}  // namespace grantry

#endif  // GRANTRY_GRANTRY_HPP
