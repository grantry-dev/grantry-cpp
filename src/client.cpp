#include "internal.hpp"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <mutex>
#include <thread>

namespace grantry {

namespace internal {

std::string AnchorOrFallback(const std::string& machine_anchor, SessionStore& store) {
  if (!machine_anchor.empty()) return machine_anchor;

  /*
   * ⚠️ A DEGRADED ANCHOR RATHER THAN NONE: a random identifier, kept in the session store's own
   * slot, as the C# and Python SDKs keep theirs. Weaker, and plainly so — it does not survive a
   * reinstall or a cleared store. Sending nothing instead would make device locking refuse the
   * sign-in outright.
   *
   * ⚠️ IT WAS THE CONSTANT "no-anchor" UNTIL 9 OCTOBER 2026, so every installation without an
   * anchor was the same device to the server, and they shared one seat per environment.
   */
  std::optional<std::string> kept = store.ReadDeviceFallback();
  if (kept.has_value() && !kept->empty()) return *kept;

  std::vector<std::uint8_t> random(16);
  if (RandomBytes(random.data(), random.size())) {
    std::string made = "fallback:" + Base64UrlEncode(random);
    store.WriteDeviceFallback(made);
    return made;
  }

  // No randomness to be had: this run's own value, never kept and never a shared one.
  return "fallback-run:" +
         std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) + ":" +
         std::to_string(reinterpret_cast<std::uintptr_t>(&store));
}

}  // namespace internal

namespace {

using internal::Json;

/*
 * Whether this translation unit may write try/catch. The library is built to
 * link into -fno-exceptions code and does not throw; these are the two places
 * where something it calls can: starting a thread, and a caller's callback on a
 * thread of the SDK's own, where an escaping exception is std::terminate.
 */
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
#define GRANTRY_HAS_EXCEPTIONS 1
#else
#define GRANTRY_HAS_EXCEPTIONS 0
#endif

/// Start `body` on a thread of its own. False when the system would not give one.
///
/// ⚠️ std::thread REPORTS THAT BY THROWING, and the caller here is a public
/// method of a library whose callers may be built without exceptions — an
/// exception reaching them is std::terminate. A watch or a start-up probe that
/// cannot start is a feature missing, never a reason to take a game down.
bool StartThread(std::thread& out, std::function<void()> body) {
#if GRANTRY_HAS_EXCEPTIONS
  try {
    out = std::thread(std::move(body));
  } catch (...) {
    return false;
  }
#else
  out = std::thread(std::move(body));
#endif
  return true;
}

/// The byte between the anchor and the environment id.
///
/// ⚠️ A SEPARATOR AT ALL, BECAUSE CONCATENATION IS AMBIGUOUS WITHOUT ONE.
/// `"ab" + "c"` and `"a" + "bc"` hash identically, so an anchor ending in a
/// digit against an environment id starting with one could collide with a
/// different pair. A byte that cannot occur in either input removes the
/// question.
///
/// ⚠️ AND IT MUST MATCH THE C# SDK EXACTLY. A customer shipping both a C++ and
/// a .NET application against one environment would otherwise see the same
/// machine register twice and burn two device slots. Written as a numeric
/// literal rather than an escape so no editor, encoding conversion or git
/// filter can quietly change it.
constexpr char kAnchorSeparator = static_cast<char>(0x1f);

/// The encrypted-payload format this build can undo.
///
/// Sent as the header's value rather than as a bare "yes", so a server that has
/// moved on to a scheme this build does not implement can answer in the old one
/// — or refuse — instead of returning bytes that would decrypt to nothing.
constexpr const char* kEncryptVersion = "v1";

/// Where a build challenge's proof is posted (migration 0362).
constexpr const char* kBuildProofPath = "/v1/client/build-proof";

/// The longest password the server accepts, mirrored here.
///
/// ⚠️ A CEILING, NOT A POLICY. It exists so an obviously impossible value is
/// refused before it costs an attempt against the rate limit; the merchant's
/// real rules are checked server-side.
constexpr std::size_t kMaxPasswordLength = 256;


Error MakeError(ErrorKind kind, std::string message, int status = 0) {
  Error error;
  error.kind = kind;
  error.message = std::move(message);
  error.status = status;
  return error;
}

/// A redirect sign-in that did not come back as one. See ErrorKind::kRedirect.
Error RedirectError(const std::string& code, std::string message) {
  Error error = MakeError(ErrorKind::kRedirect, std::move(message));
  error.code = code;
  return error;
}

/// The host of an absolute URL, lower-cased: brackets kept for IPv6, no port, no path.
///
/// ⚠️ EMPTY WHEN THE AUTHORITY CARRIES USERINFO. `http://127.0.0.1@api.example`
/// is a request to api.example with a user name of "127.0.0.1", and the old
/// prefix test read it as loopback — permitting plain HTTP to a real host the
/// moment `allow_insecure_loopback` was set. No API address has a use for
/// userinfo, so a URL carrying one has no host as far as this SDK is concerned.
std::string UrlHost(const std::string& url) {
  const std::size_t scheme = url.find("://");
  if (scheme == std::string::npos) return std::string();

  const std::string rest = url.substr(scheme + 3);
  const std::string authority = rest.substr(0, rest.find_first_of("/?#"));
  if (authority.find('@') != std::string::npos) return std::string();

  std::string host;
  if (!authority.empty() && authority[0] == '[') {
    const std::size_t close = authority.find(']');
    if (close == std::string::npos) return std::string();
    host = authority.substr(0, close + 1);
  } else {
    host = authority.substr(0, authority.find(':'));
  }
  for (char& c : host) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return host;
}

/// Whether a URL names this machine: `localhost`, `[::1]`, or 127.0.0.0/8.
///
/// ⚠️ 127.0.0.0/8 AS FOUR DECIMAL OCTETS, NOT AS A PREFIX. "Begins `127.`" was
/// the test until 12 October 2026, and `127.attacker.example` begins `127.` —
/// it is a name anybody can register, and it was let through over plain HTTP.
bool IsLoopback(const std::string& url) {
  const std::string host = UrlHost(url);
  if (host == "localhost" || host == "[::1]") return true;

  int octets = 0;
  int value = -1;
  int first = -1;
  for (std::size_t i = 0; i <= host.size(); i++) {
    const char c = i < host.size() ? host[i] : '.';
    if (c >= '0' && c <= '9') {
      value = (value < 0 ? 0 : value * 10) + (c - '0');
      if (value > 255) return false;
    } else if (c == '.') {
      if (value < 0) return false;
      if (octets == 0) first = value;
      octets++;
      value = -1;
    } else {
      return false;
    }
  }
  return octets == 4 && first == 127;
}

/// The transport's SPKI pins, or none when pinning resolves to off.
std::vector<std::string> CertificatePinsFor(const Options& options) {
  return internal::ShouldPin(options) ? internal::PinsFor(options) : std::vector<std::string>();
}

/// The nonce, freshly generated for one request and never reused.
///
/// ⚠️ A NONCE HELD ACROSS CALLS IS A NONCE AN ATTACKER HAS ALREADY SEEN in a
/// previous response, and a recording of that response then passes. This is
/// called immediately before each token request for exactly that reason.
bool NewNonce(std::string& out) {
  std::vector<std::uint8_t> bytes(32);
  if (!internal::RandomBytes(bytes.data(), bytes.size())) return false;
  out = internal::Base64UrlEncode(bytes);
  return true;
}

// ---------------------------------------------------------------------------
// Session stores
// ---------------------------------------------------------------------------

class FileStore : public SessionStore {
 public:
  explicit FileStore(std::string path) : path_(std::move(path)) {}

  std::optional<std::string> Read() override { return ReadProtected(path_); }

  void Write(const std::string& token) override { WriteProtected(path_, token); }

  void Clear() override { internal::RemoveFile(path_); }

  std::optional<std::string> ReadTrustedDevice() override {
    return ReadProtected(TrustedDevicePath());
  }

  /// ⚠️ A FILE OF ITS OWN, WITH THE SESSION'S PROTECTION. Written through Write
  /// it would replace the session, and a signed-in user would be signed out by
  /// answering their second factor.
  void WriteTrustedDevice(const std::string& value) override {
    WriteProtected(TrustedDevicePath(), value);
  }

  void ClearTrustedDevice() override { internal::RemoveFile(TrustedDevicePath()); }

 private:
  std::string TrustedDevicePath() const { return path_ + ".trusted-device"; }

 public:
  std::optional<std::string> ReadDeviceFallback() override {
    return ReadProtected(path_ + ".device");
  }
  void WriteDeviceFallback(const std::string& value) override {
    WriteProtected(path_ + ".device", value);
  }

 private:

  static std::optional<std::string> ReadProtected(const std::string& path) {
    std::optional<std::vector<std::uint8_t>> read = internal::ReadFileBytes(path);
    if (!read.has_value() || read->empty()) return std::nullopt;
    const std::vector<std::uint8_t>& stored = *read;

    std::vector<std::uint8_t> plaintext;
    if (internal::UnprotectLocal(stored, plaintext)) {
      return std::string(plaintext.begin(), plaintext.end());
    }

    /*
     * ⚠️ AN UNREADABLE STORE IS "SIGNED OUT", NOT A CRASH.
     *
     * DPAPI ciphertext does not survive a Windows profile rebuild or being
     * copied to another machine, and a half-written file survives a power cut.
     * All three are ordinary, and all three should put the user in front of a
     * sign-in screen rather than take the application down on launch.
     *
     * On a platform with no wrapping at all, `UnprotectLocal` returns false and
     * the bytes ARE the token — see platform_posix.cpp.
     */
    return std::string(stored.begin(), stored.end());
  }

  static void WriteProtected(const std::string& path, const std::string& token) {
    std::size_t slash = path.find_last_of("/\\");
    if (slash != std::string::npos) {
      internal::MakeDirectories(path.substr(0, slash));
    }

    std::vector<std::uint8_t> plaintext(token.begin(), token.end());
    std::vector<std::uint8_t> bytes;
    if (!internal::ProtectLocal(plaintext, bytes)) bytes = plaintext;

    /*
     * Written to a temporary file, created owner-only before anything goes in,
     * and moved into place in one step — see ReplaceFilePrivately.
     *
     * A direct write that is interrupted leaves a truncated file, and a
     * truncated DPAPI blob is indistinguishable from a corrupted one — so the
     * user is signed out by a power cut. On POSIX the stored token is
     * plaintext, so the file's permissions are the only thing protecting it,
     * and they are set before the token exists on disk.
     *
     * A write that fails leaves the previous value in place, and the process
     * still holds the new one in memory: the cost is a sign-in at next launch.
     */
    internal::ReplaceFilePrivately(path, bytes);
  }

  std::string path_;
};

class MemoryStore : public SessionStore {
 public:
  std::optional<std::string> Read() override { return token_; }
  void Write(const std::string& token) override { token_ = token; }
  void Clear() override { token_.reset(); }

  std::optional<std::string> ReadTrustedDevice() override { return trusted_device_; }
  void WriteTrustedDevice(const std::string& value) override { trusted_device_ = value; }
  void ClearTrustedDevice() override { trusted_device_.reset(); }

  std::optional<std::string> ReadDeviceFallback() override { return device_fallback_; }
  void WriteDeviceFallback(const std::string& value) override { device_fallback_ = value; }

 private:
  std::optional<std::string> token_;
  std::optional<std::string> trusted_device_;
  std::optional<std::string> device_fallback_;
};

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

/**
 * One `WatchPlans`: whether it has been stopped, and the wait between polls a stop can cut short.
 * Shared with its thread, so the client can go while a poll is still in flight.
 */
struct PlanWatch {
  std::mutex mutex;
  std::condition_variable wake;
  bool stopped = false;
};

/** Longer than any hold the server keeps a quiet poll for, so a quiet answer is never cut off. */
constexpr int kPlanWaitTimeoutSeconds = 40;

class ClientImpl : public Client, public std::enable_shared_from_this<ClientImpl> {
 public:
  ClientImpl(Options options, std::shared_ptr<SessionStore> store)
      : options_(std::move(options)),
        store_(std::move(store)),
        jwks_(options_.api_base_url + "/v1/.well-known/jwks.json",
              options_.jwks_cache_seconds, options_.pinned_key_thumbprints,
              options_.timeout_seconds, options_.allow_insecure_loopback,
              CertificatePinsFor(options_)),
        verifier_(&jwks_,
                  // ⚠️ FROM CONFIGURATION, NOT FROM THE BASE URL. Deriving the
                  // expected issuer from the server being talked to makes the
                  // check circular — whoever chooses the server would also be
                  // choosing what it must claim to be.
                  options_.issuer, options_.clock_skew_seconds,
                  options_.pinned_key_thumbprints) {
    std::optional<std::string> stored = store_->Read();
    if (stored.has_value() && !stored->empty()) session_ = *stored;

    // Read now, not at Restore: the sign-in after a cold start is exactly the
    // one a remembered installation should be spared.
    trusted_device_ = StoredTrustedDevice();

    /*
     * Computed once, not per request: reading the machine SID or spawning
     * `ioreg` on every call would put that work on the sign-in path, and the
     * anchor cannot change while the process runs.
     *
     * ⚠️ THE RAW ANCHOR NEVER LEAVES THIS SCOPE. It is hashed with the
     * environment id immediately, so the same machine is a different device to
     * every application and one merchant cannot recognise another's customers.
     */
    std::string anchor = internal::AnchorOrFallback(internal::ReadMachineAnchor(), *store_);
    device_hash_ = internal::Base64UrlEncode(
        internal::Sha256(anchor + kAnchorSeparator + options_.environment_id));

    // Computed once, for the same reason: hashing the whole executable on
    // every request would read it from disk on the sign-in path.
    application_hash_ = internal::ApplicationHash();

    pins_ = CertificatePinsFor(options_);

    /*
     * ⚠️ LAST, AFTER EVERY MEMBER IT READS IS BUILT. The thread runs from the
     * moment it starts, and it goes through Send — which reads the pins, the
     * device hash and the application hash set immediately above.
     */
    if (options_.connect_on_start) {
      // A thread the system will not give is a hello not said, and nothing more.
      StartThread(connect_, [this] {
        internal::HttpResponse response;
        // Dropped, error and all. See Options::connect_on_start.
        Send("GET", "/v1/client/environment", std::string(), response,
             std::string(), false, std::string(), kConnectTimeoutSeconds);
      });
    }
  }

  /*
   * ⚠️ THE JOIN IS THE FIRST THING THAT HAPPENS, and it is not optional. The
   * probe runs through Send, which reads this object's members; letting the
   * destructor carry on while it did that would be a read of a half-destroyed
   * client. Joining costs nothing in the normal case — the thread finished
   * during start-up — and is bounded by kConnectTimeoutSeconds in the one
   * where a server accepted the connection and then said nothing.
   */
  ~ClientImpl() override {
    StopWatchingPlans();
    if (connect_.joinable()) connect_.join();
  }

  void WatchPlans(std::function<void()> on_change) override {
    auto watch = std::make_shared<PlanWatch>();
    {
      std::lock_guard<std::mutex> lock(mutex_);
      StopLocked();
      watch_ = watch;
    }
    /*
     * ⚠️ DETACHED, AND HOLDING THE CLIENT WEAKLY. A WinHTTP request cannot be cut short, so a
     * joined thread would hold an application's exit for as long as the server holds the poll. This
     * one takes a strong reference for one request at a time and lets go between them: stopping
     * returns at once, the last reference to the client is free to go, and a thread that wakes to
     * find either has simply ends.
     */
    std::weak_ptr<ClientImpl> self = weak_from_this();
    const bool started_requiring = requires_plan();
    std::thread thread;
    if (!StartThread(thread, [self, watch, on_change = std::move(on_change), started_requiring] {
          RunPlanWatch(self, watch, on_change, started_requiring);
        })) {
      // Nothing is watching, so nothing may look as if it were.
      std::lock_guard<std::mutex> lock(mutex_);
      if (watch_ == watch) StopLocked();
      return;
    }
    thread.detach();
  }

  void StopWatchingPlans() override {
    std::lock_guard<std::mutex> lock(mutex_);
    StopLocked();
  }

  bool has_session() const override {
    std::lock_guard<std::mutex> lock(mutex_);
    return session_.has_value();
  }

  const std::string& environment_id() const override { return options_.environment_id; }

  bool requires_plan() const override {
    std::lock_guard<std::mutex> lock(mutex_);
    return requires_plan_;
  }

  Result<bool> Restore() override {
    Result<bool> result;

    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (!session_.has_value()) {
        result.value = false;
        return result;
      }
    }

    /*
     * ⚠️ PROVEN, NOT ASKED. An earlier revision called `/me` and believed a
     * `user` object in the reply — which means anything able to answer this SDK
     * could say "yes, signed in" and be believed. That is the whole KeyAuth
     * failure mode: the client asks a question and trusts the answer.
     *
     * Minting a token instead makes the server prove it holds the signing key
     * before this reports success.
     */
    Result<Identity> identity = GetIdentity();

    if (identity.ok()) {
      result.value = true;
      return result;
    }

    // A dead session is an ordinary "no", and the store is cleared so the next
    // launch does not retry it.
    if (identity.error.kind == ErrorKind::kNotSignedIn
        || (identity.error.kind == ErrorKind::kApi && identity.error.status == 401)) {
      Forget();
      result.value = false;
      return result;
    }

    /*
     * ⚠️ A VERIFICATION FAILURE IS NOT "SIGNED OUT" — IT IS AN ATTACK SIGNAL,
     * and it is reported as one. Collapsing it into `false` would show the user
     * a sign-in screen and hide the fact that something served this process a
     * response it could not verify.
     */
    if (identity.error.kind == ErrorKind::kVerification) Forget();

    /*
     * ⚠️ MAINTENANCE REACHES HERE AND MUST, KEEPING THE STORED SESSION.
     *
     * It is neither "signed out" nor an attack. The server refused to renew the
     * token without revoking anything, so this user is still signed in — and
     * clearing the store would make that false, signing every customer out for
     * real at the moment sign-in is disabled. The caller gets the error, shows
     * a wait screen, and retries later still holding its session.
     */
    result.error = identity.error;
    return result;
  }

  Result<bool> LookupIdentifier(const std::string& identifier,
                                const std::string& bot_token) override {
    Result<bool> result;

    std::map<std::string, std::string> body;
    body["identifier"] = identifier;
    // Absent when protection is off, which is the common case. Same rule as
    // SignIn below.
    if (!bot_token.empty()) body["botToken"] = bot_token;

    internal::HttpResponse response;
    Error error = Send("POST", "/v1/client/sign-in/identifier",
                       Json::Serialize(body), response);
    if (error) {
      /*
       * ⚠️ EVERY REFUSAL IS REPORTED, NEVER TURNED INTO AN ANSWER.
       *
       * GetVariable and GetFile turn a 404 into an empty result on purpose —
       * absent and withheld are deliberately one answer there. Copying that
       * here would be the opposite of safe. A `Result<bool>` carrying neither a
       * value nor an error reads as an unexplained failure, and a rate limit or
       * a dead connection says nothing about the account. It is emphatically
       * not "no account".
       */
      result.error = error;
      return result;
    }

    Json document;
    if (!Json::Parse(response.body, document)) {
      result.error = MakeError(ErrorKind::kApi, "The lookup response was not JSON.");
      return result;
    }

    /*
     * ⚠️ A MISSING FLAG IS REFUSED RATHER THAN READ AS FALSE, which is why this
     * does not use GetBool. That helper cannot tell "the server said no" from
     * "the server said nothing", and the two lead opposite ways: the first
     * offers a sign-up correctly, the second walks somebody who already has an
     * account into a collision with it. Refusing a response that carries no
     * answer is what StartTotp and GetIdentity do, and more turns on it here
     * than on either.
     */
    const Json* exists = document.Find("exists");
    if (exists == nullptr || exists->type != Json::Type::kBool) {
      result.error =
          MakeError(ErrorKind::kApi, "The lookup response carried no exists flag.");
      return result;
    }

    /*
     * ⚠️ SET ON BOTH ANSWERS, AND `false` IS THE ONE THAT IS EASY TO FORGET.
     * `Result<T>::ok()` is `!error && value.has_value()`, so leaving the value
     * unset for "there is no account" produces a result that is not ok carrying
     * an empty Error — an unexplained failure to every caller, at the exact
     * moment the right thing to do was offer a sign-up.
     */
    result.value = exists->boolean;
    return result;
  }

  Result<SignInResult> SignIn(const std::string& identifier,
                              const std::string& password,
                              const std::string& bot_token) override {
    std::map<std::string, std::string> fields;
    fields["identifier"] = identifier;
    fields["password"] = password;
    // Absent when protection is off, which is the common case.
    if (!bot_token.empty()) fields["botToken"] = bot_token;
    return Authenticate("/v1/client/sign-in", fields, false);
  }

  Result<SignInResult> SignInWithRedirect(const RedirectOptions& redirect) override {
    Result<SignInResult> result;
    if (redirect.timeout_seconds <= 0) {
      result.error = MakeError(ErrorKind::kInvalidArgument,
                               "timeout_seconds must be longer than zero.");
      return result;
    }

    /*
     * ⚠️ THE SERVER'S ANSWER, NOT ONE ASSEMBLED FROM `api_base_url`. The sign-in URL is
     * the environment's own host, where its hosted screens and their session live, and
     * it is the `iss` the answer must name. A value this SDK will not hand to the shell
     * is refused here, before a listener opens.
     */
    internal::HttpResponse response;
    Error error = Send("GET", "/v1/client/environment", std::string(), response);
    if (error) {
      result.error = error;
      return result;
    }
    Json document;
    const Json* environment = nullptr;
    if (Json::Parse(response.body, document)) environment = document.Find("environment");
    const std::string sign_in_url = environment != nullptr && environment->is_object()
                                        ? environment->GetString("issuer").value_or(std::string())
                                        : std::string();
    if (!internal::SignInUrlOpenable(sign_in_url)) {
      result.error = RedirectError("not_offered",
                                   "This environment offers no sign-in URL this SDK can open.");
      return result;
    }
    // The verifier is the credential: it never leaves this process except in the exchange.
    std::string verifier;
    std::string state;
    if (!NewNonce(verifier) || !NewNonce(state)) {
      result.error = MakeError(ErrorKind::kTransport,
                               "The system random number generator is unavailable.");
      return result;
    }

    // Open before the browser is, so the answer always has somewhere to land.
    internal::LoopbackListener listener;
    if (!listener.ok()) {
      result.error = RedirectError("listener_unavailable",
                                   "No loopback port could be opened for the sign-in to come "
                                   "back to.");
      return result;
    }
    const std::string redirect_uri = listener.redirect_uri();

    std::string base = sign_in_url;
    while (!base.empty() && base.back() == '/') base.pop_back();
    std::string authorize =
        base + "/oauth/authorize?response_type=code&client_id="
        + PercentEncode(options_.publishable_key) + "&redirect_uri=" + PercentEncode(redirect_uri)
        + "&scope=" + PercentEncode("openid profile email") + "&state=" + PercentEncode(state)
        + "&code_challenge=" + PercentEncode(internal::PkceChallenge(verifier))
        + "&code_challenge_method=S256";
    /*
     * ⚠️ "CONTINUE AS" UNLESS TOLD OTHERWISE (14 October 2026). The browser's own sign-in
     * outlives `SignOut`, which is this application's alone, so a sign-in that asked
     * for nothing came straight back as whoever the browser held.
     */
    if (redirect.prompt == RedirectPrompt::kSelectAccount) {
      authorize += "&prompt=select_account";
    } else if (redirect.prompt == RedirectPrompt::kLogin) {
      authorize += "&prompt=login";
    }

    const bool opened = redirect.open_browser ? redirect.open_browser(authorize)
                                              : internal::OpenSystemBrowser(authorize);
    if (!opened) {
      result.error = RedirectError("browser_unavailable",
                                   "The browser could not be opened to sign in.");
      return result;
    }

    std::map<std::string, std::string> answer;
    switch (listener.Wait(state, redirect.timeout_seconds, redirect.cancelled, answer)) {
      case internal::LoopbackListener::Outcome::kAnswered:
        break;
      case internal::LoopbackListener::Outcome::kTimedOut:
        result.error = RedirectError("timeout",
                                     "Nobody came back from the browser in time. A closed "
                                     "browser looks like this too.");
        return result;
      case internal::LoopbackListener::Outcome::kCancelled:
        result.error = RedirectError("cancelled", "The sign-in was cancelled.");
        return result;
      case internal::LoopbackListener::Outcome::kFailed:
        result.error = RedirectError("listener_unavailable", "The loopback listener stopped.");
        return result;
    }

    std::string code;
    Error refused = internal::CodeFromAnswer(answer, sign_in_url, code);
    if (refused) {
      listener.Redirect(internal::FinishedUrl(sign_in_url, false));
      result.error = refused;
      return result;
    }

    /*
     * THROUGH Authenticate, THE PASSWORD SIGN-IN'S OWN PATH. The session is taken from
     * the same header into the same store, proved by minting a token, and reported
     * from the same fields — so a session reached this way cannot be held differently
     * from one reached with a password.
     */
    std::map<std::string, std::string> fields;
    fields["code"] = code;
    fields["codeVerifier"] = verifier;
    // Exactly as authorize was given it: the code is bound to the string, port and all.
    fields["redirectUri"] = redirect_uri;
    result = Authenticate("/v1/client/oauth/exchange", fields, false);

    /*
     * ⚠️ ANSWERED LAST, SO THE PAGE TELLS THE TRUTH. The browser waits on this request
     * while the code is exchanged and the session proved; it is sent on to "you're signed
     * in" only once both have happened.
     *
     * ⚠️ AND THE PAGE IS THE SIGN-IN HOST'S, NOT OURS (10 October 2026). This used to answer
     * with a page of its own — inline HTML under a `default-src 'none'` policy, so system
     * fonts and a palette of its own, straight after the person had signed in on the hosted
     * card. It sends the browser back to that card's `/finished` page instead, which wears
     * the environment's theme and names the application itself.
     */
    const bool signed_in = result.ok() && result->mfa_challenge.empty()
                        && result->password_reset_token.empty();
    listener.Redirect(internal::FinishedUrl(sign_in_url, signed_in));
    return result;
  }

  Status SendSignInCode(const std::string& identifier,
                        const std::string& bot_token) override {
    Status status;

    std::map<std::string, std::string> body;
    body["identifier"] = identifier;
    // Absent when protection is off, which is the common case. Same rule as
    // SignIn above.
    if (!bot_token.empty()) body["botToken"] = bot_token;

    internal::HttpResponse response;
    /*
     * ⚠️ THE 202 IS THE WHOLE ANSWER AND IT IS THE SAME EITHER WAY, so there
     * is no body to parse and nothing to report but the refusals that never
     * reached the lookup — a bot challenge, a blocklist, maintenance. A
     * version of this that read `sent` and handed it back would be publishing
     * a boolean the server deliberately does not vary.
     */
    status.error =
        Send("POST", "/v1/client/sign-in/code", Json::Serialize(body), response);
    return status;
  }

  Result<SignInResult> VerifySignInCode(const std::string& email,
                                        const std::string& code) override {
    std::map<std::string, std::string> fields;
    fields["email"] = email;
    fields["code"] = code;

    /*
     * ⚠️ THROUGH Authenticate, SO THE SESSION IS PROVED RATHER THAN BELIEVED.
     * This route answers exactly as sign-in does — a session header and a user
     * — and a hand-rolled version that read the body and stopped would be
     * convinced by a party holding no key. See the note in Authenticate.
     *
     * `signing_up` is false for the reason ConfirmEmail passes false: there is
     * no pending outcome to report here, only a session or a refusal.
     */
    return Authenticate("/v1/client/sign-in/code/verify", fields, false);
  }

  Result<SignInResult> SubmitMfa(const std::string& challenge,
                                 const std::string& code,
                                 const std::string& backup_code) override {
    Result<SignInResult> result;

    std::map<std::string, std::string> body;
    body["token"] = challenge;
    if (!backup_code.empty()) {
      body["backupCode"] = backup_code;
    } else {
      body["code"] = code;
    }

    internal::HttpResponse response;
    Error error = Send("POST", "/v1/client/mfa/verify", Json::Serialize(body), response);
    if (error) {
      result.error = error;
      return result;
    }

    Json document;
    if (!Json::Parse(response.body, document)) {
      result.error = MakeError(ErrorKind::kApi, "The MFA response was not JSON.");
      return result;
    }

    {
      std::lock_guard<std::mutex> lock(mutex_);
      cached_.reset();
    }

    /*
     * ⚠️ THE FACTOR CAN BE RIGHT AND STILL PRODUCE NO SESSION. Sign-in
     * re-checked the password against the current policy and parked the verdict
     * on the challenge rather than acting on it — handing a reset token to
     * somebody who had only typed a password would let a stolen password set a
     * new one without ever proving the second factor. Both halves have now been
     * shown, so the refusal is delivered here instead.
     *
     * ⚠️ ABOVE GetIdentity, LIKE THE SAME BRANCH IN Authenticate. There is no
     * session on this response.
     *
     * `reasons` is absent here — the verdict was decided at sign-in and only a
     * boolean rode on the challenge — so `password_breached` comes back false
     * and the caller states the requirements from Environment::password_policy.
     */
    internal::PasswordUpdate update;
    if (internal::PasswordUpdateFrom(document, update)) {
      SignInResult pending;
      pending.password_reset_token = update.token;
      pending.password_breached = update.breached;
      result.value = pending;
      return result;
    }

    // The session exists from here, so it is proved like any other. See the
    // note in Authenticate.
    Result<Identity> proof = GetIdentity();
    if (!proof.ok()) {
      if (proof.error.kind == ErrorKind::kVerification) Forget();
      result.error = proof.error;
      return result;
    }

    SignInResult value;

    /*
     * ⚠️ `requiresPlan` AND `planMessage` USED TO BE READ HERE WHEN THIS ROUTE
     * SENT NEITHER. `/v1/client/mfa/verify` answered `{ backupCodesRemaining }`
     * or the 202 above, so both reads returned the absent-key default and
     * `requires_plan` was hard-false on the whole second-factor path while
     * working everywhere else — a plan-locked account with an authenticator
     * reached the main window and was refused by everything in it.
     *
     * ⚠️ STOPPED READING RATHER THAN ASKING THE SERVER TO SEND IT, and the
     * reason is that the honest value is already available and is stronger than
     * the one that was missing. The restriction is applied server-side to the
     * session this route creates, exactly as on the password path; what was
     * absent was the REPORT, not the restriction. The report has an
     * authoritative form — `ErrorKind::kPlanRequired`, returned by the first
     * call the restriction actually refuses — and a client that handles it
     * covers every path, an older server, and a plan that lapses mid-session.
     *
     * ⚠️ THE SERVER HAS SENT THE REPORT HERE SINCE SEPTEMBER 2026, AND THIS
     * STILL DOES NOT READ IT. The C# and Python SDKs do; the argument above is
     * why this one was left alone when the other two were brought in line, and
     * it still holds. Reading it would be one line, `value.requires_plan =
     * document.GetBool("requiresPlan")`, if the three are ever to agree.
     */
    value.backup_codes_remaining = internal::BackupCodesRemainingFrom(document);
    result.value = value;
    return result;
  }

  Result<TotpSetup> StartTotp(const std::string& label,
                              const std::optional<Proof>& proof) override {
    Result<TotpSetup> result;

    std::map<std::string, std::string> body;
    if (!label.empty()) body["name"] = label;
    // None for a first enrolment; the server asks for one with a 401 when it is replacing one.
    if (proof.has_value()) body[proof->field()] = proof->value();

    internal::HttpResponse response;
    Error error = Send("POST", "/v1/client/mfa/totp", Json::Serialize(body), response);
    if (error) {
      result.error = error;
      return result;
    }

    Json document;
    if (!Json::Parse(response.body, document)) {
      result.error = MakeError(ErrorKind::kApi, "The enrolment response was not JSON.");
      return result;
    }

    std::optional<std::string> secret = document.GetString("secret");
    if (!secret.has_value()) {
      result.error = MakeError(ErrorKind::kApi, "The enrolment response carried no secret.");
      return result;
    }

    TotpSetup setup;
    setup.factor_id = document.GetString("id").value_or(std::string());
    setup.secret = *secret;
    setup.uri = document.GetString("uri").value_or(std::string());
    result.value = std::move(setup);
    return result;
  }

  Result<std::vector<std::string>> ConfirmTotp(const std::string& code) override {
    Result<std::vector<std::string>> result;

    std::map<std::string, std::string> body;
    body["code"] = code;

    internal::HttpResponse response;
    Error error =
        Send("POST", "/v1/client/mfa/totp/confirm", Json::Serialize(body), response);
    if (error) {
      result.error = error;
      return result;
    }

    Json document;
    if (!Json::Parse(response.body, document)) {
      result.error =
          MakeError(ErrorKind::kApi, "The confirmation response was not JSON.");
      return result;
    }

    /*
     * ⚠️ `backupCodes`, NOT `codes`. Reading the wrong key here returned
     * nothing AFTER the server had already issued the set, so the one moment a
     * user could have written down the way back into their own account passed
     * silently. The same key is on /mfa/backup-codes below, for the same
     * reason.
     *
     * ⚠️ AND A JSON NULL IS AN EMPTY LIST, NOT A REFUSAL. The server withholds
     * codes when the account already holds unspent ones — a re-enrolment must
     * not invalidate the sheet in somebody's drawer — so an empty vector is the
     * normal answer to that case and is reported as a success.
     */
    result.value = document.GetStringArray("backupCodes");
    return result;
  }

  Result<FactorList> ListFactors() override {
    Result<FactorList> result;

    internal::HttpResponse response;
    Error error = Send("GET", "/v1/client/mfa", std::string(), response);
    if (error) {
      result.error = error;
      return result;
    }

    Json document;
    if (!Json::Parse(response.body, document)) {
      result.error = MakeError(ErrorKind::kApi, "The factors response was not JSON.");
      return result;
    }

    FactorList list;
    list.backup_codes_remaining =
        static_cast<int>(document.GetInt("backupCodesRemaining").value_or(0));
    list.can_enrol = document.GetBool("canEnrol");
    list.backup_codes_enabled = document.GetBool("backupCodesEnabled");

    const Json* data = document.Find("data");
    if (data != nullptr && data->is_array()) {
      for (const Json& entry : data->array) {
        std::optional<std::string> id = entry.GetString("id");
        if (!id.has_value() || id->empty()) continue;

        Factor factor;
        factor.id = *id;
        factor.type = entry.GetString("type").value_or("totp");
        factor.name = entry.GetString("name").value_or(std::string());
        /*
         * Confirmed is the PRESENCE of a timestamp, not a flag — the server
         * sends `confirmedAt: null` for an enrolment nobody finished, and that
         * row is in this list. See Factor::confirmed.
         */
        const Json* confirmed_at = entry.Find("confirmedAt");
        factor.confirmed = confirmed_at != nullptr && confirmed_at->is_string();
        factor.last_used_at = entry.GetString("lastUsedAt").value_or(std::string());
        factor.created_at = entry.GetString("createdAt").value_or(std::string());
        list.factors.push_back(std::move(factor));
      }
    }

    result.value = std::move(list);
    return result;
  }

  Result<std::vector<std::string>> RegenerateBackupCodes(const Proof& proof) override {
    Result<std::vector<std::string>> result;

    // The proof since 0279: see Proof, and ViewBackupCodes below.
    internal::HttpResponse response;
    Error error = Send("POST", "/v1/client/mfa/backup-codes",
                       internal::ProofBody(proof), response);
    if (error) {
      result.error = error;
      return result;
    }

    Json document;
    if (!Json::Parse(response.body, document)) {
      result.error = MakeError(ErrorKind::kApi, "The backup-code response was not JSON.");
      return result;
    }

    /*
     * ⚠️ REFUSED RATHER THAN READ AS AN EMPTY SET, which is why this does not
     * simply hand back GetStringArray. The old codes are already destroyed by
     * the time this parses, so "the server sent none" and "the server sent
     * something this SDK could not read" both leave the user with no way back
     * into their account — and only one of them may be reported as a success.
     * ConfirmTotp is the opposite case on purpose: an empty list is a real
     * answer there.
     */
    std::vector<std::string> codes = document.GetStringArray("backupCodes");
    if (codes.empty()) {
      result.error =
          MakeError(ErrorKind::kApi, "The backup-code response carried no codes.");
      return result;
    }

    result.value = std::move(codes);
    return result;
  }

  Result<BackupCodeView> ViewBackupCodes(const Proof& proof) override {
    Result<BackupCodeView> result;

    internal::HttpResponse response;
    Error error = Send("POST", "/v1/client/mfa/backup-codes/reveal",
                       internal::ProofBody(proof), response);
    if (error) {
      result.error = error;
      return result;
    }

    Json document;
    BackupCodeView view;
    if (!Json::Parse(response.body, document) ||
        !internal::BackupCodeViewFrom(document, view)) {
      /*
       * An error, never an empty set: "you have no codes" is a claim about the
       * account, and a body this SDK could not read is not evidence for it.
       */
      result.error =
          MakeError(ErrorKind::kApi, "The backup-code response carried no codes.");
      return result;
    }

    result.value = std::move(view);
    return result;
  }

  Status RemoveFactor(const std::string& factor_id,
                      const std::string& password) override {
    return RemoveFactor(factor_id, Proof::Password(password));
  }

  Status RemoveFactor(const std::string& factor_id, const Proof& proof) override {
    Status status;
    std::map<std::string, std::string> body;
    body[proof.field()] = proof.value();

    internal::HttpResponse response;
    status.error = Send("DELETE", "/v1/client/mfa/" + PercentEncode(factor_id),
                        Json::Serialize(body), response);
    return status;
  }

  Result<SignInResult> SignUp(const std::map<std::string, std::string>& fields) override {
    /*
     * ⚠️ `acceptedLegal` GOES AS A BOOLEAN. The map holds strings, so it went as "true", and the
     * server's schema wants `true` — every C++ sign-up on an environment that requires agreeing
     * to its terms was refused (9 October 2026). Pass "true" or "false" for it.
     */
    std::map<std::string, std::string> strings = fields;
    std::map<std::string, bool> flags;
    auto legal = strings.find("acceptedLegal");
    if (legal != strings.end()) {
      flags["acceptedLegal"] = legal->second == "true";
      strings.erase(legal);
    }
    return AuthenticateBody("/v1/client/sign-up", Json::Serialize(strings, flags), true);
  }

  Result<SignInResult> ConfirmEmail(const std::string& email,
                                    const std::string& code) override {
    std::map<std::string, std::string> fields;
    fields["email"] = email;
    fields["code"] = code;

    /*
     * ⚠️ `signing_up` IS FALSE, AND THAT IS THE WHOLE BEHAVIOUR. It forces
     * the status to "signed_in", so this proves the session rather than
     * reporting another pending outcome. Passing true would answer a
     * successful confirmation with kPendingVerification and leave the caller
     * in the loop this method exists to break.
     */
    return Authenticate("/v1/client/verify-email", fields, false);
  }

  Result<bool> SendEmailVerification() override {
    Result<bool> result;

    internal::HttpResponse response;
    Error error = Send("POST", "/v1/client/me/verify-email", std::string(), response);
    if (error) {
      result.error = error;
      return result;
    }

    Json document;
    if (!Json::Parse(response.body, document)) {
      result.error =
          MakeError(ErrorKind::kApi, "The verification response was not JSON.");
      return result;
    }

    /*
     * ⚠️ A MISSING FLAG IS REFUSED RATHER THAN READ AS FALSE, which is why
     * this does not use GetBool — the same rule LookupIdentifier follows. That
     * helper cannot tell "nothing was sent, because the address is already
     * confirmed" from "the server said nothing", and here the first is a
     * success the caller has to act on while the second is a response nobody
     * should be drawing a screen from. Reading silence as false hides the code
     * box from the one person who needs it.
     */
    const Json* sent = document.Find("sent");
    if (sent == nullptr || sent->type != Json::Type::kBool) {
      result.error =
          MakeError(ErrorKind::kApi, "The verification response carried no sent flag.");
      return result;
    }

    /*
     * ⚠️ SET ON BOTH ANSWERS, AND `false` IS THE ONE THAT IS EASY TO FORGET.
     * `Result<T>::ok()` is `!error && value.has_value()`, so leaving the value
     * unset for "already confirmed" produces a result that is not ok carrying
     * an empty Error — an unexplained failure reported for the outcome the
     * person actually wanted.
     */
    result.value = sent->boolean;
    return result;
  }

  Status ConfirmEmailVerification(const std::string& code) override {
    Status status;
    std::map<std::string, std::string> body;
    body["code"] = code;

    internal::HttpResponse response;
    status.error = Send("POST", "/v1/client/me/verify-email/confirm",
                        Json::Serialize(body), response);
    // The address is confirmed now, and the cached identity said it was not.
    if (!status.error) ForgetIdentity();
    return status;
  }

  Result<std::vector<EmailAddress>> GetEmailAddresses() override {
    Result<std::vector<EmailAddress>> result;

    internal::HttpResponse response;
    Error error = Send("GET", "/v1/client/me/emails", std::string(), response);
    if (error) {
      result.error = error;
      return result;
    }

    Json document;
    if (!Json::Parse(response.body, document)) {
      result.error = MakeError(ErrorKind::kApi, "The addresses response was not JSON.");
      return result;
    }

    std::vector<EmailAddress> addresses;
    const Json* data = document.Find("data");
    if (data != nullptr && data->is_array()) {
      for (const Json& entry : data->array) {
        std::optional<std::string> id = entry.GetString("id");
        std::optional<std::string> email = entry.GetString("email");
        if (!id.has_value() || id->empty()) continue;
        if (!email.has_value() || email->empty()) continue;

        EmailAddress address;
        address.id = *id;
        address.email = *email;
        /*
         * GetBool is right here and wrong in SendEmailVerification, which is
         * why that one does not use it: there, a missing flag and `false` mean
         * different things and silence has to be refused. Here an address the
         * server did not call verified is simply not verified.
         */
        address.verified = entry.GetBool("verified");
        address.created_at = entry.GetString("createdAt").value_or(std::string());
        addresses.push_back(std::move(address));
      }
    }

    result.value = std::move(addresses);
    return result;
  }

  Status AddEmailAddress(const std::string& email) override {
    Status status;
    std::map<std::string, std::string> body;
    body["email"] = email;

    internal::HttpResponse response;
    status.error =
        Send("POST", "/v1/client/me/emails", Json::Serialize(body), response);
    return status;
  }

  Status VerifyEmailAddress(const std::string& email,
                            const std::string& code) override {
    Status status;
    std::map<std::string, std::string> body;
    body["email"] = email;
    body["code"] = code;

    internal::HttpResponse response;
    status.error =
        Send("POST", "/v1/client/me/emails/verify", Json::Serialize(body), response);
    return status;
  }

  Status RemoveEmailAddress(const std::string& email_id) override {
    Status status;

    internal::HttpResponse response;
    status.error = Send("DELETE", "/v1/client/me/emails/" + PercentEncode(email_id),
                        std::string(), response);
    return status;
  }

  Result<Identity> GetIdentity() override {
    Result<Identity> result;

    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (cached_.has_value()
          && cached_->expires_at() - kRefreshMarginSeconds > internal::UnixNow()) {
        result.value = *cached_;
        return result;
      }
      if (!session_.has_value()) {
        result.error = MakeError(ErrorKind::kNotSignedIn,
                                 "No session. Call SignIn or Restore first.");
        return result;
      }
    }

    // Serialised, so twenty threads asking at once produce one request.
    std::lock_guard<std::mutex> refresh(refresh_mutex_);

    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (cached_.has_value()
          && cached_->expires_at() - kRefreshMarginSeconds > internal::UnixNow()) {
        result.value = *cached_;
        return result;
      }
    }

    std::string nonce;
    if (!NewNonce(nonce)) {
      // ⚠️ REFUSED RATHER THAN FALLING BACK TO A WEAKER SOURCE. Without a
      // usable CSPRNG there is no replay defence, and proceeding would mean
      // silently downgrading the one property this SDK exists to provide.
      result.error = MakeError(ErrorKind::kTransport,
                               "The system random number generator is unavailable.");
      return result;
    }

    std::map<std::string, std::string> body;
    body["nonce"] = nonce;

    internal::HttpResponse response;
    Error error = Send("POST", "/v1/client/token", Json::Serialize(body), response);
    if (error) {
      result.error = error;
      return result;
    }

    Json document;
    if (!Json::Parse(response.body, document)) {
      result.error = MakeError(ErrorKind::kApi, "The token response was not JSON.");
      return result;
    }

    std::optional<std::string> token = document.GetString("access_token");
    if (!token.has_value()) {
      result.error = MakeError(ErrorKind::kApi, "The token response carried no access_token.");
      return result;
    }

    /*
     * ⚠️ THE AUDIENCE COMES FROM CONFIGURATION, NEVER FROM THE SERVER. Asking
     * would make the check circular: whoever chooses the server would also be
     * choosing what it must claim to be. See Options::environment_id.
     */
    Result<Identity> verified = verifier_.Verify(*token, options_.environment_id, nonce);
    if (!verified.ok()) return verified;

    {
      std::lock_guard<std::mutex> lock(mutex_);
      cached_ = *verified.value;
      /*
       * ⚠️ RECORDED ON EVERY MINT, BECAUSE EVERY MINT RE-DECIDES IT. The server
       * recomputes the restriction here (a plan bought five minutes ago, or one
       * that lapsed), so the last answer is the current one. Absent means
       * admitted, as on every sign-in door. See `requires_plan()`.
       */
      requires_plan_ = document.GetBool("requiresPlan");
    }
    return verified;
  }

  /// Percent-encode one path segment. Unreserved characters per RFC 3986 pass
  /// through; everything else becomes %XX.
  static std::string PercentEncode(const std::string& raw) {
    static const char* kHex = "0123456789ABCDEF";
    std::string out;
    out.reserve(raw.size());
    for (unsigned char c : raw) {
      const bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                           || (c >= '0' && c <= '9')
                           || c == '-' || c == '_' || c == '.' || c == '~';
      if (unreserved) {
        out.push_back(static_cast<char>(c));
      } else {
        out.push_back('%');
        out.push_back(kHex[c >> 4]);
        out.push_back(kHex[c & 0x0F]);
      }
    }
    return out;
  }

  Result<Subscription> GetSubscription() override {
    Result<Subscription> result;

    internal::HttpResponse response;
    Error error = Send("GET", "/v1/client/billing/me", std::string(), response);
    if (error) {
      result.error = error;
      return result;
    }

    internal::Json document;
    if (!internal::Json::Parse(response.body, document)) {
      result.error = MakeError(ErrorKind::kApi, "The billing response was not JSON.");
      return result;
    }

    Subscription subscription;

    /*
     * ⚠️ NULL IS THE ORDINARY ANSWER, NOT AN ERROR. Somebody on the
     * environment's default free plan has no subscription row at all, and a
     * caller that treated a missing object as a failure would show an error
     * screen to every free user.
     */
    const internal::Json* entry = document.Find("subscription");
    if (entry != nullptr && entry->is_object()) {
      subscription.active = true;
      subscription.plan_key = entry->GetString("planKey").value_or(std::string());
      subscription.plan_name = entry->GetString("planName").value_or(std::string());
      subscription.status = entry->GetString("status").value_or(std::string());
      subscription.cancel_at_period_end = entry->GetBool("cancelAtPeriodEnd");

      /*
       * ⚠️ ABSENT FOR A LIFETIME, AND LEFT ABSENT. The server sends null
       * because there is no end; substituting anything here would hand every
       * countdown a date to subtract from.
       */
      subscription.current_period_end =
          entry->GetString("currentPeriodEnd").value_or(std::string());

      const internal::Json* interval = entry->Find("interval");
      if (interval != nullptr && interval->is_object()) {
        subscription.interval_unit =
            interval->GetString("unit").value_or(std::string());
        subscription.interval_count =
            static_cast<int>(interval->GetInt("count").value_or(1));
      }
    }

    result.value = subscription;
    return result;
  }

  Result<std::vector<Plan>> GetPlans() override {
    Result<std::vector<Plan>> result;

    internal::HttpResponse response;
    Error error = Send("GET", "/v1/client/billing/plans", std::string(), response);
    if (error) {
      result.error = error;
      return result;
    }

    internal::Json document;
    if (!internal::Json::Parse(response.body, document)) {
      result.error = MakeError(ErrorKind::kApi, "The plans response was not JSON.");
      return result;
    }

    std::vector<Plan> plans;
    const internal::Json* data = document.Find("data");

    if (data != nullptr && data->is_array()) {
      for (const internal::Json& entry : data->array) {
        Plan plan;
        plan.id = entry.GetString("id").value_or(std::string());
        plan.key = entry.GetString("key").value_or(std::string());
        plan.name = entry.GetString("name").value_or(std::string());
        plan.description = entry.GetString("description").value_or(std::string());

        const internal::Json* prices = entry.Find("prices");
        if (prices != nullptr && prices->is_array()) {
          for (const internal::Json& row : prices->array) {
            Price price;
            price.id = row.GetString("id").value_or(std::string());
            price.mode = row.GetString("mode").value_or("recurring");
            price.amount = row.GetInt("amount").value_or(0);
            price.currency = row.GetString("currency").value_or("USD");
            price.label = row.GetString("label").value_or(std::string());

            const internal::Json* interval = row.Find("interval");
            if (interval != nullptr && interval->is_object()) {
              price.interval_unit = interval->GetString("unit").value_or("month");
              price.interval_count =
                  static_cast<int>(interval->GetInt("count").value_or(1));
            }

            plan.prices.push_back(std::move(price));
          }
        }

        plans.push_back(std::move(plan));
      }
    }

    result.value = std::move(plans);
    return result;
  }

  Result<Variable> GetVariable(const std::string& key) override {
    Result<Variable> result;

    /*
     * ⚠️ GENERATED HERE, IMMEDIATELY BEFORE THE REQUEST, AND NEVER REUSED —
     * the same rule as GetIdentity, for the same reason. Every other claim in
     * the envelope is true of the SESSION rather than of this call, so a
     * recording of a real subscriber's response would verify perfectly on any
     * machine. The nonce is the only claim that says "minted in answer to the
     * request you just made".
     */
    std::string nonce;
    if (!NewNonce(nonce)) {
      result.error = MakeError(ErrorKind::kTransport,
                               "The system random number generator is unavailable.");
      return result;
    }

    /*
     * Only worth asking for when there is a session: the payload key derives
     * from the session token, so an anonymous caller could not undo it. What an
     * anonymous caller reads is `anyone` content — published by definition, and
     * nothing a cipher has anything to protect.
     */
    bool signed_in = false;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      signed_in = session_.has_value();
    }
    const bool encrypt = options_.encrypt_variable_payloads && signed_in;

    internal::HttpResponse response;
    Error error = Send("GET", "/v1/client/variables/" + PercentEncode(key),
                       std::string(), response, nonce, encrypt);
    if (error) {
      /*
       * ⚠️ A 404 IS "NOT THERE OR NOT FOR YOU", AND IT IS NOT AN ERROR TO
       * PROPAGATE. The two cases are deliberately indistinguishable server-side;
       * surfacing them as a failure would push callers into treating a withheld
       * key as a fault and retrying it.
       */
      if (error.kind == ErrorKind::kApi && error.status == 404) return result;
      result.error = error;
      return result;
    }

    internal::Json document;
    if (!internal::Json::Parse(response.body, document)) {
      result.error = MakeError(ErrorKind::kApi, "The variable response was not JSON.");
      return result;
    }

    /*
     * ⚠️ THE CIPHERTEXT WINS WHEN BOTH ARE SOMEHOW PRESENT. The server drops
     * the plaintext whenever it encrypts, so the two never arrive together —
     * and if they ever did, preferring the readable one would let anything in
     * the path switch the encryption off by adding a field.
     */
    std::string value;
    const internal::Json* encrypted_payload = document.Find("encrypted");
    if (encrypted_payload != nullptr && encrypted_payload->is_object()) {
      Error decrypt_error = DecryptVariable(key, *encrypted_payload, value);
      if (decrypt_error) {
        result.error = decrypt_error;
        return result;
      }
    } else {
      value = document.GetString("value").value_or(std::string());
    }

    /*
     * ⚠️ VERIFIED BEFORE THE EMPTY CHECK, NOT AFTER.
     *
     * A null value is legal — a variable can hold one — and the server signs
     * the digest of the empty string for it. Checking the signature only on the
     * non-null path would mean anything in the path could turn any variable
     * into "not found" simply by blanking it, and the SDK would agree without
     * looking.
     */
    Error verification = VerifySignedResource(
        document, "variable", key,
        internal::Base64UrlEncode(internal::Sha256(value)), nonce);
    if (verification) {
      result.error = verification;
      return result;
    }

    if (!document.GetString("value").has_value() && encrypted_payload == nullptr) {
      return result;
    }

    Variable variable;
    variable.key = key;
    variable.value = value;
    variable.per_user = document.GetString("scope").value_or(std::string()) == "user";
    variable.writable = document.GetBool("writable");

    result.value = std::move(variable);
    return result;
  }

  Status SetVariable(const std::string& key, const std::string& value) override {
    Status status;

    internal::HttpResponse response;
    std::map<std::string, std::string> body;
    body["value"] = value;

    /*
     * The key is percent-encoded rather than trusted into the path. It comes
     * from the application, not from us, and a key carrying a slash would
     * silently address a different route.
     */
    status.error = Send("PUT",
                        "/v1/client/variables/" + PercentEncode(key),
                        Json::Serialize(body),
                        response);
    return status;
  }

  Status Activate(const std::string& code) override {
    Status status;

    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (!session_.has_value()) {
        status.error = MakeError(ErrorKind::kNotSignedIn,
                                 "Activation applies to the signed-in account.");
        return status;
      }
    }

    std::map<std::string, std::string> body;
    body["key"] = code;

    internal::HttpResponse response;
    status.error = Send("POST", "/v1/client/licenses/redeem",
                        Json::Serialize(body), response);

    if (!status.error) {
      // Redeeming may have changed the plan and features, so the cached
      // identity is stale. Dropping it makes the next call re-mint.
      std::lock_guard<std::mutex> lock(mutex_);
      cached_.reset();
    }
    return status;
  }

  Status Suspend(const std::string& reason) override {
    Status status;

    std::map<std::string, std::string> body;
    if (!reason.empty()) body["reason"] = reason;

    internal::HttpResponse response;
    status.error = Send("POST", "/v1/client/self/suspend",
                        Json::Serialize(body), response);

    /*
     * ⚠️ THE LOCAL SESSION IS DROPPED, BUT THAT IS NOT WHAT MAKES THIS
     * WORK. The server ended every session for this account; clearing here only
     * keeps the client honest. A patched build that skipped this would still
     * find its very next request refused.
     */
    if (!status.error) Forget();
    return status;
  }

  Status Block(BlockTarget target, const std::string& reason) override {
    Status status;

    std::map<std::string, std::string> body;
    body["target"] = target == BlockTarget::kDevice ? "device" : "ip";
    if (!reason.empty()) body["reason"] = reason;

    internal::HttpResponse response;
    status.error = Send("POST", "/v1/client/self/block",
                        Json::Serialize(body), response);
    return status;
  }

  Result<File> GetFile(const std::string& file_id) override {
    Result<File> result;

    // Fresh per call, never reused. See GetVariable.
    std::string nonce;
    if (!NewNonce(nonce)) {
      result.error = MakeError(ErrorKind::kTransport,
                               "The system random number generator is unavailable.");
      return result;
    }

    internal::HttpResponse response;
    Error error = Send("GET", "/v1/client/files/" + PercentEncode(file_id),
                       std::string(), response, nonce);
    if (error) {
      // Same rule as GetVariable: absent and withheld are one answer.
      if (error.kind == ErrorKind::kApi && error.status == 404) return result;
      result.error = error;
      return result;
    }

    internal::Json document;
    if (!internal::Json::Parse(response.body, document)) {
      result.error = MakeError(ErrorKind::kApi, "The file response was not JSON.");
      return result;
    }

    std::optional<std::string> id = document.GetString("id");
    if (!id.has_value()) return result;

    const std::string checksum = document.GetString("checksum").value_or(std::string());

    /*
     * ⚠️ VERIFIED AGAINST THE ID WE ASKED FOR, NOT THE ONE THE BODY CAME BACK
     * CARRYING. Trusting `id` here would undo the check entirely: whoever could
     * edit the body could edit that field too, and the envelope for some other
     * file the caller is entitled to would verify happily against its own name.
     *
     * ⚠️ AND WHAT IS SIGNED IS THE CHECKSUM, WHICH IS WHAT MAKES THE DOWNLOAD
     * TAMPER-EVIDENT WITHOUT SIGNING A GIGABYTE. The bytes never go through the
     * signer — they cannot, at this size. Download hashes what actually arrives
     * and compares it against the value verified here, so substituting the
     * payload requires producing a matching SHA-256 and substituting the
     * checksum requires Grantry's signing key.
     */
    Error verification =
        VerifySignedResource(document, "file", file_id, checksum, nonce);
    if (verification) {
      result.error = verification;
      return result;
    }

    File file;
    file.id = *id;
    file.name = document.GetString("name").value_or(*id);
    file.size_bytes = document.GetInt("sizeBytes").value_or(0);
    file.checksum = checksum;
    file.content_type =
        document.GetString("contentType").value_or("application/octet-stream");

    result.value = std::move(file);
    return result;
  }

  Result<std::vector<std::uint8_t>> Download(const std::string& file_id) override {
    Result<std::vector<std::uint8_t>> result;

    /*
     * ⚠️ THE SIGNED DESCRIPTION FIRST, THE BYTES SECOND.
     *
     * This is where the expected checksum comes from, and it has to come from
     * somewhere the caller cannot be talked out of asking. An overload taking a
     * checksum the application already held would be verifying a number against
     * itself the moment somebody obtained both from one tampered response.
     *
     * GetFile refuses a description that arrives unsigned while this caller
     * holds a session, so reaching the download at all means the checksum below
     * was covered by Grantry's key.
     */
    Result<File> described = GetFile(file_id);
    if (!described.ok()) {
      result.error = described.error;
      return result;
    }

    /*
     * ⚠️ 64 MB, AS THE PYTHON SDK READS, WHERE IT WAS THE TRANSPORT'S MEGABYTE (9 October
     * 2026): every file larger than that failed to download. Still a ceiling, for the reason
     * the transport has one.
     */
    constexpr std::size_t kMaxDownloadBytes = 64 * 1024 * 1024;
    internal::HttpResponse response;
    Error error = Send("GET",
                       "/v1/client/files/" + PercentEncode(file_id) + "/download",
                       std::string(),
                       response,
                       std::string(),
                       false,
                       std::string(),
                       0,
                       kMaxDownloadBytes);
    if (error) {
      result.error = error;
      return result;
    }

    /*
     * The transport already refuses a body past its own ceiling, so reaching
     * here means the bytes are within it. Copied out of the response string
     * rather than parsed: this is not JSON and must never be treated as such.
     */
    std::vector<std::uint8_t> bytes(response.body.begin(), response.body.end());

    /*
     * ⚠️ HASHED AND COMPARED HERE, NOT LEFT TO THE CALLER.
     *
     * An SDK that hands back unverified bytes with a documented warning has
     * moved the check to the one place it will not happen. The merchant who
     * most needs it — shipping an update, or a payload their application is
     * about to run — is the one who reads "remember to verify the checksum"
     * and does not.
     *
     * A description with an empty checksum is refused rather than skipped: the
     * alternative is a defence anything in the path can switch off by blanking
     * one field.
     */
    const std::string expected =
        described.value.has_value() ? described.value->checksum : std::string();
    if (expected.empty()) {
      result.error.kind = ErrorKind::kVerification;
      result.error.verification = VerificationFailure::kContentMismatch;
      result.error.message =
          "The file arrived with no checksum to check it against, so there is no way to tell "
          "whether these are the bytes Grantry stored.";
      return result;
    }

    std::string actual = internal::Hex(internal::Sha256(bytes));
    std::string lowered = expected;
    for (char& c : lowered) {
      if (c >= 'A' && c <= 'F') c = static_cast<char>(c - 'A' + 'a');
    }

    if (!internal::FixedTimeEquals(actual, lowered)) {
      result.error.kind = ErrorKind::kVerification;
      result.error.verification = VerificationFailure::kContentMismatch;
      result.error.message =
          "The downloaded bytes did not match the checksum Grantry signed. Do not use them, and "
          "do not retry — something between this application and the API changed the file.";
      return result;
    }

    result.value = std::move(bytes);
    return result;
  }

  Status ChangeEmail(const std::string& new_email,
                     const std::string& current_password,
                     const std::string& redirect_url) override {
    return ChangeEmail(new_email, Proof::Password(current_password), redirect_url);
  }

  Status ChangeEmail(const std::string& new_email, const Proof& proof,
                     const std::string& redirect_url) override {
    Status status;
    std::map<std::string, std::string> body;
    body["newEmail"] = new_email;
    body[proof.field()] = proof.value();
    body["redirectUrl"] = redirect_url;

    internal::HttpResponse response;
    status.error = Send("POST", "/v1/client/change-email",
                        Json::Serialize(body), response);
    return status;
  }

  Status SendReauthenticationCode() override {
    Status status;
    internal::HttpResponse response;
    status.error =
        Send("POST", "/v1/client/me/reauthentication-code", std::string(), response);
    return status;
  }

  Result<std::string> ChangeAvatar(const std::vector<std::uint8_t>& image,
                                   const std::string& file_name) override {
    Result<std::string> result;

    if (image.empty()) {
      result.error = MakeError(ErrorKind::kInvalidArgument, "The image was empty.");
      return result;
    }

    /*
     * ⚠️ A RANDOM BOUNDARY, NOT A FIXED ONE. A multipart boundary that appears
     * inside the payload ends the part early, and a constant makes that
     * trivial to arrange on purpose: an image whose bytes contain the literal
     * boundary would let whoever chose the file terminate our body and append
     * parts of their own. 128 random bits makes an accidental collision
     * impossible and a deliberate one unguessable.
     */
    std::string suffix;
    if (!NewNonce(suffix)) {
      result.error = MakeError(ErrorKind::kTransport,
                               "The system random number generator is unavailable.");
      return result;
    }
    /*
     * Base64url is legal in a boundary: RFC 2046 permits `-` and `_` along with
     * the alphanumerics, and this stays well inside the 70-character ceiling.
     */
    const std::string boundary = "----grantry" + suffix;

    /*
     * ⚠️ THE FILE NAME IS SANITISED BECAUSE IT LANDS IN A HEADER. A quote or a
     * newline in it would close the `filename=` attribute and let the caller
     * write multipart headers of their own — which matters the moment a
     * merchant passes through a name their user chose. Only characters that
     * cannot change the framing survive.
     */
    std::string safe_name;
    for (char c : file_name) {
      const bool ordinary = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                            (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
      if (ordinary) safe_name.push_back(c);
    }
    if (safe_name.empty()) safe_name = "avatar";

    /*
     * `application/octet-stream` on purpose: a client cannot be trusted to
     * describe its own upload, so the server decides what these bytes are by
     * reading them. Claiming `image/png` here would be a claim it has to
     * ignore anyway.
     */
    std::string body;
    body.reserve(image.size() + 256);
    body += "--" + boundary + "\r\n";
    body += "Content-Disposition: form-data; name=\"file\"; filename=\"" + safe_name + "\"\r\n";
    body += "Content-Type: application/octet-stream\r\n\r\n";
    body.append(reinterpret_cast<const char*>(image.data()), image.size());
    body += "\r\n--" + boundary + "--\r\n";

    internal::HttpResponse response;
    Error error = Send("POST", "/v1/client/self/avatar", body, response, std::string(),
                       false, "multipart/form-data; boundary=" + boundary);
    if (error) {
      result.error = error;
      return result;
    }

    Json document;
    if (!Json::Parse(response.body, document)) {
      result.error = MakeError(ErrorKind::kApi, "The upload response was not JSON.");
      return result;
    }

    std::optional<std::string> url = document.GetString("avatarUrl");
    if (!url.has_value()) {
      result.error = MakeError(ErrorKind::kApi, "The upload response carried no picture URL.");
      return result;
    }

    result.value = *url;
    return result;
  }

  Status RemoveAvatar() override {
    Status status;
    internal::HttpResponse response;
    status.error = Send("DELETE", "/v1/client/self/avatar", std::string(), response);
    return status;
  }

  Status DeleteAccount(const std::string& current_password) override {
    return DeleteAccount(Proof::Password(current_password));
  }

  Status DeleteAccount(const Proof& proof) override {
    Status status;
    std::map<std::string, std::string> body;
    body[proof.field()] = proof.value();

    internal::HttpResponse response;
    status.error = Send("POST", "/v1/client/delete-account",
                        Json::Serialize(body), response);

    // The account is gone; holding its session would be a lie.
    if (!status.error) Forget();
    return status;
  }

  Result<std::vector<Device>> GetDevices() override {
    Result<std::vector<Device>> result;

    internal::HttpResponse response;
    Error error = Send("GET", "/v1/client/account/devices", std::string(), response);
    if (error) {
      result.error = error;
      return result;
    }

    internal::Json document;
    if (!internal::Json::Parse(response.body, document)) {
      result.error = MakeError(ErrorKind::kApi, "The devices response was not JSON.");
      return result;
    }

    std::vector<Device> devices;
    const internal::Json* data = document.Find("data");
    if (data != nullptr && data->is_array()) {
      for (const internal::Json& entry : data->array) {
        std::optional<std::string> id = entry.GetString("id");
        if (!id.has_value() || id->empty()) continue;

        Device device;
        device.id = *id;
        device.label = entry.GetString("label").value_or(*id);
        device.platform = entry.GetString("platform").value_or("unknown");
        device.last_seen_at = entry.GetString("lastSeenAt").value_or(std::string());
        device.current = entry.GetBool("current");
        devices.push_back(std::move(device));
      }
    }

    result.value = std::move(devices);
    return result;
  }

  Status ReleaseDevice(const std::string& device_id) override {
    Status status;
    std::map<std::string, std::string> body;
    body["activationId"] = device_id;

    internal::HttpResponse response;
    status.error = Send("POST", "/v1/client/account/devices/release",
                        Json::Serialize(body), response);
    return status;
  }

  Result<AccountList> GetAccounts() override {
    Result<AccountList> result;

    internal::HttpResponse response;
    Error error = Send("GET", "/v1/client/accounts", std::string(), response);
    if (error) {
      result.error = error;
      return result;
    }

    internal::Json document;
    if (!internal::Json::Parse(response.body, document)) {
      result.error = MakeError(ErrorKind::kApi, "The accounts response was not JSON.");
      return result;
    }

    AccountList list;
    list.multi_session = document.GetBool("multiSession");

    const internal::Json* data = document.Find("data");
    if (data != nullptr && data->is_array()) {
      for (const internal::Json& entry : data->array) {
        std::optional<std::string> session_id = entry.GetString("sessionId");
        if (!session_id.has_value() || session_id->empty()) continue;

        Account account;
        account.session_id = *session_id;
        account.is_current = entry.GetBool("current");
        account.last_active_at =
            entry.GetString("lastActiveAt").value_or(std::string());

        const internal::Json* user = entry.Find("user");
        if (user != nullptr && user->is_object()) {
          account.user_id = user->GetString("id").value_or(std::string());
          account.email = user->GetString("email").value_or(std::string());
          account.username = user->GetString("username").value_or(std::string());
        }

        list.accounts.push_back(std::move(account));
      }
    }

    result.value = std::move(list);
    return result;
  }

  Status SwitchAccount(const std::string& session_id) override {
    Status status;

    internal::HttpResponse response;
    status.error = Send("POST",
                        "/v1/client/accounts/" + PercentEncode(session_id) +
                            "/activate",
                        std::string(), response);
    /*
     * ⚠️ THE CACHED IDENTITY BELONGED TO THE ACCOUNT NO LONGER IN FRONT. Until 9 October 2026
     * it was kept, so `GetIdentity` went on answering for the last account — its plan, its
     * features — for up to a minute after the switch.
     */
    if (!status.error) ForgetIdentity();
    return status;
  }

  Status SignOutOf(const std::string& session_id) override {
    Status status;
    std::map<std::string, std::string> body;
    body["sessionId"] = session_id;

    internal::HttpResponse response;
    status.error =
        Send("POST", "/v1/client/sign-out", Json::Serialize(body), response);
    // Signing out of the account in front moves the session to another; see SwitchAccount.
    if (!status.error) ForgetIdentity();
    return status;
  }

  Result<LegalDocument> GetLegalDocument(const std::string& key) override {
    Result<LegalDocument> result;

    internal::HttpResponse response;
    Error error = Send("GET", "/v1/client/legal/documents", std::string(), response);
    if (error) {
      result.error = error;
      return result;
    }

    internal::Json document;
    if (!internal::Json::Parse(response.body, document)) {
      result.error = MakeError(ErrorKind::kApi, "The legal response was not JSON.");
      return result;
    }

    const internal::Json* data = document.Find("data");
    if (data == nullptr || !data->is_array()) return result;

    for (const internal::Json& entry : data->array) {
      if (entry.GetString("kind").value_or(std::string()) != key) continue;

      LegalDocument found;
      found.key = key;
      found.url = entry.GetString("url").value_or(std::string());
      found.text = entry.GetString("body")
                       .value_or(entry.GetString("content").value_or(std::string()));
      found.version = entry.GetString("version").value_or(std::string());

      result.value = std::move(found);
      return result;
    }

    // Absent is not an error: a merchant who published no privacy policy has
    // not misconfigured anything.
    return result;
  }

  Result<Environment> GetEnvironment() override {
    Result<Environment> result;

    internal::HttpResponse response;
    Error error = Send("GET", "/v1/client/environment", std::string(), response);
    if (error) {
      result.error = error;
      return result;
    }

    internal::Json document;
    if (!internal::Json::Parse(response.body, document)) {
      result.error =
          MakeError(ErrorKind::kApi, "The environment response was not JSON.");
      return result;
    }

    const internal::Json* env = document.Find("environment");
    if (env == nullptr || !env->is_object()) {
      result.error = MakeError(ErrorKind::kApi,
                               "The environment response was not in the expected shape.");
      return result;
    }

    Environment found;
    found.application_name = env->GetString("applicationName").value_or(std::string());
    found.identifiers = env->GetStringArray("identifiers");

    /*
     * ⚠️ ABSENT MUST MEAN PASSWORDS, WHICH IS WHY THIS IS NOT GetBool.
     * That helper collapses "the server said false" into "the server said
     * nothing", and here they lead opposite ways: a server on the previous
     * release does not publish this field at all, and reading its silence as
     * passwordless would put a code prompt in front of every user of every
     * environment that still has passwords — and mail one to whatever they
     * typed. So the answer has to be present AND a boolean AND false before
     * anything changes, which is the equality the header describes; `!true` is
     * not the same test.
     *
     * The struct field is inverted from the wire for the same reason: it makes
     * the safe reading the default one, rather than a default that has to be
     * remembered. See Environment::passwordless_sign_up.
     */
    const internal::Json* password_sign_up = env->Find("passwordSignUp");
    found.passwordless_sign_up = password_sign_up != nullptr
                              && password_sign_up->type == internal::Json::Type::kBool
                              && password_sign_up->boolean == false;

    found.username_required = env->GetBool("usernameRequired");
    found.require_email_verification = env->GetBool("requireEmailVerification");

    /*
     * What the password field will accept.
     *
     * ⚠️ READ BECAUSE THE REFUSAL DOES NOT CARRY IT. A sign-in that comes back
     * with `password_reset_token` says the current password fails the policy;
     * the server's own `reasons` are not exposed to the caller, and on the
     * second-factor path they do not arrive at all. This is what a new-password
     * screen states its requirements from, on both paths and in advance.
     *
     * ⚠️ ABSENT LEAVES EVERY MEMBER AT ITS DEFAULT, and the header tells
     * callers to draw nothing rather than a list demanding zero characters. A
     * server on an older release does not publish the object.
     */
    const internal::Json* policy = env->Find("passwordPolicy");
    if (policy != nullptr && policy->is_object()) {
      found.password_policy.min_length =
          static_cast<int>(policy->GetInt("minLength").value_or(0));
      found.password_policy.require_uppercase = policy->GetBool("requireUppercase");
      found.password_policy.require_lowercase = policy->GetBool("requireLowercase");
      found.password_policy.require_number = policy->GetBool("requireNumber");
      found.password_policy.require_symbol = policy->GetBool("requireSymbol");
      found.password_policy.min_strength =
          static_cast<int>(policy->GetInt("minStrength").value_or(0));
    }

    // An empty list would leave a caller with no box to draw at all.
    if (found.identifiers.empty()) found.identifiers.push_back("email");

    /*
     * ⚠️ AN UNRECOGNISED MODE READS AS kOpen, DELIBERATELY. An old binary
     * meeting a newer server should fall back to the screen offering the most
     * doors and let the server close the ones that are shut. The alternative
     * — refusing what it does not understand — is a shipped build that
     * shows nobody any way in, and the merchant cannot fix it from their
     * dashboard.
     */
    const std::string mode = env->GetString("accessMode").value_or(std::string());
    if (mode == "waitlist") {
      found.access_mode = AccessMode::kWaitlist;
    } else if (mode == "invite_only") {
      found.access_mode = AccessMode::kInviteOnly;
    } else {
      found.access_mode = AccessMode::kOpen;
    }

    /*
     * ⚠️ CLOSED IS `== "all"`, NEVER `!= "off"`. A server on the previous
     * release does not send this field at all, and a build that read the
     * absence as closed would black out every application pointed at one — an
     * outage caused by upgrading the CLIENT. Absent and unrecognised therefore
     * fall to open, the same direction as accessMode above.
     *
     * ⚠️ AND THIS ROUTE IS THE ONLY ONE THAT ANSWERS WHILE CLOSED, which is
     * a flag is worth reading here at all: everything else refuses with the
     * maintenance code, so this is where a client learns WHY.
     */
    found.closed_for_maintenance =
        env->GetString("maintenanceMode").value_or(std::string()) == "all";

    result.value = std::move(found);
    return result;
  }

  Status RequestPasswordReset(const std::string& email,
                              const std::string& redirect_url) override {
    Status status;

    std::map<std::string, std::string> body;
    body["email"] = email;
    body["redirectUrl"] = redirect_url;

    internal::HttpResponse response;
    status.error = Send("POST", "/v1/client/request-password-reset",
                        Json::Serialize(body), response);
    return status;
  }

  Status ResetPassword(const std::string& token,
                       const std::string& new_password) override {
    Status status;

    status.error = CheckPasswordLength(new_password);
    if (status.error) return status;

    std::map<std::string, std::string> body;
    body["token"] = token;
    body["password"] = new_password;

    internal::HttpResponse response;
    status.error =
        Send("POST", "/v1/client/reset-password", Json::Serialize(body), response);
    if (status.error) return status;

    /*
     * The server has just revoked every session on this account. Holding the
     * token would mean the next call fails in a way that reads like a bug
     * rather than the sign-out it is.
     */
    Forget();
    return status;
  }

  Status ChangePassword(const std::string& current_password,
                        const std::string& new_password,
                        bool sign_out_other_sessions) override {
    Status status;

    status.error = CheckPasswordLength(new_password);
    if (status.error) return status;

    std::map<std::string, std::string> body;
    body["newPassword"] = new_password;

    // Omitted rather than sent empty for an account that has no password yet:
    // the server distinguishes "not supplied" from "supplied and wrong".
    if (!current_password.empty()) body["currentPassword"] = current_password;

    std::map<std::string, bool> flags;
    flags["signOutOfOtherSessions"] = sign_out_other_sessions;

    internal::HttpResponse response;
    status.error = Send("POST", "/v1/client/change-password",
                        Json::Serialize(body, flags), response);
    return status;
  }

  Result<RelayResult> SendRelay(
      const std::string& relay_id,
      const std::map<std::string, std::string>& args) override {
    Result<RelayResult> result;

    /*
     * The arguments go under an `args` object, so nothing the caller passes can
     * collide with a field this endpoint reads.
     */
    std::string body = "{\"args\":" + Json::Serialize(args) + "}";

    internal::HttpResponse response;
    Error error = Send("POST", "/v1/client/relays/" + PercentEncode(relay_id),
                       body, response);
    if (error) {
      result.error = error;
      return result;
    }

    internal::Json document;
    if (!internal::Json::Parse(response.body, document)) {
      result.error = MakeError(ErrorKind::kApi, "The relay response was not JSON.");
      return result;
    }

    RelayResult value;
    value.status = static_cast<int>(document.GetInt("status").value_or(0));
    value.body = document.GetString("body").value_or(std::string());
    value.truncated = document.GetBool("truncated");

    result.value = value;
    return result;
  }

  Result<std::string> StartSso(const std::string& provider,
                               const std::string& redirect_url,
                               const std::string& bot_token) override {
    Result<std::string> result;

    std::map<std::string, std::string> body;
    body["redirectUrl"] = redirect_url;
    // Absent when protection is off, which is the common case. Same rule as
    // SignIn.
    if (!bot_token.empty()) body["botToken"] = bot_token;

    internal::HttpResponse response;
    Error error = Send("POST",
                       "/v1/client/oauth/" + PercentEncode(provider) + "/start",
                       Json::Serialize(body), response);
    if (error) {
      result.error = error;
      return result;
    }

    internal::Json document;
    if (!internal::Json::Parse(response.body, document)) {
      result.error = MakeError(ErrorKind::kApi, "The sign-on response was not JSON.");
      return result;
    }

    /*
     * ⚠️ `authorization_url`, THE ONLY NAME THE ROUTE HAS EVER ANSWERED WITH.
     * This read `url`, so every sign-on came back as the error below — and
     * nothing called the method until the conformance harness did.
     */
    std::optional<std::string> url = document.GetString("authorization_url");
    if (!url.has_value()) {
      result.error = MakeError(ErrorKind::kApi, "The sign-on response carried no URL.");
      return result;
    }

    result.value = *url;
    return result;
  }

  Status SignOut() override {
    Status status;

    bool had_session;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      had_session = session_.has_value();
    }

    if (had_session) {
      internal::HttpResponse response;
      // The local half happens whatever the network says: somebody who pressed
      // sign-out on a shared machine and got an error would otherwise walk away
      // from a signed-in application.
      Send("POST", "/v1/client/sign-out", std::string(), response);
    }

    Forget();
    return status;
  }

 private:
  static constexpr std::int64_t kRefreshMarginSeconds = 10;

  /// How long the start-up probe may take before it is abandoned.
  ///
  /// Short because the destructor waits for it, and a merchant's application
  /// closing must not sit for half a minute on a request whose answer nobody
  /// was ever going to read.
  static constexpr int kConnectTimeoutSeconds = 5;

  /// Shared by SignIn and SignUp.
  ///
  /// `signing_up` gates the non-session outcomes below. Sign-in has only one
  /// success shape, so a sign-in response claiming one of them is nonsense —
  /// and it goes down the verification path, where the absent session is
  /// caught, rather than being reported as a waitlist entry nobody asked for.
  Result<SignInResult> Authenticate(const std::string& path,
                                    const std::map<std::string, std::string>& fields,
                                    bool signing_up) {
    return AuthenticateBody(path, Json::Serialize(fields), signing_up);
  }

  /// The same, for a body already serialised: sign-up's, which carries a boolean.
  Result<SignInResult> AuthenticateBody(const std::string& path, const std::string& body,
                                        bool signing_up) {
    Result<SignInResult> result;

    internal::HttpResponse response;
    Error error = Send("POST", path, body, response);
    if (error) {
      result.error = error;
      return result;
    }

    Json document;
    if (!Json::Parse(response.body, document)) {
      result.error = MakeError(ErrorKind::kApi, "The API returned a body that was not JSON.");
      return result;
    }

    {
      // A fresh sign-in invalidates whatever identity was cached, even for the
      // same person: the session id changed.
      std::lock_guard<std::mutex> lock(mutex_);
      cached_.reset();
    }

    /*
     * ⚠️ A SUCCESSFUL SIGN-UP DOES NOT ALWAYS MEAN A SESSION.
     *
     * Three things can come back. The account may be live and signed in; it
     * may be waiting on an emailed CODE (finish it with ConfirmEmail),
     * because the merchant requires verification OR because the address was
     * already taken; or the
     * application may not be taking sign-ups at all, in which case the server
     * adds the address to the waitlist rather than refusing outright.
     *
     * Only the first has a session. Proving one in the other two would turn a
     * normal outcome into "not signed in" — an obscure error at the exact
     * moment the application should be saying "check your email", and one that
     * appears the day a merchant turns verification on, in a build that
     * shipped months earlier.
     */
    /*
     * ⚠️ THE SECOND FACTOR STOPS BEFORE ANY SESSION EXISTS, and this branch
     * is what makes that survivable. The server answers with a challenge and
     * nothing else: no session header, no user. Falling through to GetIdentity
     * threw "not signed in" at everybody who had ever enrolled an
     * authenticator.
     */
    const Json* challenge = document.Find("mfa");
    if (challenge != nullptr && challenge->is_object()) {
      SignInResult pending;
      pending.mfa_challenge = challenge->GetString("token").value_or(std::string());
      result.value = pending;
      return result;
    }

    /*
     * ⚠️ A 202 THAT IS NOT AN ERROR AND IS NOT A SESSION EITHER, and this
     * branch is the whole of the fix for it.
     *
     * The password was CORRECT and is no longer acceptable — the plaintext is
     * re-checked against the current policy at sign-in, which is the only
     * moment it exists. `Send` treats every 2xx as success, so without this the
     * call returned "fine", fell through to GetIdentity, found no session and
     * reported NOT SIGNED IN: an unexplained sign-out at the exact moment the
     * right screen is "choose a new password", with the reset token dropped on
     * the floor.
     *
     * ⚠️ AND NO GetIdentity BELOW THIS LINE, for the same reason as the MFA
     * branch above: there is no session to prove, and proving one that does not
     * exist turns a normal outcome into a verification failure.
     */
    internal::PasswordUpdate update;
    if (internal::PasswordUpdateFrom(document, update)) {
      SignInResult pending;
      pending.password_reset_token = update.token;
      pending.password_breached = update.breached;
      result.value = pending;
      return result;
    }

    const std::string status =
        signing_up ? document.GetString("status").value_or("signed_in") : "signed_in";

    if (status == "waitlisted" || status == "pending_verification") {
      SignInResult pending;
      pending.outcome = status == "waitlisted" ? SignUpOutcome::kWaitlisted
                                               : SignUpOutcome::kPendingVerification;
      result.value = pending;
      return result;
    }

    /*
     * ⚠️ THE SINGLE MOST IMPORTANT LINE IN THIS CLASS.
     *
     * A sign-in endpoint answers with a status code and some JSON. Neither is
     * signed, so anything able to answer this SDK — a rogue DNS entry, a proxy
     * with a trusted certificate, a `hosts` file on a machine the attacker owns
     * — can return `200 {"user":{...}}` and a session token of its choosing. A
     * client that reports success at that point has been convinced by a party
     * with no key.
     *
     * Minting a token here costs one round trip and turns a server assertion
     * into a cryptographic one.
     */
    Result<Identity> proof = GetIdentity();
    if (!proof.ok()) {
      // Being left holding a token from an unverified source is worse than
      // being signed out: the next call would present it and the application
      // would carry on as though the sign-in had worked.
      if (proof.error.kind == ErrorKind::kVerification) Forget();
      result.error = proof.error;
      return result;
    }

    SignInResult value;
    value.mfa_required = document.GetBool("mfaRequired");
    value.requires_plan = document.GetBool("requiresPlan");
    value.plan_message = document.GetString("planMessage").value_or(std::string());
    result.value = value;
    return result;
  }

  /// One request, with the session carried in a header rather than a cookie.
  ///
  /// ⚠️ NO COOKIE JAR, DELIBERATELY. A cookie is a browser mechanism whose rules
  /// — SameSite, `__Host-`, the origin model — describe a threat this process is
  /// not in. The API answers this header only for callers that send no `Origin`,
  /// which is what keeps the path unreachable from a browser.
  /// One call to the API, with a build challenge answered on the way if the server asks one.
  ///
  /// ⚠️ ANSWERED HERE, ONCE, FOR EVERY CALL (migration 0362). Where the merchant
  /// checks builds, a session proves every ten minutes that this process can read
  /// part of its own file, and any call — a refresh, a variable, a file — may be
  /// the one asked. Answering in each caller would be a rule the next caller
  /// forgets; here the proof is posted and the refused call sent again.
  Error Send(const std::string& method, const std::string& path, const std::string& body,
             internal::HttpResponse& response, const std::string& resource_nonce = std::string(),
             bool request_encryption = false,
             const std::string& content_type = std::string(),
             /// Zero means the caller's configured timeout. Only the start-up
             /// probe passes anything else; see Options::connect_on_start.
             int timeout_override = 0,
             /// Zero means the transport's megabyte. Only `Download` passes more.
             std::size_t max_body_bytes = 0) {
    Error error = SendOnce(method, path, body, response, resource_nonce, request_encryption,
                           content_type, timeout_override, max_body_bytes);
    if (!error || error.code != "build_challenge" || path == kBuildProofPath) return error;

    Json document;
    const Json* challenge = nullptr;
    if (Json::Parse(response.body, document)) {
      const Json* api_error = document.Find("error");
      if (api_error != nullptr) challenge = api_error->Find("challenge");
    }
    if (challenge == nullptr) return error;

    Error answered = AnswerBuildChallenge(*challenge);
    if (answered) return answered;
    return SendOnce(method, path, body, response, resource_nonce, request_encryption,
                    content_type, timeout_override, max_body_bytes);
  }

  /// Prove this build to the server, from the slice of its file the challenge names.
  Error AnswerBuildChallenge(const Json& challenge) {
    std::optional<std::string> token = challenge.GetString("token");
    std::optional<std::int64_t> offset = challenge.GetInt("offset");
    std::optional<std::int64_t> length = challenge.GetInt("length");
    std::optional<std::string> nonce = challenge.GetString("nonce");

    std::string proof;
    if (token.has_value() && offset.has_value() && length.has_value() && nonce.has_value()
        && *offset >= 0 && *length >= 1 && *length <= 65536) {
      std::vector<std::uint8_t> slice;
      if (internal::ReadApplicationSlice(*offset, static_cast<std::size_t>(*length), slice)) {
        std::vector<std::uint8_t> mac;
        if (internal::HmacSha256(internal::Sha256(slice),
                                 std::vector<std::uint8_t>(nonce->begin(), nonce->end()), mac)) {
          proof = internal::Hex(mac);
        }
      }
    }
    if (proof.empty()) {
      Error unreadable = MakeError(
          ErrorKind::kApi, "This build could not read its own file to prove it is a listed build.", 403);
      unreadable.code = "application_unrecognised";
      return unreadable;
    }

    std::map<std::string, std::string> body;
    body["challenge"] = *token;
    body["proof"] = proof;
    internal::HttpResponse answer;
    return SendOnce("POST", kBuildProofPath, Json::Serialize(body), answer);
  }

  Error SendOnce(const std::string& method, const std::string& path, const std::string& body,
                 internal::HttpResponse& response, const std::string& resource_nonce = std::string(),
                 bool request_encryption = false,
                 const std::string& content_type = std::string(),
                 int timeout_override = 0,
                 std::size_t max_body_bytes = 0) {
    /*
     * ⚠️ THE TRANSPORT IS PROVEN BEFORE ANYTHING WORTH INTERCEPTING TRAVELS.
     *
     * See ProbeTransport. On Windows the pin can only be checked after the
     * handshake, so without this a session token would already have reached an
     * interception proxy by the time we refused its answer.
     */
    const int timeout_seconds = timeout_override > 0 ? timeout_override : options_.timeout_seconds;

    // With this request's own timeout, so the start-up probe's short one bounds
    // its proof too — the destructor waits for that thread.
    Error trusted = EnsureTransportTrusted(timeout_seconds);
    if (trusted) return trusted;

    internal::HttpRequest request;
    request.method = method;
    request.url = options_.api_base_url + path;
    request.body = body;
    request.timeout_seconds = timeout_seconds;
    request.allow_insecure = options_.allow_insecure_loopback;
    request.certificate_pins = pins_;
    if (max_body_bytes > 0) request.max_body_bytes = max_body_bytes;

    /*
     * ⚠️ SENT ONLY BY THE CALLS THAT VERIFY WHAT COMES BACK. A nonce on a
     * request whose answer nobody checks is decoration, and worse than
     * decoration: it looks like a replay defence in a network trace while
     * buying nothing. Every call site that sets this also calls
     * VerifySignedResource with the same value.
     */
    if (!resource_nonce.empty()) {
      request.headers["x-grantry-nonce"] = resource_nonce;
    }
    if (request_encryption) {
      request.headers["x-grantry-encrypt"] = kEncryptVersion;
    }

    request.headers["x-grantry-key"] = options_.publishable_key;
    /*
     * ⚠️ ONE SEND PATH, INCLUDING FOR THE ROUTE THAT CARRIES A FILE. A second
     * transport path for multipart would be a second place to forget the pin
     * probe above, the device header, the application hash and the session
     * rotation below — and it would be forgotten on an upload, which is the
     * request that least deserves an unproven transport.
     */
    if (!body.empty()) {
      request.headers["Content-Type"] =
          content_type.empty() ? std::string("application/json") : content_type;
    }

    /*
     * Sent whether or not the environment uses device locking.
     *
     * ⚠️ UNCONDITIONAL SO TURNING THE SETTING ON NEVER NEEDS A CLIENT UPDATE. A
     * merchant enabling device locking must not discover that every shipped
     * build is refused until their users install a new one.
     */
    request.headers["X-Grantry-Device"] = device_hash_;
    request.headers["X-Grantry-Device-Platform"] = internal::PlatformName();
    request.headers["X-Grantry-Sdk"] = std::string("grantry-cpp/") + Version();

    /*
     * The build's own digest, when it could be computed.
     *
     * ⚠️ SENT UNCONDITIONALLY, like the device header, so a merchant
     * turning enforcement on does not have to ship a new build first.
     * Omitted when we could not read our own file; the server decides what
     * an absent header means, and it decides that it is a refusal.
     */
    if (!application_hash_.empty()) {
      request.headers["X-Grantry-App-Hash"] = application_hash_;
      // A build this process can read is one it can prove; see Send.
      request.headers["X-Grantry-Build-Challenge"] = "1";
    }

    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (session_.has_value()) request.headers["X-Grantry-Session"] = *session_;
      /*
       * ⚠️ ON EVERY CALL, AS A BROWSER SENDS ITS COOKIE. The server reads it
       * only where it would otherwise ask for the second factor — every door
       * that opens a session — and a list here of which calls those are would
       * be this SDK second-guessing the server's.
       */
      if (trusted_device_.has_value()) {
        request.headers["X-Grantry-Trusted-Device"] = *trusted_device_;
      }
    }

    std::string transport_error;
    if (!internal::HttpSend(request, response, transport_error)) {
      return MakeError(ErrorKind::kTransport, transport_error);
    }

    /*
     * The rotated session, if this response carried one.
     *
     * An EMPTY value means the server ended the session and is telling us so —
     * a sign-out, or a refresh-token reuse it detected. Absence means "this
     * response did not rotate anything", which is the normal case on nearly
     * every route. The two must not be conflated.
     */
    auto returned = response.headers.find("x-grantry-session");
    if (returned != response.headers.end()) {
      if (returned->second.empty()) {
        Forget();
      } else {
        std::lock_guard<std::mutex> lock(mutex_);
        session_ = returned->second;
        store_->Write(returned->second);
      }
    }

    // The trusted-device token, by the same rule. Read before the status is
    // judged, as the session is: a refusal can carry "this spares nobody" too.
    auto trust_header = response.headers.find("x-grantry-trusted-device");
    if (trust_header != response.headers.end()) AdoptTrustedDevice(trust_header->second);

    if (response.status < 200 || response.status >= 300) {
      std::string message = "The Grantry API returned "
                          + std::to_string(response.status) + ".";
      std::string code;
      int attempts_remaining = -1;

      Json document;
      if (Json::Parse(response.body, document)) {
        const Json* api_error = document.Find("error");
        if (api_error != nullptr) {
          std::optional<std::string> reported = api_error->GetString("code");
          if (reported.has_value()) {
            code = *reported;
          }
          /*
           * ⚠️ THE ONE PART OF AN ERROR BODY MEANT FOR A HUMAN TO SEE.
           * Everything else here is either machine-readable or the unsigned
           * `message`, which the header tells callers not to render. A count is
           * neither: it is exactly what a second-factor screen needs, and a
           * hostile responder lying about it achieves nothing the user cannot
           * check by trying again.
           */
          attempts_remaining = internal::AttemptsRemainingFrom(*api_error);
          std::optional<std::string> detail = api_error->GetString("message");
          if (detail.has_value()) {
            /*
             * ⚠️ BOUNDED, BECAUSE THIS TEXT IS NOT VERIFIED AND OFTEN ENDS UP
             * ON SCREEN. The error body carries no signature, so anything able
             * to answer this SDK chooses what it says — and an application that
             * shows `error.message` in a dialog has rendered attacker-chosen
             * text inside a window the user trusts. Switch on `Error::kind` and
             * `status` for anything a person reads.
             */
            message = detail->size() > 300 ? detail->substr(0, 300) + "..." : *detail;
          }
        }
      }

      // The code decides the kind, not the status. See kMaintenance.
      // Its own kind, for the same reason maintenance has one: a bare 403
      // leads to an error screen, this one leads to an activate-a-code screen.
      ErrorKind kind = ErrorKind::kApi;
      if (code == "plan_required") kind = ErrorKind::kPlanRequired;
      else if (code == "maintenance") kind = ErrorKind::kMaintenance;

      Error error = MakeError(kind, message, response.status);
      error.attempts_remaining = attempts_remaining;
      error.code = code;
      return error;
    }

    return Error();
  }

  /// Refuse a password this SDK can already tell the server will refuse.
  ///
  /// ⚠️ NOT THE PASSWORD POLICY, AND IT MUST NOT GROW INTO ONE. The
  /// merchant's rules live on the server and are checked there. This only stops
  /// a value that is obviously not a password from costing an attempt against
  /// the rate limit.
  static Error CheckPasswordLength(const std::string& password) {
    if (password.empty()) {
      return MakeError(ErrorKind::kInvalidArgument, "A password is required.");
    }
    if (password.size() > kMaxPasswordLength) {
      return MakeError(ErrorKind::kInvalidArgument,
                       "That password is longer than the server accepts.");
    }
    return Error();
  }

  /// Prove the connection is Grantry's before sending a credential over it.
  ///
  /// ⚠️ ONE CREDENTIAL-FREE REQUEST, ONCE PER CLIENT, AND THE REASON IS A GAP
  /// IN WinHTTP. libcurl checks a pin during the handshake and refuses before
  /// any request byte leaves; WinHTTP offers no equivalent hook in synchronous
  /// mode, so its check lands after the request has already gone out. Without
  /// this probe, a Windows user running an interception proxy would hand over a
  /// session token and only then be told no.
  ///
  /// The probe fetches the JWKS: public by definition, sent with no session, no
  /// device header and nothing else worth reading. If the PIN fails, this
  /// client refuses every subsequent call for the rest of its life — a proxy
  /// does not come and go, and re-probing on each request would just be a way
  /// to pay the cost repeatedly for the same answer.
  ///
  /// ⚠️ ANY OTHER FAILURE IS RETRIED ON THE NEXT CALL. Until 12 October 2026
  /// every failure latched, so an application started with no network — the
  /// train the start-up probe's own comment is about, and `connect_on_start`
  /// probes at once — refused every call for as long as it ran, network or not.
  /// The call that met the failure still fails: nothing goes out unproven.
  Error EnsureTransportTrusted(int timeout_seconds) {
    if (pins_.empty()) return Error();

    std::lock_guard<std::mutex> lock(probe_mutex_);
    if (transport_trusted_) return Error();
    if (probe_error_) return probe_error_;

    internal::HttpRequest request;
    request.method = "GET";
    request.url = options_.api_base_url + "/v1/.well-known/jwks.json";
    request.timeout_seconds = timeout_seconds;
    request.allow_insecure = options_.allow_insecure_loopback;
    request.certificate_pins = pins_;

    internal::HttpResponse response;
    std::string transport_error;
    if (internal::HttpSend(request, response, transport_error)) {
      transport_trusted_ = true;
      return Error();
    }

    Error error = MakeError(ErrorKind::kTransport, transport_error);
    if (response.pin_refused) probe_error_ = error;
    return error;
  }

  /// Check the envelope the API signed over what we just read.
  ///
  /// ⚠️ AN ABSENT SIGNATURE IS A FAILURE FOR A SIGNED-IN CALLER, never a pass.
  /// Grantry signs every resource read made with a session, so a response
  /// without one did not come from Grantry — and treating "no signature" as
  /// "nothing to check" would make the whole defence removable by deleting a
  /// field, which is exactly what an interception proxy is for.
  ///
  /// An anonymous caller is the one case where there is genuinely nothing to
  /// check: it reads `anyone` content, already published, already identical in
  /// every copy of the application, and bound to no user for a subject claim to
  /// name. An envelope with an empty subject would verify for everybody, which
  /// is worse than none because it looks like a guarantee.
  Error VerifySignedResource(const internal::Json& document, const std::string& kind,
                             const std::string& key, const std::string& digest,
                             const std::string& nonce) {
    const std::string signature = document.GetString("signature").value_or(std::string());

    if (signature.empty()) {
      bool signed_in = false;
      {
        std::lock_guard<std::mutex> lock(mutex_);
        signed_in = session_.has_value();
      }
      if (!signed_in) return Error();

      Error error;
      error.kind = ErrorKind::kVerification;
      error.verification = VerificationFailure::kMissingSignature;
      error.message = "The API answered for " + kind + " \"" + key
                    + "\" without a signature. Every read made with a session is signed; an "
                      "unsigned one means something is answering in Grantry's place, or "
                      "stripping the field on the way through.";
      return error;
    }

    TokenVerifier::ResourceExpectation expected;
    // ⚠️ FROM CONFIGURATION, NEVER FROM THE SERVER. See Options::environment_id.
    expected.audience = options_.environment_id;
    expected.nonce = nonce;
    expected.kind = kind;
    expected.key = key;
    expected.digest = digest;

    /*
     * The signed-in user, when this SDK has already verified one. Empty skips
     * that single check rather than failing: an application may read a variable
     * before it has ever called GetIdentity, and refusing there would turn a
     * legitimate ordering into an attack report. The nonce still binds the
     * envelope to a request made with this session's token, which is what the
     * subject would otherwise be proving.
     */
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (cached_.has_value()) expected.subject = cached_->user_id();
    }

    return verifier_.VerifyResource(signature, expected).error;
  }

  /// Undo the API's per-session encryption of one variable payload.
  ///
  /// The key is HKDF-SHA256 over the session token, salted per response and
  /// bound to the variable's name — which is what stops a ciphertext being
  /// moved from one key's response onto another's.
  ///
  /// ⚠️ THE SESSION TOKEN IS THE INPUT KEYING MATERIAL, AND THAT IS THE WHOLE
  /// POINT. The pattern this replaces — encrypt at rest, ship the key inside
  /// the application — has one flaw that outweighs every other: the key is
  /// identical in every copy, so one person extracts it once and every
  /// customer's values are readable forever, with no way to rotate short of a
  /// new release. A key derived from the session dies when the session does.
  ///
  /// ⚠️ AND IT DOES NOT DEFEAT A PROXY WATCHING THE WHOLE EXCHANGE, which sees
  /// the token go out in the request header. What it defeats is a capture of
  /// the response alone, and bodies sitting in a log, a crash dump or a HAR
  /// file. Pinning stops the proxy; the signature stops substitution. This is
  /// the third layer, worth having because the first two can be patched out of
  /// a binary while this still has to be reimplemented.
  Error DecryptVariable(const std::string& key, const internal::Json& encrypted,
                        std::string& out) {
    if (encrypted.GetString("v").value_or(std::string()) != kEncryptVersion) {
      /*
       * ⚠️ REFUSED, NOT FALLEN BACK FROM. A build that quietly accepted an
       * unknown version would be guessing at a scheme it does not implement;
       * one that quietly re-asked without encryption would let anything in the
       * path turn the layer off by answering with a version it made up.
       */
      return MakeError(ErrorKind::kApi,
                       "The API encrypted this variable with a format this build does not "
                       "implement. Update the SDK.");
    }

    std::string token;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (!session_.has_value()) {
        return MakeError(ErrorKind::kApi,
                         "An encrypted payload arrived without a session to derive its key from.");
      }
      token = *session_;
    }

    std::vector<std::uint8_t> salt;
    std::vector<std::uint8_t> iv;
    std::vector<std::uint8_t> ciphertext;
    std::vector<std::uint8_t> tag;

    const bool decoded =
        internal::Base64UrlDecode(encrypted.GetString("salt").value_or(std::string()), salt)
        && internal::Base64UrlDecode(encrypted.GetString("iv").value_or(std::string()), iv)
        && internal::Base64UrlDecode(encrypted.GetString("ciphertext").value_or(std::string()),
                                     ciphertext)
        && internal::Base64UrlDecode(encrypted.GetString("tag").value_or(std::string()), tag);
    if (!decoded) {
      return MakeError(ErrorKind::kApi,
                       "The encrypted payload was not valid base64url.");
    }

    // Must match lib/resource-encryption.ts exactly. The key name is in the
    // info string so a payload only decrypts as the thing it is.
    const std::string info = std::string("grantry.variable.") + kEncryptVersion + "." + key;
    const std::vector<std::uint8_t> ikm(token.begin(), token.end());
    const std::vector<std::uint8_t> info_bytes(info.begin(), info.end());

    std::vector<std::uint8_t> derived;
    if (!internal::Hkdf(ikm, salt, info_bytes, 32, derived)) {
      return MakeError(ErrorKind::kTransport, "The payload key could not be derived.");
    }

    std::vector<std::uint8_t> plaintext;
    const bool ok = internal::AesGcmDecrypt(derived, iv, ciphertext, tag, plaintext);
    std::fill(derived.begin(), derived.end(), std::uint8_t{0});

    if (!ok) {
      Error error;
      error.kind = ErrorKind::kVerification;
      error.verification = VerificationFailure::kContentMismatch;
      error.message =
          "The encrypted variable payload did not authenticate. Treat this as an attack, not a "
          "retryable error.";
      return error;
    }

    out.assign(plaintext.begin(), plaintext.end());
    return Error();
  }

  /// ⚠️ THE SESSION ONLY. Signing out keeps the trusted-device token, which
  /// remembers this installation rather than the session: the next sign-in is
  /// spared the factor, as it would be in a browser. Signing out everywhere
  /// revokes it on the server, and the server then says so.
  void Forget() {
    std::lock_guard<std::mutex> lock(mutex_);
    session_.reset();
    cached_.reset();
    requires_plan_ = false;
    store_->Clear();
  }

  /// Ends the current watch, if any. Guarded by mutex_, as `watch_` is.
  void StopLocked() {
    if (!watch_) return;
    {
      std::lock_guard<std::mutex> lock(watch_->mutex);
      watch_->stopped = true;
    }
    watch_->wake.notify_all();
    watch_.reset();
  }

  /// Whether this watch has been stopped, waiting up to `seconds` first unless it is stopped meanwhile.
  static bool StoppedAfter(const std::shared_ptr<PlanWatch>& watch, int seconds) {
    std::unique_lock<std::mutex> lock(watch->mutex);
    watch->wake.wait_for(lock, std::chrono::seconds(seconds), [&] { return watch->stopped; });
    return watch->stopped;
  }

  static void RunPlanWatch(std::weak_ptr<ClientImpl> self, std::shared_ptr<PlanWatch> watch,
                           std::function<void()> on_change, bool started_requiring) {
    std::string version;
    bool baseline = true;
    int failures = 0;

    while (!StoppedAfter(watch, 0)) {
      int pause_seconds = 1;  // a floor, so nothing the server answers can make this spin
      bool notify = false;
      {
        std::shared_ptr<ClientImpl> client = self.lock();
        if (!client) return;

        if (!client->has_session()) {
          // Signed out: nothing to watch until somebody signs in, and nothing to ask meanwhile.
          pause_seconds = 30;
        } else {
          internal::HttpResponse response;
          Error error = client->Send("GET", "/v1/client/entitlements/changes?since=" + PercentEncode(version),
                                     std::string(), response, std::string(), false, std::string(),
                                     kPlanWaitTimeoutSeconds);
          if (error) {
            ++failures;
            pause_seconds = std::min(60, 1 << std::min(failures, 6));
            if (error.kind == ErrorKind::kApi && error.status == 429) {
              auto retry = response.headers.find("retry-after");
              int asked = retry == response.headers.end() ? 0 : std::atoi(retry->second.c_str());
              pause_seconds = std::max(pause_seconds, std::min(asked > 0 ? asked : 30, 300));
            }
          } else {
            failures = 0;
            internal::Json document;
            if (internal::Json::Parse(response.body, document)) {
              const bool changed = document.GetBool("changed");
              version = document.GetString("version").value_or(version);
              if (changed) {
                // Mint afresh first, so the callback finds requires_plan() and the identity agreeing.
                client->ForgetIdentity();
                (void)client->GetIdentity();
                notify = baseline ? client->requires_plan() != started_requiring : true;
              }
              baseline = false;
            }
          }
        }

        // Stopped while that poll was in flight: its answer is dropped, and nobody is called.
        if (notify && !StoppedAfter(watch, 0) && on_change) {
          /*
           * ⚠️ AN EXCEPTION OUT OF THE CALLBACK ENDS HERE. This is a thread of the
           * SDK's own, so one that escaped would be std::terminate — the whole
           * application, for a callback that only meant to redraw a window. The
           * watch goes on; the next change calls again.
           */
#if GRANTRY_HAS_EXCEPTIONS
          try {
            on_change();
          } catch (...) {
          }
#else
          on_change();
#endif
        }
      }
      if (StoppedAfter(watch, pause_seconds)) return;
    }
  }

  /// The cached identity only, for a change that leaves the session but moves what it answers
  /// for: the account in front, or a confirmed address. The next call mints afresh.
  void ForgetIdentity() {
    std::lock_guard<std::mutex> lock(mutex_);
    cached_.reset();
  }

  /// Keep, or let go of, the token that spares this installation the factor.
  ///
  /// The session header's rule exactly. A value is a token the server just
  /// issued — the second factor was answered — and replaces whatever was held.
  /// An EMPTY value is the server saying the token spares nobody any more:
  /// forgotten, expired, or revoked by a new password, a removed factor or a
  /// sign-out everywhere. Absence is every other response.
  ///
  /// ⚠️ STORED WITH THE ENVIRONMENT IT CAME FROM. A store belongs to an
  /// application, and one pointed at another environment — development, then
  /// production — must not present one environment's token to the other. The
  /// person is the server's to check: a token spares only the one who answered,
  /// so a second account signing in here is asked, and its own answer then
  /// takes the slot over, as in a browser.
  void AdoptTrustedDevice(const std::string& value) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (value.empty()) {
      trusted_device_.reset();
      store_->ClearTrustedDevice();
    } else {
      trusted_device_ = value;
      store_->WriteTrustedDevice(options_.environment_id + "\n" + value);
    }
  }

  /// The token a previous run kept, when it belongs to this environment.
  std::optional<std::string> StoredTrustedDevice() {
    std::optional<std::string> stored = store_->ReadTrustedDevice();
    if (!stored.has_value()) return std::nullopt;

    const std::size_t split = stored->find('\n');
    if (split == std::string::npos || split == 0) return std::nullopt;

    std::string token = stored->substr(split + 1);
    const std::size_t first = token.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return std::nullopt;
    token = token.substr(first, token.find_last_not_of(" \t\r\n") - first + 1);

    if (stored->substr(0, split) != options_.environment_id) return std::nullopt;
    return token;
  }

  Options options_;
  std::shared_ptr<SessionStore> store_;
  internal::JwksCache jwks_;
  TokenVerifier verifier_;

  std::string device_hash_;
  /// Computed once at construction: hashing the whole executable on every
  /// request would read it from disk on the sign-in path.
  std::string application_hash_;

  /// Resolved once at construction, so the policy is decided in one place.
  std::vector<std::string> pins_;

  /// The start-up probe. Joined in the destructor; see connect_on_start.
  std::thread connect_;

  mutable std::mutex mutex_;
  std::mutex refresh_mutex_;
  std::mutex probe_mutex_;
  /// The probe passed: the pins matched once, and are not asked again.
  bool transport_trusted_ = false;
  /// Set only when the pins did NOT match; latched, see EnsureTransportTrusted.
  Error probe_error_;
  std::optional<std::string> session_;
  /// See AdoptTrustedDevice. Guarded by mutex_, as the session is.
  std::optional<std::string> trusted_device_;
  std::optional<Identity> cached_;
  /// The last mint's report. Guarded by mutex_, as the cached identity is.
  bool requires_plan_ = false;
  /// The running `WatchPlans`, if any. Guarded by mutex_.
  std::shared_ptr<PlanWatch> watch_;
};

}  // namespace

std::unique_ptr<SessionStore> MakeFileSessionStore(const std::string& application_name) {
  std::string safe = application_name;
  for (char& c : safe) {
    bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
           || c == '-' || c == '_' || c == '.' || c == ' ';
    if (!ok) c = '_';
  }
  if (safe.empty()) safe = "grantry";

  std::string path = internal::UserDataDirectory();
#ifdef _WIN32
  path += "\\" + safe + "\\grantry\\session";
#else
  path += "/" + safe + "/grantry/session";
#endif
  return std::unique_ptr<SessionStore>(new FileStore(path));
}

std::unique_ptr<SessionStore> MakeFileSessionStoreAt(const std::string& path) {
  return std::unique_ptr<SessionStore>(new FileStore(path));
}

std::unique_ptr<SessionStore> MakeInMemorySessionStore() {
  return std::unique_ptr<SessionStore>(new MemoryStore());
}

namespace {

/**
 * The environment a publishable key names, or empty.
 *
 * `pk_test_<base64url(env_...)>_<random>`. Three segments is the older format,
 * which carries nothing and has to be told.
 */
std::string EnvironmentFromKey(const std::string& token) {
  if (token.rfind("pk_", 0) != 0) return {};

  // Split on '_': `pk` `test` `<encoded>` `<random>`.
  std::vector<std::string> parts;
  std::string current;
  for (char c : token) {
    if (c == '_') {
      parts.push_back(current);
      current.clear();
    } else {
      current.push_back(c);
    }
  }
  parts.push_back(current);
  if (parts.size() < 4) return {};

  std::vector<std::uint8_t> bytes;
  if (!internal::Base64UrlDecode(parts[2], bytes)) return {};
  const std::string decoded(bytes.begin(), bytes.end());

  /*
   * ⚠️ THE `env_` PREFIX IS THE VALIDITY CHECK. base64 accepts almost
   * anything and yields mojibake rather than failing, so without this an older
   * key whose random body happened to decode would produce a garbage
   * environment - and every token's audience would then be compared against it
   * and refused.
   */
  if (decoded.rfind("env_", 0) != 0) return {};
  return decoded;
}

}  // namespace

Result<std::shared_ptr<Client>> Client::Create(Options options) {
  Result<std::shared_ptr<Client>> result;

  if (options.publishable_key.empty()) {
    result.error = MakeError(
        ErrorKind::kConfiguration,
        "publishable_key is required. Find it in the Grantry dashboard under "
        "Configure -> API keys.");
    return result;
  }

  /*
   * ⚠️ THE CHECK THAT STOPS A FULL COMPROMISE SHIPPING.
   *
   * A secret key in a desktop binary is not a degraded configuration, it is the
   * whole environment handed to anybody who runs `strings` on the executable.
   * Refusing at construction means a developer who pastes the wrong key finds
   * out on their own machine, in the first second, rather than after release.
   */
  if (options.publishable_key.rfind("sk_", 0) == 0) {
    result.error = MakeError(
        ErrorKind::kConfiguration,
        "A secret key (sk_...) must never be used in a native application - anybody "
        "who runs the binary can read it. Use the publishable key (pk_...) instead, "
        "and keep the secret key on your own server.");
    return result;
  }

  if (options.publishable_key.rfind("pk_", 0) != 0) {
    result.error = MakeError(
        ErrorKind::kConfiguration,
        "publishable_key does not look like a Grantry publishable key; it should "
        "begin \"pk_\".");
    return result;
  }

  /*
   * ⚠️ THE ENVIRONMENT COMES OFF THE KEY, and is only asked for when it
   * cannot.
   *
   * A publishable key encodes the environment it names, so requiring both was
   * requiring the same fact twice - and the one way to get it wrong was silent
   * until the first verified read, which then failed as "signed for a different
   * environment". That reads like an attack rather than like a typo.
   *
   * The derived value wins over a supplied one deliberately: the key is what
   * actually authenticates, so if the two disagree it is the one telling the
   * truth about which environment this is.
   */
  const std::string derived = EnvironmentFromKey(options.publishable_key);
  if (!derived.empty()) {
    options.environment_id = derived;
  } else if (options.environment_id.empty()) {
    result.error = MakeError(
        ErrorKind::kConfiguration,
        "This publishable key does not carry its environment, so environment_id has "
        "to be set. Keys created before mid-2026 are like this; the one on your "
        "dashboard's API keys page is not, and needs no environment_id at all.");
    return result;
  }

  // Trailing slashes would produce `//v1/...`, which some proxies normalise and
  // others route to nothing.
  while (!options.api_base_url.empty() && options.api_base_url.back() == '/') {
    options.api_base_url.pop_back();
  }

  if (UrlHost(options.api_base_url).empty()) {
    result.error = MakeError(
        ErrorKind::kConfiguration,
        "api_base_url must be an absolute URL naming a host, with no user name or password "
        "in it - for example https://api.grantry.dev.");
    return result;
  }

  bool https = options.api_base_url.rfind("https://", 0) == 0;
  if (!https) {
    bool loopback = IsLoopback(options.api_base_url);
    if (!loopback || !options.allow_insecure_loopback) {
      result.error = MakeError(
          ErrorKind::kConfiguration,
          loopback ? "api_base_url is plain HTTP. Set allow_insecure_loopback if this "
                     "is a local development server."
                   : "api_base_url must be HTTPS. Session tokens and access tokens "
                     "travel over it.");
      return result;
    }
  }

  if (options.issuer.empty()) {
    result.error = MakeError(ErrorKind::kConfiguration, "issuer cannot be empty.");
    return result;
  }

  if (options.clock_skew_seconds < 0 || options.clock_skew_seconds > 300) {
    result.error = MakeError(
        ErrorKind::kConfiguration,
        "clock_skew_seconds must be between zero and 300. Access tokens live sixty "
        "seconds; a larger tolerance than their lifetime accepts tokens that have "
        "genuinely expired.");
    return result;
  }

  std::shared_ptr<SessionStore> store = options.session_store;
  if (!store) {
    store = std::shared_ptr<SessionStore>(
        MakeFileSessionStore(options.application_name.empty() ? "grantry"
                                                             : options.application_name)
            .release());
  }

  result.value = std::static_pointer_cast<Client>(
      std::make_shared<ClientImpl>(std::move(options), std::move(store)));
  return result;
}

/*
 * The project's version, from CMakeLists.txt's `project(... VERSION ...)`, so a
 * release bumps one number. The fallback is for a build that compiles these
 * sources without the CMake file; keep it equal to that line.
 */
#ifndef GRANTRY_VERSION
#define GRANTRY_VERSION "0.1.0"
#endif

const char* Version() { return GRANTRY_VERSION; }

}  // namespace grantry
