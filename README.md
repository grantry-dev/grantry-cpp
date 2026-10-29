# grantry-cpp

Identity, access and entitlements for C++ desktop applications.

**Read [`SECURITY.md`](SECURITY.md) before you build anything on this.**
It is short, and it decides how you should use every method below.

```
C++17 · Windows, macOS, Linux
```

---

## No third-party dependencies on Windows

A desktop SDK that drags in libcurl and OpenSSL is one a games studio cannot
ship: every shared library is another thing to reconcile against whatever the
engine already loaded, another CVE to chase, and another DLL to put beside the
executable. So the transport and the cryptography come from the platform:

| | Transport | Crypto | Session at rest |
|---|---|---|---|
| **Windows** | WinHTTP (Schannel, system trust store) | BCrypt / CNG | DPAPI |
| **POSIX** | libcurl | OpenSSL | `0600` file — see below |

On Windows that is **zero** external dependencies. On Linux both are the system
libraries already there; on macOS libcurl is, and OpenSSL comes from Homebrew or
vcpkg (see Build).

The JSON parser is hand-written for the same reason. It parses exactly what this
library consumes and refuses everything else, with a depth limit — every input
it sees arrives from the network, and a few kilobytes of `[` is the shortest
denial of service against a recursive-descent parser there is.

---

## Build

Requires CMake 3.16 and a C++17 compiler: Visual Studio 2019 or later, GCC 8,
Clang 7 or Apple Clang 11. On POSIX, the libcurl and OpenSSL (1.1.1 or 3.x)
development packages — `libcurl4-openssl-dev libssl-dev` on Debian and Ubuntu.
macOS has libcurl but no OpenSSL headers, so point CMake at Homebrew's:
`-DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)`.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release
```

The tests are built only when this is the top-level project
(`-DGRANTRY_BUILD_TESTS=ON` forces them).

Then link it, either vendored:

```cmake
add_subdirectory(path/to/grantry-cpp)
target_link_libraries(your_app PRIVATE grantry::grantry)
```

or installed, as a CMake package:

```bash
cmake --install build --prefix /opt/grantry
```

```cmake
find_package(grantry 0.2 CONFIG REQUIRED)   # -DCMAKE_PREFIX_PATH=/opt/grantry
target_link_libraries(your_app PRIVATE grantry::grantry)
```

It is a static library. On POSIX the package finds libcurl and OpenSSL for
you, because whatever links a static library links what it depends on too.

---

## Use

```cpp
#include <grantry/grantry.hpp>

grantry::Options options;
options.publishable_key  = "pk_live_…";   // public by design
options.api_base_url     = "https://api.grantry.dev";
options.application_name = "Photon Editor";

auto created = grantry::Client::Create(options);
if (!created.ok()) { /* created.error.message */ }
std::shared_ptr<grantry::Client> grantry_client = *created;

// Returning users: no sign-in screen at all.
auto restored = grantry_client->Restore();
if (!restored.ok() || !*restored) {
  auto signed_in = grantry_client->SignIn(email, password);
  if (!signed_in.ok()) { /* signed_in.error.message */ }

  // ⚠️ TWO OF THE THREE SUCCESSES ARE NOT A SESSION, and neither is an error.
  //    Check both before you draw your main window; SubmitMfa can answer with
  //    the second one too.
  else if (!signed_in->mfa_challenge.empty()) {
    // A second screen. SubmitMfa(challenge, code).
  } else if (!signed_in->password_reset_token.empty()) {
    // The password was CORRECT and no longer meets the policy — HTTP 202, not
    // 401. ResetPassword(token, chosen), then back to the sign-in screen.
  }
}

auto identity = grantry_client->GetIdentity();
if (!identity.ok()) { /* see below */ }
```

### Errors, not exceptions

Games and audio applications routinely build with `-fno-exceptions`, and a
library that cannot be linked into one is a library those projects cannot use at
all. Everything returns `Result<T>` or `Status`.

```cpp
if (identity.error.kind == grantry::ErrorKind::kVerification) {
  // ⚠️ Treat as an attack until proven otherwise. It does not mean the
  //    credentials were wrong — that is kApi with status 401.
  //    identity.error.verification says which check failed.
}
```

For a refusal, switch on `error.code` — the API's own name for it — rather than
on `error.message`, which is unsigned text:

```cpp
auto signed_in = client->SignIn(email, password);
if (signed_in.error.code == "device_limit_reached") {
  // "Release a device from your account page, or contact support."
} else if (signed_in.error.code == "application_unrecognised") {
  // "This copy is out of date. Download the latest version."
}
```

`device_limit_reached`, `device_required` and `application_unrecognised` are all
`kApi` with status 403, so the code is the only thing that tells them apart.
Plan-locked and maintenance refusals have kinds of their own.

### Or sign in through the browser

`SignInWithRedirect` sends the person to your environment's hosted sign-in in
their own browser, and brings them back signed in. The second factor, social
providers and their password manager are all handled there, and your application
never sees a password. It blocks until they come back, so call it from a worker
thread.

```cpp
std::atomic<bool> cancel_pressed{false};   // set from a Cancel button

grantry::RedirectOptions redirect;
redirect.cancelled = [&] { return cancel_pressed.load(); };

auto result = client->SignInWithRedirect(redirect);
if (result.error.kind == grantry::ErrorKind::kRedirect) {
  // result.error.code: "timeout" (a closed browser looks exactly like this),
  // "cancelled", "access_denied", ...
} else if (result.ok() && result->requires_plan) {
  // Your activate-a-code screen.
}
```

It is RFC 8252's shape. A listener opens on `127.0.0.1`, on a port the system
picks. The browser carries a PKCE challenge (S256) and a random state, and the
listener takes one answer, then closes. Only a request carrying this sign-in's
state is taken, so a page that finds the port can neither end the wait nor hand
you a code. The session goes through `SignIn`'s own path, so it is stored and
proved exactly as a password sign-in's is. The browser is then sent on to the
sign-in host's own `/finished` card, in the environment's theme, telling the person
to return to your application.

⚠️ **A closed browser cannot be seen from here.** The call waits out
`timeout_seconds`, ten minutes by default, so give the person a Cancel button.
Once the code reaches the API, a refusal is `kApi` as at any sign-in.

On Windows the browser is opened with `ShellExecute`, on macOS with `open` and
elsewhere with `xdg-open`; `RedirectOptions::open_browser` replaces it. The
listener is the one socket the library opens itself, which is why it links
`ws2_32`.

### Then use it in one of three ways

**1. Gate a menu — worth nothing on its own.**

```cpp
export_button.SetVisible(identity->has_feature("pro_export"));
```

One instruction in a patched binary. Fine for showing and hiding; never a
licence check.

**2. Gate a call to your own backend — worth a great deal.**

```cpp
headers["Authorization"] = "Bearer " + identity->access_token();
```

Your server verifies the same token against
`https://api.grantry.dev/v1/.well-known/jwks.json`, and your server has no
patched binary in it.

**3. Gate the delivery of something the client does not have — worth the most.**

If the paid feature *is* data, fetch it with the token above rather than
shipping it and unlocking it.

---

## What it verifies, on every token

Offline, with no "is this valid?" round trip — because an endpoint that returns
a boolean is an endpoint a patched client overwrites and never calls again.

| Check | What it stops |
|---|---|
| RS256 signature against the cached JWKS | A forged or altered response |
| Algorithm fixed in code, never read from the token | `alg: none`, and HMAC keyed with the public key |
| `nonce` echoed from 32 fresh CSPRNG bytes | **A replayed response** |
| `aud` against this environment | A token minted for another application on the same instance |
| `iss` against a configured constant | A token from another issuer |
| `exp` / `nbf` with bounded skew | An expired token |
| 2048-bit minimum modulus | A downgraded signing key |
| Optional pinning by RFC 7638 thumbprint | A swapped signing key |
| Signed envelope on every variable and file read | **A substituted value** — see below |
| Certificate pinning on the SPKI, on by default for the real API | **An interception proxy** — HTTPToolkit, Fiddler, Charles |
| AES-256-GCM payload encryption under a per-session key | A response body read out of a log, a crash dump or a HAR file |


### Why the signed envelope matters

Signing used to stop at the access token, and that asymmetry was the largest
hole in this SDK. `GetIdentity` was a JWT nobody could forge; `GetVariable` was
bare JSON. So the obvious line an application wants to write was defeated with a
proxy and no understanding of anything at all: change `"free"` to `"pro"` in the
response body, done.

Every read made with a session now carries a signature binding the value to this
key, this user, this application and this exact request. **An answer that
arrives unsigned is refused**, because treating "no signature" as "nothing to
check" would make the defence removable by deleting a field — which is precisely
what a proxy is for.

For files the envelope binds the **checksum**, since the bytes cannot go through
a signer. `Download` fetches the signed description, hashes what arrived and
compares, so verifying a download is no longer advice a merchant has to remember
to follow.

**Verified is not secret.** Whoever runs the binary can still read a value out
of its memory once the check has passed — no SDK can change that. What they
cannot do is substitute one.

Every other claim in an access token describes the **session**, not the request
— so a token captured from a paying subscriber verifies perfectly on any machine
for its full sixty seconds. The nonce is the only thing that says "minted in
answer to *this* request", which is why it is generated immediately before each
call and never reused.

---

## Entitlements

```cpp
identity->plan_key();                       // "pro", or empty on no plan
identity->has_feature("pro_export");        // granted by the user's plan
```

`plan_key` and `features` come from the signed `pln` and `fea` claims.

⚠️ **There is no `try_get_limit`, and its absence is deliberate.** Numeric plan
limits were removed from Grantry because nothing counted consumption against
them — the SDK could report a ceiling of 500 while neither it nor the server
knew whether four or four thousand had been used. An accessor that looks
enforcing and is advisory is worse than no accessor, so it went with the
feature.

Limits will return when they can be counted properly. Until then, count what
you meter in your own database, where you already know the numbers.

### Hearing about a plan change

A plan bought in the browser, a renewal that failed, a licence redeemed on
another machine: `WatchPlans` long-polls the API and calls you back once the
client has minted afresh, so `requires_plan()` and `GetIdentity()` already agree
with the change.

```cpp
std::weak_ptr<grantry::Client> weak = client;   // never capture the shared_ptr
client->WatchPlans([weak] {
  // On the SDK's thread: marshal to your UI thread before touching a window.
  post_to_ui([weak] {
    if (auto c = weak.lock()) show_screen_for(c->requires_plan());
  });
});
// ...
client->StopWatchingPlans();   // returns at once; see the header for the rest
```

⚠️ **Capture the client weakly.** The watch keeps the callback until it is
stopped, and releasing the client is what stops it — a callback holding a
`shared_ptr` keeps both alive forever. A poll already in flight when you stop
finishes on its own (twelve seconds normally, forty at most), so a DLL that can
be unloaded must stop the watch well before it is.

---

## Sessions

Stored through `grantry::SessionStore`. The default encrypts with DPAPI on
Windows; **on macOS and Linux it is a `0600` file and nothing more**, because
the right answers there are the login keychain and the Secret Service and both
need a dependency this library deliberately does not take. Implement the
interface yourself if that matters to your product — it exists for exactly that.

---

## Configuration that is refused

`Client::Create` returns `kConfiguration` rather than letting these ship:

- **a key beginning `sk_`** — a secret key in a desktop binary is the whole
  environment handed to anybody who runs `strings` on the executable;
- **plain HTTP to a real host** — there is no option to disable TLS, only one
  that permits loopback for local development;
- **a clock skew wider than a token's lifetime**.

---

## Tests

```bash
./build/grantry_tests
```

No test framework — one more dependency for a library whose whole argument is
that it has none. The suite plays the attacker: swapped signing keys, replayed
responses, `alg: none`, tokens HMAC'd with the public key, tokens minted for a
different environment, malformed base64, and a flood of forged key ids to prove
the JWKS refresh floor holds.

---

## Construction is the connection

Building a client reaches the API once, in the background: a single `GET` of
the public environment route. Nothing else in the SDK reads the answer.

It exists so a merchant's dashboard can see the application. A web application
announces itself the moment it loads, because its provider fetches the
environment on mount; a native one had no such moment — nothing left the
process until somebody typed a password, which could be days after the SDK was
wired up. Their setup guide sat on "watching for connection" the whole time.

⚠️ **It never blocks start-up, never reports a failure and never retries.** An
application that starts on a train must still start, and a server that is down
must not turn into a reconnect loop nobody asked for.

`Create` does not block on it and the destructor waits for it, so a client is
never torn down with a request still reading its memory. Turn it off with
`options.connect_on_start = false`.
