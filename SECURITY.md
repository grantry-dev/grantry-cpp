# Native SDKs — what is actually defended, and what is not

This document is shared by the C# and C++ SDKs. Read it before either README.
It is deliberately blunt, because the most dangerous thing a native auth SDK can
ship with is a vague security claim that a customer builds a business on.

---

## The premise

A desktop application runs on hardware the attacker owns. They can read the
binary, patch it, attach a debugger, hook its imports, and point it at a server
they control. **No client-side check survives that.** Anybody claiming otherwise
is selling obfuscation and calling it security.

C# is the sharpest version of this problem. IL decompiles to near-original
source, and a one-byte patch turns `brfalse` into `brtrue`. Assume any `bool` your
application reads from this SDK can be `true` whenever the attacker wants it to
be.

So the SDK is not built to make that impossible. It is built so that **the things
worth protecting do not depend on it being impossible.**

---

## The one property everything rests on

> The server holds an RSA private key. The client holds only the public half.

Every guarantee below is a restatement of that. An attacker who can patch your
binary still cannot produce a signature, and so cannot produce an artefact that
anybody *else* will accept.

That is why the SDK's job is not to answer "is this user allowed?" — a question
whose answer is a branch — but to obtain **a signed statement from the server**
and hand it to you intact.

---

## What is defended

### A forged or altered response

The access token is an RS256 JWT. The SDK verifies the signature offline against
the JWKS published at `/v1/.well-known/jwks.json`, and checks the algorithm, the
`kid`, the issuer, the audience and the expiry.

**There is no "is this valid?" round trip, and that is on purpose.** An endpoint
that returns a boolean is an endpoint whose answer a patched client overwrites
with `true` and never calls again. A signature check is different in kind: the
attacker cannot satisfy it without the private key, no matter what they patch —
they can only skip it, which brings us to the section below on what that costs
them.

### A substituted variable or file

Signing used to stop at the access token, and that asymmetry was the largest
hole in this document. `GetIdentity` was a signed JWT nobody could forge;
`GetVariable` was bare JSON. So the obvious line an application wants to write —

```csharp
if (await client.GetVariableAsync("tier") is { Value: "pro" }) { … }
```

— was defeated with an interception proxy and no understanding of anything at
all: change `"free"` to `"pro"` in the response body, done.

**Every variable and file read made with a session now comes back with a signed
envelope**, minted with the same key as the access token and verified the same
way. The envelope binds four things, and each one closes a specific move:

| Claim | Without it |
| --- | --- |
| `aud` — the environment | Every environment on an instance shares one signing key, so a valid signature would say nothing about *which* application asked. An envelope minted for anybody else's app would verify here. |
| `sub` — the user | An envelope captured from one account would verify for another. This is what stops a free buyer replaying a colleague's paid read. |
| `nonce` | A recording made a second ago would still verify. See the next section. |
| `kind` + `key` | One valid envelope could be pasted onto every other variable's response, and the scheme would degrade to "some value, somewhere, was signed once". |

The value itself rides as a SHA-256 digest rather than in the clear, so the
envelope stays small and the plaintext does not travel twice.

**An absent signature is a failure, not a pass.** A signed-in caller that
receives an unsigned answer refuses it. Treating "no signature" as "nothing to
check" would make the whole defence removable by deleting a field, which is
precisely what a proxy is for. The one exception is an anonymous read: it can
only reach `anyone` content, which is published by definition and bound to no
user for a `sub` to name, so the server mints nothing and the SDK demands
nothing.

Files work the same way with one wrinkle: the bytes cannot go through a signer,
so the envelope binds the **checksum**. `Download` therefore fetches the signed
description first, verifies it, hashes what actually arrived and compares —
substituting the payload means producing a matching SHA-256, and substituting
the checksum means holding the signing key. That check used to be advice in the
sample code. Advice in a sample is advice; the merchant shipping an update their
application is about to execute is exactly the one who copies the download call
and not the hashing under it.

### A replayed response

Every token request carries 32 bytes of fresh randomness from the SDK. The
server echoes them into the token as the `nonce` claim, and the SDK refuses any
token that does not carry back exactly the nonce it just generated.

This is the claim that matters most for desktop software, and it is worth being
precise about why. Every *other* claim in the token is true of the session rather
than of the request — so a token captured from a real, paying user verifies
perfectly on any machine for its full sixty-second lifetime. Right signature,
right issuer, not expired. Without the nonce, "record one response from a real
subscriber and feed it to every cracked copy" works, and the signature check does
nothing to stop it.

With the nonce, a recording carries somebody else's random number and is
detectably not an answer to this request.

The same applies to a signed variable or file: 32 fresh bytes go out in
`x-grantry-nonce`, come back inside the envelope, and are compared. An envelope
that carries no nonce at all fails for the same reason one carrying the wrong
nonce does — the server ignores a malformed nonce rather than rejecting it,
because answering 400 would tell a prober exactly which check they tripped, so
the omission has to be the client's failure.

### A token minted for a different application

Every environment on a Grantry instance is signed by the same key, so a valid
signature says nothing about *which* application a token belongs to. The SDK
checks the `aud` claim against the environment its publishable key resolves to,
so a token lifted from another product on the same instance is rejected.

### A stolen session at rest

The long-lived session token is written through `ISessionStore` /
`grantry::SessionStore`. **What that buys you depends on the platform, and the
difference is not cosmetic:**

| Platform | At rest | What it stops |
|---|---|---|
| **Windows** | DPAPI, `CurrentUser` scope, with static entropy | Another local account cannot decrypt it, even holding the file |
| **macOS, Linux** | **Plaintext, in a `0600` file** | Only the file permission — another account is refused by the OS, but anything running *as that user* reads it directly |

There is no cross-platform DPAPI. The honest answers off Windows are the login
keychain and the Secret Service, and both need a dependency this SDK does not
take. So the default does the one thing it can do without one, and says so
rather than implying more.

**If a plaintext token on disk is not acceptable for your product, implement
`ISessionStore` / `grantry::SessionStore` over the platform keychain and pass it
in.** That is exactly why the interface exists.

### A signed-in user who has not paid

Plan locking is a server-side refusal, not a flag the client is trusted to obey.

When a merchant switches it on and the account holds none of the plans they
accept, sign-in **succeeds** — and the session it creates is restricted. The API
then refuses every call except three:

| Still works | Refused, `403 plan_required` |
|---|---|
| `Activate` / `ActivateAsync` — redeem a code | variables, files, relays |
| `GetIdentity` / `GetIdentityAsync` | profile edits, username, email changes |
| `SignOut` / `SignOutAsync` | session lists, device release, MFA enrolment |

**The session is created on purpose, and the reason is the point.** Refusing the
sign-in outright is the obvious implementation and it strands the one customer
who matters most: somebody who has just paid, holding a code, unable to redeem
it from inside the application they bought it for.

**Subscription-gated variables and files are covered by the same rule**, but
they answer differently: those routes accept anonymous callers by design, since
an `anyone` variable is public. A restricted session is treated there exactly as
a signed-out visitor is — it reads public content and nothing else — so a
withheld variable is indistinguishable from an absent one, which is the existing
behaviour and deliberate.

The verdict is stored on the session and re-decided on every token refresh, so
it costs one boolean per request and self-corrects within the sixty-second life
of an access token: a subscription that starts opens the application without a
sign-out, and one that lapses closes it without waiting for the session to
expire. Redeeming a code lifts it immediately rather than a minute later.

⚠️ **This is still not anti-piracy, and the reason has changed.** It used to be
worth little because a patched binary could ignore the `RequiresPlan` flag.
Now it can ignore the flag and open its own window — and reach nothing, because
the refusal is on the server. What a patched build *can* still do is whatever
your application already holds in its own bytes. That is the same limit as
everywhere else in this document, and the next section is what to do about it.

### More than one account signed in at once

Multi-session is a per-application setting and is **off by default**. Most
native applications should leave it off, and with it off the behaviour is the
one you already expect: signing in replaces whoever was signed in, and the
replaced session is **revoked** rather than merely forgotten.

That distinction is the security property. Forgetting the old session and
revoking it look identical from inside the application — the stored token was
overwritten either way — but an un-revoked session is a live credential for an
account the user believes they left, sitting in whatever your `ISessionStore`
wrote it to until it expires.

When a merchant switches it on:

| | |
|---|---|
| `GetAccounts` / `GetAccountsAsync` | the accounts signed in on this client, and which is active |
| `SwitchAccount` / `SwitchAccountAsync` | make another of them active |
| `SignOutOf` / `SignOutOfAsync` | leave **one** account, keeping the rest |
| `SignOut` / `SignOutAsync` | leave **every** account on this client |

**A background account's token is never in your process.** Only the active
session's token exists outside the database; the others exist as hashes. A
switch mints the target a fresh token and hands that over, so there is no window
in which your application holds a credential for an account it is not currently
acting as — and the token a switch moved away from is dead, not parked.

**`SignOut` leaves everything, and that is deliberate.** Somebody pressing a
sign-out button means they are no longer signed in. Leaving them signed in as
their other account is how a shared machine leaks one, so the plain call is the
safe reading and the per-account version has to be asked for by name. Do not
wire `SignOutOf` to a sign-out button.

**Read `MultiSession` / `multi_session`, not the account count.** With the
setting off the server refuses a switch outright, so a switcher rendered from
`accounts.size()` would appear the moment somebody happened to have two and then
fail when pressed.

⚠️ **Switching invalidates any identity you are holding.** The access token,
the entitlements and the user id all belong to the account that *was* active.
Call `GetIdentity` again before deciding anything on them — and, as everywhere
else in this document, decide it on your server.

### A hostile network

TLS is required. `http://` is refused outright unless the host is a loopback
address, which exists so `localhost` development works and for no other reason.
Certificate validation uses the operating system trust store.

**And the trust store is the problem, which is why both SDKs pin.** HTTPToolkit,
Fiddler and Charles all work the same way: install a root certificate on the
machine, and the application's own TLS becomes readable and editable. The user
owns that store, so an ordinary HTTPS client has no grounds to refuse. Pinning
does — the connection is accepted only if the server's certificate chains to a
key built into the SDK, and a proxy's certificate chains to the root it
installed instead.

It is on by default for `api.grantry.dev` and off for any other base URL, so
production is protected without anybody thinking about it and a staging host
still works. `PinCertificate` / `pin_certificate` overrides either way, and
`CertificatePins` / `certificate_pins` carries your own for a self-hosted
instance.

Three details worth stating rather than assuming:

- **The built-in pins are Let's Encrypt's four root keys** (ISRG Root X1 and X2,
  Root YR and Root YE), not the API certificate's own. That certificate renews
  with a new key, and a pin on it would brick every shipped build on somebody
  else's schedule, with no update able to reach them because the updater is
  behind the same pin. A root pin refuses a proxy just the same. What it gives up
  is a certificate for our name wrongly issued by Let's Encrypt itself, which
  needs control of our DNS.
- **The pin is on the public key, not the certificate**, so a re-issued root
  that keeps its key still matches, and the match is made anywhere in the chain.
- **Enforcement differs by platform, and the difference is real.** On Linux the
  handshake trusts those four roots and nothing else, so a proxied connection is
  refused before a single request byte leaves the process. On Windows (WinHTTP)
  and macOS (whose system libcurl also consults the keychain) the chain is
  checked after the handshake — which is why the client makes one credential-free
  probe before it sends anything worth intercepting. By the time a session token
  travels, a proxy has already been detected and every call refused. The .NET
  SDK checks during the handshake on every platform.

### A response body read out of a log

Variable payloads are additionally encrypted under a key derived from the
session token — HKDF-SHA256, salted per response, AES-256-GCM, bound to the
variable's name so a ciphertext cannot be moved onto another key's response.

**Be precise about what this buys**, because it is narrower than it looks. TLS
already encrypts the response, and a proxy watching the whole exchange sees the
session token go out in the request header, so it can derive the same key. What
this defeats is a capture of the *response alone*, and bodies sitting in a log,
a crash dump, a support bundle or a HAR file.

It is worth having anyway for one reason: pinning and the signature check are
both code in a binary the attacker can patch out. This still has to be
*reimplemented*.

The pattern it deliberately does not use is the common one — encrypt at rest,
ship the key inside the application, decrypt after fetching. That key is
identical in every copy, so one person extracts it once and every customer's
values are readable forever, with no way to rotate short of a new release. A key
derived from the session dies when the session is revoked.

---

## What is not defended, and cannot be

### A patched binary, on the attacker's own machine

They can delete the verification call. They can replace the embedded JWKS with
their own key and mint tokens that pass. They can `return true`. They can strip
the pin, skip the signature check on a variable, and hand their own plaintext to
the application.

Everything in the section above raises the cost of attacking **users who have
not been compromised** — the ones running your unmodified build behind a proxy
they installed. None of it constrains the person running the debugger.

**This is not a bug and it is not fixable in a client.** The mitigation is
architectural, and it is the next section.

### The secrecy of a value the application must read

The signature protects **integrity**, which is achievable: producing an envelope
that verifies requires the signing key, and nobody who runs your binary has it.
It does not protect **secrecy**, which is not achievable and never will be — the
value is in the process's memory by the time your code reads it, and the process
belongs to whoever launched it.

A product that claims otherwise is selling a feeling. If a value must not be
readable by the user, it must not reach their machine; see the next section.

### Anything the binary already contains

Assume every byte shipped is readable. The SDK holds no secret and asks you to
hold none:

- the **publishable key** is public by design — it ships in web bundles too, and
  it grants nothing on its own;
- there is **no secret key** in a native build, ever. The SDK refuses a key
  beginning `sk_` at construction rather than letting one reach production;
- the JWKS is public;
- the session token is the user's own credential, not yours.

If your application needs a value the user must not have — a signing key for
your own backend, a decryption key for paid content — **it cannot live in the
binary**, and no SDK can change that.

---

## How to build on this so the patch does not pay

The rule is one sentence:

> **Never let the client's answer be the last word on anything valuable.**

Three concrete shapes, in increasing order of how much they are worth:

**1. Gate a branch — worth nothing on its own.**

```csharp
if (identity.HasFeature("pro_export")) EnableExport();   // one byte to defeat
```

Fine for menus and upsells. Not a licence check.

Plan locking is the exception that proves the rule: it *looks* like this shape
from inside your code — you catch an exception and show a screen — but the
enforcement is not in your binary at all, so the byte is not there to flip. If
what you need is "this person may not use my application", switch that on rather
than writing this `if`.

**2. Gate a request to your own backend — worth a great deal.**

Send `identity.AccessToken` to your server and verify it there against the same
JWKS. Your server has no patched binary in it. This is the intended shape for
anything that touches your data:

```csharp
request.Headers.Authorization = new AuthenticationHeaderValue(
    "Bearer", identity.AccessToken);
```

**3. Gate the delivery of something the client does not have — worth the most.**

If the feature *is* data — a model, a level pack, a rendering pipeline — do not
ship it and unlock it. Fetch it, authenticated by the token above. A patched
binary that skips the check still does not have the bytes, because they were
never in the binary to unlock.

The honest summary: **the SDK's value is not that it says yes. It is that when it
says yes, it hands you something a server will believe.**

---

## Reporting

Security issues in either SDK go to security@grantry.dev, not to the issue
tracker.
