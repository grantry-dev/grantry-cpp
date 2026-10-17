// Redirect sign-in: the loopback listener, and the rules a redirect answer is read by
// (docs/hosted-sign-in.md §12 decision 3, RFC 8252 §7.3).
//
// ⚠️ 127.0.0.1, NEVER ANY OTHER INTERFACE. Bound to the loopback literal, so nothing
// off this machine can reach it, and named by that literal in the return address,
// the one shape the API admits for it. `localhost` is not used (RFC 8252 §8.3): a
// hosts file can point that name somewhere else.
//
// ⚠️ ONE ANSWER, THEN CLOSED. The request on /callback carrying this sign-in's state
// is the answer. Taking it closes the listening socket, and that request is answered
// once the exchange has decided what the page should say. Anything else that reaches
// the port while it waits is turned away and the wait goes on: another path gets a
// 404, and the callback path with another state gets a page saying so. Any page the
// person has open can reach the port, so a request that could end the wait would let
// such a page cancel the sign-in, and one that was believed could hand this process
// a code of its own choosing.
//
// ⚠️ SEVERAL CONNECTIONS AT ONCE, BECAUSE BROWSERS OPEN SPARE ONES. Chrome can
// connect a socket it never sends on, beside the one that carries the request. A
// listener that read the first connection to the end would sit on the idle one until
// it timed out, with the answer queued behind it. `select` watches them all, and the
// first complete request is the one looked at.

#include "internal.hpp"

// clang-format off
#ifdef _WIN32
// winsock2.h before anything that reaches windows.h; see tests/main.cpp.
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <cerrno>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
// clang-format on

#include <cctype>
#include <chrono>
#include <cstring>
#include <string>
#include <vector>

namespace grantry {
namespace internal {
namespace {

/// The one path answered. The API admits no other (lib/oauth-redirects.ts).
constexpr const char* kCallbackPath = "/callback";

/// A request head longer than this is not a browser coming back.
constexpr std::size_t kMaxHeadBytes = 16 * 1024;

/// How many connections may be open at once while waiting.
constexpr std::size_t kMaxConnections = 8;

/// How long one connection may take to deliver its request line and headers.
constexpr int kConnectionSeconds = 10;

/// How often the deadline and the cancel callback are looked at.
constexpr int kTickMilliseconds = 200;

#ifdef _WIN32
using Native = SOCKET;
const Native kInvalid = INVALID_SOCKET;
void CloseNative(Native s) { ::closesocket(s); }
/// Whether `select` can watch this socket. Always, on Windows: an fd_set there
/// is a list of handles rather than a bitmap indexed by them.
bool Selectable(Native) { return true; }
constexpr int kSendFlags = 0;
#else
using Native = int;
const Native kInvalid = -1;
void CloseNative(Native s) { ::close(s); }
/*
 * ⚠️ AN fd_set IS A BITMAP OF FD_SETSIZE BITS, AND FD_SET PAST IT WRITES OFF THE
 * END. A game or an editor with a thousand files and sockets open is ordinary,
 * and the listener's next descriptor is then 1024 or more: FD_SET on it was a
 * stack overwrite. Such a descriptor is refused instead — the listener reports
 * `listener_unavailable`, an accepted connection is dropped.
 */
bool Selectable(Native s) { return s >= 0 && s < FD_SETSIZE; }
/*
 * ⚠️ NO SIGPIPE. A browser that closes its tab before the answer is written
 * makes the next send() raise SIGPIPE, whose default action ends the process —
 * the application, because a tab was closed. MSG_NOSIGNAL on Linux; macOS has
 * no such flag and takes SO_NOSIGPIPE on the socket instead (see Accept).
 */
#ifdef MSG_NOSIGNAL
constexpr int kSendFlags = MSG_NOSIGNAL;
#else
constexpr int kSendFlags = 0;
#endif
#endif

/// Accept one connection, made ready for this file's sends. kInvalid when none.
Native Accept(Native server) {
  Native accepted = ::accept(server, nullptr, nullptr);
  if (accepted == kInvalid) return kInvalid;
  if (!Selectable(accepted)) {
    CloseNative(accepted);
    return kInvalid;
  }
#if defined(SO_NOSIGPIPE)
  int on = 1;
  ::setsockopt(accepted, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#endif
  return accepted;
}

Error RedirectError(const std::string& code, std::string message) {
  Error error;
  error.kind = ErrorKind::kRedirect;
  error.code = code;
  error.message = std::move(message);
  return error;
}

int FromHex(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

/// application/x-www-form-urlencoded: `+` is a space, `%XX` a byte.
std::string Decode(const std::string& text) {
  std::string out;
  out.reserve(text.size());
  for (std::size_t i = 0; i < text.size(); i++) {
    if (text[i] == '+') {
      out.push_back(' ');
    } else if (text[i] == '%' && i + 2 < text.size() && FromHex(text[i + 1]) >= 0
               && FromHex(text[i + 2]) >= 0) {
      out.push_back(static_cast<char>(FromHex(text[i + 1]) * 16 + FromHex(text[i + 2])));
      i += 2;
    } else {
      out.push_back(text[i]);
    }
  }
  return out;
}

std::string Escape(const std::string& text) {
  std::string out;
  for (char c : text) {
    switch (c) {
      case '&': out += "&amp;"; break;
      case '<': out += "&lt;"; break;
      case '>': out += "&gt;"; break;
      case '"': out += "&quot;"; break;
      case '\'': out += "&#39;"; break;
      default: out.push_back(c);
    }
  }
  return out;
}

// ⚠️ THE SAME PAGE, WORD FOR WORD, AS THE C# AND PYTHON SDKs SERVE. Somebody who uses
// two of a merchant's applications sees one sentence, and a support article can quote
// it. Only a request that is not this sign-in's answer sees it now: the answer itself is
// sent on to the sign-in host (`FinishedUrl`).
std::string Page(const std::string& title, const std::string& heading, const std::string& body) {
  return std::string("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
       + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
       + "<title>" + title + "</title><style>"
       + "body{margin:0;min-height:100vh;display:grid;place-items:center;"
       + "font:16px/1.5 system-ui,-apple-system,'Segoe UI',sans-serif;background:#fafafa;color:#18181b}"
       + "main{max-width:26rem;padding:2rem;text-align:center}"
       + "h1{margin:0 0 .5rem;font-size:1.25rem}p{margin:0;color:#52525b}"
       + "@media (prefers-color-scheme:dark){body{background:#09090b;color:#fafafa}p{color:#a1a1aa}}"
       + "</style></head><body><main><h1>" + heading + "</h1><p>" + body
       + "</p></main></body></html>";
}

/// One response, with `Connection: close`. A browser that went away is not an error.
void Write(Native s, int status, const std::string& reason, const std::string& body, bool html,
           const std::string& extra_headers = std::string()) {
  std::string reply = "HTTP/1.1 " + std::to_string(status) + " " + reason + "\r\n"
                    + extra_headers
                    + "Content-Type: " + (html ? "text/html" : "text/plain") + "; charset=utf-8\r\n"
                    + "Content-Length: " + std::to_string(body.size()) + "\r\n"
                    + "Cache-Control: no-store\r\n"
                    + "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; "
                      "frame-ancestors 'none'\r\n"
                    + "Referrer-Policy: no-referrer\r\n"
                    + "X-Content-Type-Options: nosniff\r\n"
                    + "Connection: close\r\n\r\n" + body;
  std::size_t sent = 0;
  while (sent < reply.size()) {
    int n = static_cast<int>(
        ::send(s, reply.data() + sent, static_cast<int>(reply.size() - sent), kSendFlags));
    if (n <= 0) return;
    sent += static_cast<std::size_t>(n);
  }
}

/// `GET /callback?code=... HTTP/1.1`, split. False for anything that is not a request
/// line in origin form.
bool RequestLine(const std::string& head, std::string& method, std::string& path,
                 std::string& query) {
  std::string line = head.substr(0, head.find("\r\n"));
  std::size_t first = line.find(' ');
  if (first == std::string::npos) return false;
  std::size_t second = line.find(' ', first + 1);
  if (second == std::string::npos || line.find(' ', second + 1) != std::string::npos) return false;
  if (line.compare(second + 1, 7, "HTTP/1.") != 0) return false;

  method = line.substr(0, first);
  std::string target = line.substr(first + 1, second - first - 1);
  if (target.empty() || target[0] != '/') return false;
  std::size_t question = target.find('?');
  path = target.substr(0, question);
  query = question == std::string::npos ? std::string() : target.substr(question + 1);
  return true;
}

struct Pending {
  Native socket;
  std::string head;
  std::chrono::steady_clock::time_point accepted;
};

}  // namespace

// ---------------------------------------------------------------------------
// The rules an answer is read by
// ---------------------------------------------------------------------------

std::string PkceChallenge(const std::string& verifier) {
  return Base64UrlEncode(Sha256(verifier));
}

bool SignInUrlOpenable(const std::string& url) {
  std::size_t scheme_end = url.find("://");
  if (scheme_end == std::string::npos) return false;
  std::string scheme = url.substr(0, scheme_end);
  std::string rest = url.substr(scheme_end + 3);
  std::string authority = rest.substr(0, rest.find_first_of("/?#"));
  if (authority.empty() || authority.find('@') != std::string::npos) return false;
  // Nothing a shell could take as an argument or a second command.
  for (char c : url) {
    if (static_cast<unsigned char>(c) <= 0x20 || c == '"' || c == '\'' || c == '`' || c == '\\') {
      return false;
    }
  }

  if (scheme == "https") return true;
  if (scheme != "http") return false;

  std::string host = authority;
  if (!host.empty() && host[0] == '[') {
    host = host.substr(0, host.find(']') + 1);
  } else {
    host = host.substr(0, host.find(':'));
  }
  for (char& c : host) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

  const std::string suffix = ".localhost";
  return host == "localhost" || host == "127.0.0.1" || host == "[::1]"
      || (host.size() > suffix.size()
          && host.compare(host.size() - suffix.size(), suffix.size(), suffix) == 0);
}

bool ParseQuery(const std::string& query, std::map<std::string, std::string>& out) {
  out.clear();
  std::size_t at = 0;
  while (at <= query.size()) {
    std::size_t end = query.find('&', at);
    if (end == std::string::npos) end = query.size();
    std::string pair = query.substr(at, end - at);
    at = end + 1;
    if (pair.empty()) continue;

    std::size_t equals = pair.find('=');
    std::string name = Decode(pair.substr(0, equals));
    std::string value = equals == std::string::npos ? std::string() : Decode(pair.substr(equals + 1));
    if (out.count(name) != 0) return false;
    out[name] = value;
  }
  return true;
}

Error CodeFromAnswer(const std::map<std::string, std::string>& answer,
                     const std::string& sign_in_url, std::string& code) {
  // RFC 9207, first, and on an error too: an answer naming another sign-in URL is a
  // mix-up, never a sign-in, and its error is not this environment's to report.
  auto issuer = answer.find("iss");
  if (issuer == answer.end() || issuer->second != sign_in_url) {
    return RedirectError("issuer_mismatch",
                         "That sign-in came back from somewhere other than the sign-in URL "
                         "it went to.");
  }

  auto error = answer.find("error");
  if (error != answer.end()) {
    // The hosted sign-in's own OAuth error, passed through, and only in the shape RFC
    // 6749 gives those codes.
    bool shaped = !error->second.empty() && error->second.size() <= 64;
    for (char c : error->second) {
      if (!((c >= 'a' && c <= 'z') || c == '_')) shaped = false;
    }
    return RedirectError(shaped ? error->second : "invalid_response", "Signing in did not finish.");
  }

  auto found = answer.find("code");
  if (found == answer.end() || found->second.empty() || found->second.size() > 200) {
    return RedirectError("invalid_response", "The sign-in came back with no code.");
  }

  code = found->second;
  return Error();
}

std::string FinishedUrl(const std::string& sign_in_url, bool signed_in) {
  std::string base = sign_in_url;
  while (!base.empty() && base.back() == '/') base.pop_back();
  return base + "/finished?outcome=" + (signed_in ? "signed_in" : "failed");
}

std::string NotThisSignInPage() {
  return Page("Not this sign-in", "Nothing to do here",
              "This address is waiting for a sign-in that did not come from this page. You can "
              "close this tab.");
}

// ---------------------------------------------------------------------------
// The listener
// ---------------------------------------------------------------------------

LoopbackListener::LoopbackListener()
    : listener_(static_cast<Socket>(kInvalid)), answer_(static_cast<Socket>(kInvalid)) {
#ifdef _WIN32
  WSADATA data;
  if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return;
  started_ = true;
#endif

  Native s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s == kInvalid) return;
  if (!Selectable(s)) {
    CloseNative(s);
    return;
  }

#ifdef _WIN32
  /*
   * ⚠️ ON WINDOWS A SECOND SOCKET CAN BIND A PORT THAT IS ALREADY BOUND, unless the
   * first says otherwise: SO_REUSEADDR there lets a process share the port and take
   * connections off it. Exclusive use closes that for the minutes this waits. POSIX
   * already refuses by default.
   */
  BOOL exclusive = TRUE;
  ::setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive),
               sizeof(exclusive));
#endif

  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;

#ifdef _WIN32
  int length = sizeof(address);
#else
  socklen_t length = sizeof(address);
#endif
  if (::bind(s, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0
      || ::listen(s, static_cast<int>(kMaxConnections)) != 0
      || ::getsockname(s, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
    CloseNative(s);
    return;
  }

  listener_ = static_cast<Socket>(s);
  port_ = ntohs(address.sin_port);
}

LoopbackListener::~LoopbackListener() {
  CloseListener();
  if (static_cast<Native>(answer_) != kInvalid) CloseNative(static_cast<Native>(answer_));
#ifdef _WIN32
  if (started_) WSACleanup();
#endif
}

void LoopbackListener::CloseListener() {
  if (static_cast<Native>(listener_) != kInvalid) {
    CloseNative(static_cast<Native>(listener_));
    listener_ = static_cast<Socket>(kInvalid);
  }
}

bool LoopbackListener::listening() const { return static_cast<Native>(listener_) != kInvalid; }

std::string LoopbackListener::address() const {
  if (!listening()) return std::string();
  sockaddr_in address{};
#ifdef _WIN32
  int length = sizeof(address);
#else
  socklen_t length = sizeof(address);
#endif
  if (::getsockname(static_cast<Native>(listener_), reinterpret_cast<sockaddr*>(&address),
                    &length) != 0) {
    return std::string();
  }
  char text[INET_ADDRSTRLEN] = {0};
  if (::inet_ntop(AF_INET, &address.sin_addr, text, sizeof(text)) == nullptr) return std::string();
  return text;
}

std::string LoopbackListener::redirect_uri() const {
  return "http://127.0.0.1:" + std::to_string(static_cast<int>(port_)) + kCallbackPath;
}

LoopbackListener::Outcome LoopbackListener::Wait(const std::string& state, int timeout_seconds,
                                                 const std::function<bool()>& cancelled,
                                                 std::map<std::string, std::string>& answer) {
  using Clock = std::chrono::steady_clock;
  if (!listening()) return Outcome::kFailed;

  const Native server = static_cast<Native>(listener_);
  const Clock::time_point deadline = Clock::now() + std::chrono::seconds(timeout_seconds);
  std::vector<Pending> pending;

  auto finish = [&](Outcome outcome) {
    for (const Pending& connection : pending) CloseNative(connection.socket);
    pending.clear();
    CloseListener();
    return outcome;
  };

  while (true) {
    if (cancelled && cancelled()) return finish(Outcome::kCancelled);
    const Clock::time_point now = Clock::now();
    if (now >= deadline) return finish(Outcome::kTimedOut);

    // A connection that has not delivered a request in time gives its place back.
    for (std::size_t i = pending.size(); i-- > 0;) {
      if (now - pending[i].accepted > std::chrono::seconds(kConnectionSeconds)) {
        CloseNative(pending[i].socket);
        pending.erase(pending.begin() + static_cast<std::ptrdiff_t>(i));
      }
    }

    fd_set readable;
    FD_ZERO(&readable);
    FD_SET(server, &readable);
    Native highest = server;
    for (const Pending& connection : pending) {
      FD_SET(connection.socket, &readable);
      if (connection.socket > highest) highest = connection.socket;
    }

    const auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
    const long long tick = remaining < kTickMilliseconds ? remaining : kTickMilliseconds;
    timeval timeout{};
    timeout.tv_sec = static_cast<long>(tick / 1000);
    timeout.tv_usec = static_cast<long>((tick % 1000) * 1000);

#ifdef _WIN32
    int ready = ::select(0, &readable, nullptr, nullptr, &timeout);
#else
    int ready = ::select(static_cast<int>(highest) + 1, &readable, nullptr, nullptr, &timeout);
    if (ready < 0 && errno == EINTR) continue;
#endif
    (void)highest;
    if (ready < 0) return finish(Outcome::kFailed);
    if (ready == 0) continue;

    if (FD_ISSET(server, &readable)) {
      Native accepted = Accept(server);
      if (accepted != kInvalid) {
        if (pending.size() >= kMaxConnections) {
          CloseNative(accepted);
        } else {
          pending.push_back(Pending{accepted, std::string(), Clock::now()});
        }
      }
    }

    for (std::size_t i = pending.size(); i-- > 0;) {
      Pending& connection = pending[i];
      if (!FD_ISSET(connection.socket, &readable)) continue;

      auto drop = [&]() {
        CloseNative(connection.socket);
        pending.erase(pending.begin() + static_cast<std::ptrdiff_t>(i));
      };

      char chunk[4096];
      int n = static_cast<int>(::recv(connection.socket, chunk, static_cast<int>(sizeof(chunk)), 0));
      if (n <= 0) {
        drop();
        continue;
      }
      connection.head.append(chunk, static_cast<std::size_t>(n));
      if (connection.head.size() > kMaxHeadBytes) {
        drop();
        continue;
      }
      std::size_t end = connection.head.find("\r\n\r\n");
      if (end == std::string::npos) continue;

      std::string method;
      std::string path;
      std::string query;
      if (!RequestLine(connection.head.substr(0, end), method, path, query)) {
        drop();
        continue;
      }
      if (path != kCallbackPath) {
        Write(connection.socket, 404, "Not Found", "Not found.", false);
        drop();
        continue;
      }
      if (method != "GET") {
        Write(connection.socket, 405, "Method Not Allowed", "Not allowed.", false);
        drop();
        continue;
      }

      /*
       * ⚠️ THE STATE DECIDES WHICH REQUEST IS THE ANSWER, compared without leaking
       * where it differs. A missing state, a repeated one and a wrong one are all "not
       * this sign-in": turned away, and the wait goes on.
       */
      std::map<std::string, std::string> parameters;
      auto presented = parameters.end();
      if (ParseQuery(query, parameters)) presented = parameters.find("state");
      if (presented == parameters.end() || !FixedTimeEquals(presented->second, state)) {
        Write(connection.socket, 400, "Bad Request", NotThisSignInPage(), true);
        drop();
        continue;
      }

      // This sign-in's answer. Nothing else is let in from here on.
      answer_ = static_cast<Socket>(connection.socket);
      pending.erase(pending.begin() + static_cast<std::ptrdiff_t>(i));
      answer = std::move(parameters);
      return finish(Outcome::kAnswered);
    }
  }
}

void LoopbackListener::Redirect(const std::string& location) {
  const Native s = static_cast<Native>(answer_);
  if (s == kInvalid) return;
  /*
   * ⚠️ 303, AND NO REFERRER. See Other makes the browser's next request a plain GET of the
   * hosted page; `no-referrer` (which `Write` sends) keeps this address — it carried the
   * code — out of that request. The body is for a client that does not follow, which no
   * browser is.
   */
  const std::string body = "<!doctype html><a href=\"" + Escape(location) + "\">Continue</a>";
  Write(s, 303, "See Other", body, true, "Location: " + location + "\r\n");
  CloseNative(s);
  answer_ = static_cast<Socket>(kInvalid);
}

}  // namespace internal
}  // namespace grantry
