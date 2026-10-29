// The C++ SDK's conformance driver: one operation per process, one JSON line out.
//
// The harness in `apps/api/conformance` runs the same scripts through this, the C# driver and the
// Python one, against one real API, and asserts all three answer alike. One process
// per step on purpose: the SDK keeps a sixty-second token, and a fresh process is the only honest
// way to make it ask `/v1/client/token` again, which is where a retired build is caught.
//
// Every outcome is data. The driver exits 0 whether the API admitted or refused, and exits 2 only
// when the driver itself broke.

#include <grantry/grantry.hpp>

#include <cstdio>
#include <map>
#include <string>
#include <vector>

namespace {

std::string Quote(const std::string& text) {
  std::string out = "\"";
  for (char c : text) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          char buffer[8];
          std::snprintf(buffer, sizeof(buffer), "\\u%04x", c);
          out += buffer;
        } else {
          out += c;
        }
    }
  }
  return out + "\"";
}

const char* KindName(grantry::ErrorKind kind) {
  switch (kind) {
    case grantry::ErrorKind::kPlanRequired: return "plan_required";
    case grantry::ErrorKind::kMaintenance: return "maintenance";
    case grantry::ErrorKind::kNotSignedIn: return "not_signed_in";
    case grantry::ErrorKind::kApi: return "api";
    case grantry::ErrorKind::kTransport: return "transport";
    case grantry::ErrorKind::kVerification: return "verification";
    case grantry::ErrorKind::kConfiguration: return "configuration";
    case grantry::ErrorKind::kInvalidArgument: return "invalid_argument";
    case grantry::ErrorKind::kRedirect: return "redirect";
    default: return "other";
  }
}

std::string Refused(const grantry::Error& error) {
  return std::string("{\"ok\":false,\"kind\":") + Quote(KindName(error.kind)) +
         ",\"code\":" + (error.code.empty() ? std::string("null") : Quote(error.code)) +
         ",\"status\":" + std::to_string(error.status) +
         ",\"message\":" + Quote(error.message) + "}";
}

std::string Run(grantry::Client& client, const std::string& op, const std::vector<std::string>& a) {
  if (op == "sign-in") {
    auto result = client.SignIn(a.at(0), a.at(1));
    if (!result.ok()) return Refused(result.error);
    return std::string("{\"ok\":true,\"requiresPlan\":") + (result->requires_plan ? "true" : "false") +
           ",\"planMessage\":" +
           (result->plan_message.empty() ? std::string("null") : Quote(result->plan_message)) + "}";
  }
  if (op == "restore") {
    auto result = client.Restore();
    if (!result.ok()) return Refused(result.error);
    return std::string("{\"ok\":true,\"restored\":") + (*result ? "true" : "false") + "}";
  }
  if (op == "sso") {
    // A sign-in, so no session to restore: the URL is for the system browser.
    auto result = client.StartSso(a.at(0), a.at(1), a.size() > 2 ? a.at(2) : std::string());
    if (!result.ok()) return Refused(result.error);
    return "{\"ok\":true,\"url\":" + Quote(*result) + "}";
  }
  if (op == "redirect") {
    // The harness is the browser. It reads this line, answers the authorize URL as the hosted
    // screens would for somebody signed in, and follows the redirect to the listener.
    grantry::RedirectOptions redirect;
    redirect.timeout_seconds = 60;
    redirect.open_browser = [](const std::string& url) {
      std::printf("{\"browse\":%s}\n", Quote(url).c_str());
      std::fflush(stdout);
      return true;
    };
    auto result = client.SignInWithRedirect(redirect);
    if (!result.ok()) return Refused(result.error);
    auto identity = client.GetIdentity();
    if (!identity.ok()) return Refused(identity.error);
    return std::string("{\"ok\":true,\"signedIn\":true,\"subject\":") + Quote(identity->user_id()) +
           ",\"requiresPlan\":" + (result->requires_plan ? "true" : "false") + "}";
  }

  // Everything below acts for a session a previous process left in the store.
  auto restored = client.Restore();
  if (!restored.ok()) return Refused(restored.error);

  if (op == "identity") {
    auto result = client.GetIdentity();
    if (!result.ok()) return Refused(result.error);
    return std::string("{\"ok\":true,\"subject\":") + Quote(result->user_id()) + ",\"plan\":" +
           (result->plan_key().has_value() ? Quote(*result->plan_key()) : std::string("null")) + "}";
  }
  if (op == "devices") {
    auto result = client.GetDevices();
    if (!result.ok()) return Refused(result.error);
    std::string out = "{\"ok\":true,\"devices\":[";
    bool first = true;
    for (const auto& device : *result) {
      if (!first) out += ",";
      first = false;
      out += "{\"id\":" + Quote(device.id) + ",\"label\":" + Quote(device.label) +
             ",\"platform\":" + Quote(device.platform) + "}";
    }
    return out + "]}";
  }
  if (op == "release") {
    auto status = client.ReleaseDevice(a.at(0));
    if (!status.ok()) return Refused(status.error);
    return "{\"ok\":true}";
  }
  if (op == "variable") {
    auto result = client.GetVariable(a.at(0));
    if (result.error) return Refused(result.error);
    // Neither a value nor an error is the SDK's "not there, or not for you" — a 404 it
    // deliberately does not propagate — and the other SDKs' null.
    if (!result.value.has_value()) return "{\"ok\":true,\"value\":null}";
    return "{\"ok\":true,\"value\":" + Quote(result->value) + "}";
  }
  if (op == "activate") {
    auto status = client.Activate(a.at(0));
    if (!status.ok()) return Refused(status.error);
    return "{\"ok\":true}";
  }
  if (op == "sign-out") {
    auto status = client.SignOut();
    if (!status.ok()) return Refused(status.error);
    return "{\"ok\":true}";
  }
  return std::string();
}

}  // namespace

int main(int argc, char** argv) {
  std::map<std::string, std::string> options;
  std::vector<std::string> rest;
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg.rfind("--", 0) == 0 && i + 1 < argc) {
      options[arg.substr(2)] = argv[++i];
    } else {
      rest.push_back(arg);
    }
  }
  if (rest.empty()) {
    std::fprintf(stderr, "usage: driver --api URL --key PK --issuer ISS --session FILE <op> [args]\n");
    return 2;
  }

  grantry::Options settings;
  settings.publishable_key = options["key"];
  settings.api_base_url = options["api"];
  settings.issuer = options["issuer"];
  settings.application_name = "grantry-conformance";
  settings.session_store = grantry::MakeFileSessionStoreAt(options["session"]);
  settings.allow_insecure_loopback = true;
  settings.pin_certificate = false;
  settings.connect_on_start = false;

  auto created = grantry::Client::Create(settings);
  if (!created.ok()) {
    std::printf("%s\n", Refused(created.error).c_str());
    return 0;
  }

  std::vector<std::string> args(rest.begin() + 1, rest.end());
  std::string out = Run(**created, rest[0], args);
  if (out.empty()) {
    std::fprintf(stderr, "unknown op %s\n", rest[0].c_str());
    return 2;
  }
  std::printf("%s\n", out.c_str());
  return 0;
}
