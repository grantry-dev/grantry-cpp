#include "internal.hpp"

#include <chrono>

namespace grantry {
namespace internal {
namespace {

const char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int DecodeChar(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '-') return 62;
  if (c == '_') return 63;
  return -1;
}

}  // namespace

std::string Base64UrlEncode(const std::vector<std::uint8_t>& bytes) {
  std::string out;
  out.reserve((bytes.size() + 2) / 3 * 4);

  std::size_t i = 0;
  while (i + 3 <= bytes.size()) {
    std::uint32_t block = (static_cast<std::uint32_t>(bytes[i]) << 16)
                        | (static_cast<std::uint32_t>(bytes[i + 1]) << 8)
                        | bytes[i + 2];
    out.push_back(kAlphabet[(block >> 18) & 0x3F]);
    out.push_back(kAlphabet[(block >> 12) & 0x3F]);
    out.push_back(kAlphabet[(block >> 6) & 0x3F]);
    out.push_back(kAlphabet[block & 0x3F]);
    i += 3;
  }

  // No `=` padding: base64url in a JWT is unpadded, and emitting padding here
  // would produce thumbprints that do not match the server's.
  std::size_t remaining = bytes.size() - i;
  if (remaining == 1) {
    std::uint32_t block = static_cast<std::uint32_t>(bytes[i]) << 16;
    out.push_back(kAlphabet[(block >> 18) & 0x3F]);
    out.push_back(kAlphabet[(block >> 12) & 0x3F]);
  } else if (remaining == 2) {
    std::uint32_t block = (static_cast<std::uint32_t>(bytes[i]) << 16)
                        | (static_cast<std::uint32_t>(bytes[i + 1]) << 8);
    out.push_back(kAlphabet[(block >> 18) & 0x3F]);
    out.push_back(kAlphabet[(block >> 12) & 0x3F]);
    out.push_back(kAlphabet[(block >> 6) & 0x3F]);
  }

  return out;
}

bool Base64UrlDecode(const std::string& text, std::vector<std::uint8_t>& out) {
  out.clear();
  if (text.empty()) return false;

  // A length of 1 mod 4 cannot be valid base64 at all.
  if (text.size() % 4 == 1) return false;

  std::uint32_t buffer = 0;
  int bits = 0;

  for (char c : text) {
    int value = DecodeChar(c);
    // ⚠️ NO TOLERANCE FOR `+`, `/`, `=` OR WHITESPACE. A decoder that accepts
    // them lets two different strings decode to the same bytes, which is a
    // signature-splicing primitive when the input is a JWT segment.
    if (value < 0) return false;

    buffer = (buffer << 6) | static_cast<std::uint32_t>(value);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<std::uint8_t>((buffer >> bits) & 0xFF));
    }
  }

  // Whatever is left must be zero padding bits. Anything else means the input
  // encoded more than it declared.
  if (bits >= 6) return false;
  if ((buffer & ((1u << bits) - 1)) != 0) return false;

  return true;
}

bool FixedTimeEquals(const std::string& a, const std::string& b) {
  // ⚠️ THE LENGTH IS COMPARED FIRST AND NOT IN CONSTANT TIME, which is correct:
  // a nonce's length is public — always 43 characters of base64url — so leaking
  // it costs nothing, and pretending otherwise means looping over an
  // attacker-influenced length.
  if (a.size() != b.size()) return false;

  unsigned char difference = 0;
  for (std::size_t i = 0; i < a.size(); i++) {
    difference |= static_cast<unsigned char>(a[i] ^ b[i]);
  }
  return difference == 0;
}

std::string RsaThumbprint(const std::string& n_b64url, const std::string& e_b64url) {
  // Required members only, in lexicographic order, no whitespace — RFC 7638.
  std::string canonical = "{\"e\":\"" + e_b64url + "\",\"kty\":\"RSA\",\"n\":\"" + n_b64url + "\"}";
  return Base64UrlEncode(Sha256(canonical));
}

std::int64_t UnixNow() {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

int AttemptsRemainingFrom(const Json& api_error) {
  std::optional<std::int64_t> left = api_error.GetInt("attempts_remaining");
  if (!left.has_value()) return -1;

  /*
   * ⚠️ AN UNSIGNED BODY CAN SAY ANYTHING, so the range is the check. A
   * negative count would have an application draw "you have -1 attempts left";
   * an enormous one would have it promise a thousand guesses at a six-digit
   * code. Neither is a number the server would ever send, so both mean the same
   * thing as silence.
   *
   * 100 rather than a tighter bound because the cap is a server-side policy the
   * SDK does not know — this rejects nonsense, it does not enforce the limit.
   */
  if (*left < 0 || *left > 100) return -1;
  return static_cast<int>(*left);
}

int BackupCodesRemainingFrom(const Json& document) {
  std::optional<std::int64_t> left = document.GetInt("backupCodesRemaining");
  if (!left.has_value()) return -1;

  // The server mints ten. Anything outside a sane range is a responder
  // inventing numbers, and it means what silence means.
  if (*left < 0 || *left > 100) return -1;
  return static_cast<int>(*left);
}

bool BackupCodeViewFrom(const Json& document, BackupCodeView& out) {
  const std::string status = document.GetString("status").value_or(std::string());

  if (status == "regenerate") {
    out.codes.clear();
    out.regenerate_required = true;
    return true;
  }

  const Json* entries = document.Find("backupCodes");
  if (status != "shown" || entries == nullptr || !entries->is_array()) return false;

  BackupCodeView view;
  for (const Json& entry : entries->array) {
    std::optional<std::string> code = entry.GetString("code");
    if (!code.has_value() || code->empty()) continue;

    BackupCode item;
    item.code = *code;
    // A JSON null — a code that still works — is not a string, so it reads as empty.
    item.used_at = entry.GetString("usedAt").value_or(std::string());
    view.codes.push_back(std::move(item));
  }

  out = std::move(view);
  return true;
}

std::string ProofBody(const Proof& proof) {
  std::map<std::string, std::string> body;
  body[proof.field()] = proof.value();
  return Json::Serialize(body);
}

bool PasswordUpdateFrom(const Json& document, PasswordUpdate& out) {
  if (document.GetString("status").value_or(std::string()) != "password_update_required") {
    return false;
  }

  const std::string token = document.GetString("token").value_or(std::string());
  if (token.empty()) return false;

  out.token = token;

  /*
   * ⚠️ THE LIST IS ABSENT AFTER A SECOND FACTOR, WHICH IS WHY ONLY THIS ONE
   * VALUE IS LIFTED OUT OF IT. The verdict is decided at sign-in and only a
   * boolean travels with the MFA challenge, so an application that rendered
   * `reasons` would state the requirements on one path and none on the other.
   * Everything else in the list is `Environment::password_policy` restated;
   * "breached" is the only member that is not.
   */
  for (const std::string& reason : document.GetStringArray("reasons")) {
    if (reason == "breached") out.breached = true;
  }
  return true;
}

}  // namespace internal
}  // namespace grantry
