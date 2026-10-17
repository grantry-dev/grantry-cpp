#include "internal.hpp"

#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace grantry {
namespace internal {
namespace {

/// A recursive-descent parser over a bounded, non-recursive-by-design input.
///
/// ⚠️ THE DEPTH LIMIT IS THE POINT OF THIS CLASS. Every input this library
/// parses arrives from the network, and the shortest denial of service against
/// a recursive-descent parser is `[[[[[[[…` — a few kilobytes that blow the
/// stack. The documents we actually consume nest three or four deep, so
/// thirty-two is generous and still nowhere near a crash.
class Parser {
 public:
  explicit Parser(const std::string& text) : text_(text) {}

  bool Parse(Json& out) {
    SkipWhitespace();
    if (!ParseValue(out, 0)) return false;
    SkipWhitespace();
    // Trailing content means the document was not what it claimed to be.
    return position_ == text_.size();
  }

 private:
  static constexpr int kMaxDepth = 32;

  const std::string& text_;
  std::size_t position_ = 0;

  bool Eof() const { return position_ >= text_.size(); }
  char Peek() const { return text_[position_]; }

  void SkipWhitespace() {
    while (!Eof()) {
      char c = Peek();
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
        position_++;
      } else {
        break;
      }
    }
  }

  bool Literal(const char* word) {
    std::size_t length = 0;
    while (word[length] != '\0') length++;
    if (text_.compare(position_, length, word) != 0) return false;
    position_ += length;
    return true;
  }

  bool ParseValue(Json& out, int depth) {
    if (depth > kMaxDepth) return false;
    if (Eof()) return false;

    switch (Peek()) {
      case '{': return ParseObject(out, depth);
      case '[': return ParseArray(out, depth);
      case '"': {
        out.type = Json::Type::kString;
        return ParseString(out.string);
      }
      case 't':
        if (!Literal("true")) return false;
        out.type = Json::Type::kBool;
        out.boolean = true;
        return true;
      case 'f':
        if (!Literal("false")) return false;
        out.type = Json::Type::kBool;
        out.boolean = false;
        return true;
      case 'n':
        if (!Literal("null")) return false;
        out.type = Json::Type::kNull;
        return true;
      default: return ParseNumber(out);
    }
  }

  bool ParseObject(Json& out, int depth) {
    out.type = Json::Type::kObject;
    position_++;  // '{'
    SkipWhitespace();

    if (!Eof() && Peek() == '}') {
      position_++;
      return true;
    }

    while (true) {
      SkipWhitespace();
      if (Eof() || Peek() != '"') return false;

      std::string key;
      if (!ParseString(key)) return false;

      SkipWhitespace();
      if (Eof() || Peek() != ':') return false;
      position_++;

      SkipWhitespace();
      Json value;
      if (!ParseValue(value, depth + 1)) return false;
      out.object[key] = std::move(value);

      SkipWhitespace();
      if (Eof()) return false;
      if (Peek() == ',') {
        position_++;
        continue;
      }
      if (Peek() == '}') {
        position_++;
        return true;
      }
      return false;
    }
  }

  bool ParseArray(Json& out, int depth) {
    out.type = Json::Type::kArray;
    position_++;  // '['
    SkipWhitespace();

    if (!Eof() && Peek() == ']') {
      position_++;
      return true;
    }

    while (true) {
      SkipWhitespace();
      Json value;
      if (!ParseValue(value, depth + 1)) return false;
      out.array.push_back(std::move(value));

      SkipWhitespace();
      if (Eof()) return false;
      if (Peek() == ',') {
        position_++;
        continue;
      }
      if (Peek() == ']') {
        position_++;
        return true;
      }
      return false;
    }
  }

  bool ParseString(std::string& out) {
    if (Eof() || Peek() != '"') return false;
    position_++;

    out.clear();
    while (true) {
      if (Eof()) return false;
      char c = text_[position_++];

      if (c == '"') return true;

      if (c != '\\') {
        // A raw control character is invalid JSON. Rejecting rather than
        // passing it through keeps "what we parsed" and "what was sent"
        // identical, which matters when the value is a key id.
        if (static_cast<unsigned char>(c) < 0x20) return false;
        out.push_back(c);
        continue;
      }

      if (Eof()) return false;
      char escape = text_[position_++];
      switch (escape) {
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        case '/': out.push_back('/'); break;
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        case 'u': {
          if (position_ + 4 > text_.size()) return false;
          unsigned code = 0;
          for (int i = 0; i < 4; i++) {
            char h = text_[position_++];
            code <<= 4;
            if (h >= '0' && h <= '9') code |= static_cast<unsigned>(h - '0');
            else if (h >= 'a' && h <= 'f') code |= static_cast<unsigned>(h - 'a' + 10);
            else if (h >= 'A' && h <= 'F') code |= static_cast<unsigned>(h - 'A' + 10);
            else return false;
          }
          // UTF-8, and surrogate halves are emitted as replacement characters
          // rather than reconstructed: nothing this library parses contains
          // astral-plane text, and half-decoding one would be worse than not.
          AppendUtf8(out, code);
          break;
        }
        default: return false;
      }
    }
  }

  static void AppendUtf8(std::string& out, unsigned code) {
    if (code >= 0xD800 && code <= 0xDFFF) code = 0xFFFD;
    if (code < 0x80) {
      out.push_back(static_cast<char>(code));
    } else if (code < 0x800) {
      out.push_back(static_cast<char>(0xC0 | (code >> 6)));
      out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
    } else {
      out.push_back(static_cast<char>(0xE0 | (code >> 12)));
      out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
    }
  }

  bool ParseNumber(Json& out) {
    std::size_t start = position_;
    if (!Eof() && Peek() == '-') position_++;

    bool digits = false;
    while (!Eof()) {
      char c = Peek();
      if (c >= '0' && c <= '9') {
        digits = true;
        position_++;
      } else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
        position_++;
      } else {
        break;
      }
    }
    if (!digits) return false;

    out.type = Json::Type::kNumber;
    out.number = std::strtod(text_.substr(start, position_ - start).c_str(), nullptr);
    return true;
  }
};

void EscapeInto(std::string& out, const std::string& value) {
  for (char c : value) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          char buffer[8];
          std::snprintf(buffer, sizeof(buffer), "\\u%04x", static_cast<unsigned char>(c));
          out += buffer;
        } else {
          out.push_back(c);
        }
    }
  }
}

}  // namespace

bool Json::Parse(const std::string& text, Json& out) {
  Parser parser(text);
  return parser.Parse(out);
}

std::string Json::Serialize(const std::map<std::string, std::string>& fields,
                            const std::map<std::string, bool>& flags) {
  std::string out = "{";
  bool first = true;

  for (const auto& entry : fields) {
    if (!first) out += ",";
    first = false;
    out += "\"";
    EscapeInto(out, entry.first);
    out += "\":\"";
    EscapeInto(out, entry.second);
    out += "\"";
  }

  for (const auto& entry : flags) {
    if (!first) out += ",";
    first = false;
    out += "\"";
    EscapeInto(out, entry.first);
    out += "\":";
    out += entry.second ? "true" : "false";
  }

  out += "}";
  return out;
}

std::string Json::Serialize(const std::map<std::string, std::string>& fields) {
  std::string out = "{";
  bool first = true;
  for (const auto& entry : fields) {
    if (!first) out += ",";
    first = false;
    out += "\"";
    EscapeInto(out, entry.first);
    out += "\":\"";
    EscapeInto(out, entry.second);
    out += "\"";
  }
  out += "}";
  return out;
}

const Json* Json::Find(const std::string& key) const {
  if (type != Type::kObject) return nullptr;
  auto it = object.find(key);
  return it == object.end() ? nullptr : &it->second;
}

std::optional<std::string> Json::GetString(const std::string& key) const {
  const Json* value = Find(key);
  if (value == nullptr || value->type != Type::kString) return std::nullopt;
  return value->string;
}

std::optional<std::int64_t> Json::GetInt(const std::string& key) const {
  const Json* value = Find(key);
  if (value == nullptr || value->type != Type::kNumber) return std::nullopt;
  // A non-integral value is refused rather than truncated: an `exp` of
  // 1.7e9 + 0.5 is a malformed token, not a token expiring half a second early.
  //
  // ⚠️ AND SO IS ONE NO int64 CAN HOLD. `1e999` parses to infinity, whose
  // fractional part is zero, and converting infinity or 1e300 to an integer is
  // undefined behaviour — reachable from an unsigned error body's
  // `attempts_remaining`, before any range check could run. 2^53 is the edge of
  // what a double counts exactly, and further than any value this library reads.
  if (!std::isfinite(value->number)) return std::nullopt;
  double integral = 0;
  if (std::modf(value->number, &integral) != 0.0) return std::nullopt;
  constexpr double kExact = 9007199254740992.0;  // 2^53
  if (integral > kExact || integral < -kExact) return std::nullopt;
  return static_cast<std::int64_t>(integral);
}

bool Json::GetBool(const std::string& key) const {
  const Json* value = Find(key);
  return value != nullptr && value->type == Type::kBool && value->boolean;
}

std::vector<std::string> Json::GetStringArray(const std::string& key) const {
  std::vector<std::string> out;
  const Json* value = Find(key);
  if (value == nullptr || value->type != Type::kArray) return out;
  for (const Json& entry : value->array) {
    if (entry.type == Type::kString) out.push_back(entry.string);
  }
  return out;
}


}  // namespace internal
}  // namespace grantry
