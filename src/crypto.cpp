// Derivations and encodings that are the same on every platform.
//
// The primitives underneath — SHA-256, HMAC, AES-GCM — come from the operating
// system, because a desktop SDK has no business shipping its own cipher. What
// lives here is the part above them: the key schedule, the pin policy, and two
// encodings. All of it is portable, so there is one implementation to audit
// rather than one per platform that might quietly disagree.
#include "internal.hpp"

#include <algorithm>
#include <cstring>

namespace grantry {
namespace internal {

// ---------------------------------------------------------------------------
// Encodings
// ---------------------------------------------------------------------------

std::string Hex(const std::vector<std::uint8_t>& bytes) {
  static const char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (std::uint8_t byte : bytes) {
    out.push_back(kDigits[byte >> 4]);
    out.push_back(kDigits[byte & 0x0F]);
  }
  return out;
}

std::string Base64Encode(const std::vector<std::uint8_t>& bytes) {
  static const char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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

  // ⚠️ PADDED, UNLIKE Base64UrlEncode. A pin is printed by openssl, by curl and
  // by every browser's certificate viewer, all of them with `=`. Emitting an
  // unpadded one would produce a fingerprint that matches nothing a merchant
  // can compute for themselves.
  std::size_t remaining = bytes.size() - i;
  if (remaining == 1) {
    std::uint32_t block = static_cast<std::uint32_t>(bytes[i]) << 16;
    out.push_back(kAlphabet[(block >> 18) & 0x3F]);
    out.push_back(kAlphabet[(block >> 12) & 0x3F]);
    out.push_back('=');
    out.push_back('=');
  } else if (remaining == 2) {
    std::uint32_t block = (static_cast<std::uint32_t>(bytes[i]) << 16)
                        | (static_cast<std::uint32_t>(bytes[i + 1]) << 8);
    out.push_back(kAlphabet[(block >> 18) & 0x3F]);
    out.push_back(kAlphabet[(block >> 12) & 0x3F]);
    out.push_back(kAlphabet[(block >> 6) & 0x3F]);
    out.push_back('=');
  }

  return out;
}

// ---------------------------------------------------------------------------
// HKDF
// ---------------------------------------------------------------------------

bool Hkdf(const std::vector<std::uint8_t>& ikm, const std::vector<std::uint8_t>& salt,
          const std::vector<std::uint8_t>& info, std::size_t length,
          std::vector<std::uint8_t>& out) {
  constexpr std::size_t kHashLength = 32;
  if (length == 0 || length > kHashLength * 255) return false;

  /*
   * Extract. An absent salt is HashLen zero bytes by definition, and HMAC pads
   * any key shorter than its block size with zeros anyway — so an empty vector
   * and thirty-two zeros land on the same block. Skipping the step instead
   * would be a different function that looks identical from outside and
   * disagrees with the server on every derivation.
   */
  std::vector<std::uint8_t> prk;
  if (!HmacSha256(salt.empty() ? std::vector<std::uint8_t>(kHashLength, 0) : salt, ikm, prk)) {
    return false;
  }

  // Expand. T(n) = HMAC(prk, T(n-1) || info || n), n counting from 1.
  out.clear();
  out.reserve(length);

  std::vector<std::uint8_t> previous;
  std::uint8_t counter = 1;

  while (out.size() < length) {
    std::vector<std::uint8_t> block;
    block.reserve(previous.size() + info.size() + 1);
    block.insert(block.end(), previous.begin(), previous.end());
    block.insert(block.end(), info.begin(), info.end());
    block.push_back(counter);

    if (!HmacSha256(prk, block, previous)) return false;

    const std::size_t take = std::min(previous.size(), length - out.size());
    out.insert(out.end(), previous.begin(), previous.begin() + static_cast<long>(take));
    counter++;
  }

  std::fill(prk.begin(), prk.end(), std::uint8_t{0});
  return true;
}

// ---------------------------------------------------------------------------
// Certificate pinning policy
// ---------------------------------------------------------------------------

/*
 * ⚠️ LET'S ENCRYPT'S FOUR ROOT KEYS, NOT THE API CERTIFICATE'S OWN (17 October 2026). The plan
 * was the server's key, kept across renewals; measured before the first release, api.grantry.dev
 * is served the *.grantry.dev wildcard, whose key is new at every renewal, so a leaf pin would
 * have cut every shipped build off at the first one. A root pin refuses an interception proxy
 * just the same, because its certificates chain to a root it installed, never to these. The C#
 * SDK pins the same four (CertificatePinning.cs), and the edge asks Let's Encrypt and nobody else
 * for the names the SDKs reach (the ca lines in deploy/Caddyfile).
 *
 * Matching a root needs the chain, and the two transports reach it differently:
 *   Windows  WinHTTP hands back the chain Windows built, and every element is compared
 *   POSIX    libcurl pins only the server's own key, so with these pins the handshake trusts
 *            these roots and nothing else: kDefaultTrustAnchorsPem is its whole trust store
 *
 * In this order: ISRG Root X1 (RSA, to 2035), X2 (ECDSA, to 2040), Root YR (RSA) and Root YE
 * (ECDSA), both to 2045. TestBuiltInPinsAreTheirRoots computes each pin from its certificate.
 */
const char* const kDefaultCertificatePins[4] = {
    "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=",  // ISRG Root X1
    "diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=",  // ISRG Root X2
    "fk6IOKit1ild5647BH06ujSIq5XbCgqlbYl6ANhhi88=",  // Root YR
    "sCkq5UWXjg+7mKu9lMhhYF5bGLsy7VI/UNW3tccdR7w=",  // Root YE
};

/// The four roots those pins name, as letsencrypt.org/certificates publishes them.
const char* const kDefaultTrustAnchorsPem =
    // ISRG Root X1
    "-----BEGIN CERTIFICATE-----\n"
    "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\n"
    "-----END CERTIFICATE-----\n"
    // ISRG Root X2
    "-----BEGIN CERTIFICATE-----\n"
    "MIICGzCCAaGgAwIBAgIQQdKd0XLq7qeAwSxs6S+HUjAKBggqhkjOPQQDAzBPMQsw\n"
    "CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg\n"
    "R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5MDQwMDAwMDBaFw00\n"
    "MDA5MTcxNjAwMDBaME8xCzAJBgNVBAYTAlVTMSkwJwYDVQQKEyBJbnRlcm5ldCBT\n"
    "ZWN1cml0eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgyMHYw\n"
    "EAYHKoZIzj0CAQYFK4EEACIDYgAEzZvVn4CDCuwJSvMWSj5cz3es3mcFDR0HttwW\n"
    "+1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7mAHf7AlF9\n"
    "ItgKbppbd9/w+kHsOdx1ymgHDB/qo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0T\n"
    "AQH/BAUwAwEB/zAdBgNVHQ4EFgQUfEKWrt5LSDv6kviejM9ti6lyN5UwCgYIKoZI\n"
    "zj0EAwMDaAAwZQIwe3lORlCEwkSHRhtFcP9Ymd70/aTSVaYgLXTWNLxBo1BfASdW\n"
    "tL4ndQavEi51mI38AjEAi/V3bNTIZargCyzuFJ0nN6T5U6VR5CmD1/iQMVtCnwr1\n"
    "/q4AaOeMSQ+2b1tbFfLn\n"
    "-----END CERTIFICATE-----\n"
    // Root YR
    "-----BEGIN CERTIFICATE-----\n"
    "MIIFKTCCAxGgAwIBAgIRAOxGNJNgz0sP+KmC2Tqpyj0wDQYJKoZIhvcNAQELBQAw\n"
    "LjELMAkGA1UEBhMCVVMxDTALBgNVBAoTBElTUkcxEDAOBgNVBAMTB1Jvb3QgWVIw\n"
    "HhcNMjUwOTAzMDAwMDAwWhcNNDUwOTAyMjM1OTU5WjAuMQswCQYDVQQGEwJVUzEN\n"
    "MAsGA1UEChMESVNSRzEQMA4GA1UEAxMHUm9vdCBZUjCCAiIwDQYJKoZIhvcNAQEB\n"
    "BQADggIPADCCAgoCggIBANvGJnN78CTJdWL3+eGfsLN5TrNBJs+VH9hRXqRbwxu9\n"
    "sGNiB0BD1fcOxbSUQCJIM1xE13Db+5Cw1w0s0EBYsvuIP/6joF0w8cuImbgR1OGg\n"
    "YbSQ4OpzI+DG8SGuTlcE873OCS+kh3srlo6vl43M5OJg4Aeo1sfHp6kTJDoIiFBN\n"
    "JAY+OKfX/FUvYKuhjT+no49lmqmupSBI5PkBQiqrEGtWU5uxU/cQWHGu8jSjFBzn\n"
    "ZqvbNPLMXMLFxCb3WTfrJBXXjqvWG+v4bjzxjjeAtOlU7qarRDvNOyAuQYLln904\n"
    "M+faKx8hnLCpJ15ZqaEgcNlY+9MMWcC5yvL2A2j3l9+2buggZX+dOE91zYmIdawT\n"
    "vSZuVvlbRrAlLxIB6pwMBjneXCjYQ8+3BCCjssbSNpZU3hTcBDdhfAlEDlYr6pEa\n"
    "tnMdmDT5BqnKC92bd0EhM1fbLHioLccLCuievT8ZkPhZrq7Mii7gNXAcUEAR8+lz\n"
    "Yal+9zTg7C5DALyVOeG/CqfRAMn1KSHCR0NSA6P8tn/mGRlnCct5rtVCLnVySVpU\n"
    "6H1qGg3DgTOuskf8eahTMiYbI5ezPJmO5ertalskQ1utp74+eDy92PI4ftHKTbq9\n"
    "IWhH4YZKh3WnJEIt+oQvlYZbY8tpEroKrFB6PFGzrJIDRyts4HqvuH52RFj2zv/B\n"
    "AgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud\n"
    "DgQWBBTe51tg0CJtQCh9Pw0B/qS1UrRRlDANBgkqhkiG9w0BAQsFAAOCAgEAWHnf\n"
    "713Bdkq7t5yN2dNIgQakUb94X9WuyhMEHHkgx4oDpSUlnG0w4g94MoqaEUE31ZjR\n"
    "LU7L5LD1g9ujFHTQu8AD215AHMVQFbm6j8hQxdXHAzDajFNQnOlDJrLjzIx176oy\n"
    "AjvUtejZx2NNmdb5fd0WGVGsCdoAJ3N8ozo7ajE8t6vfxStZb4BQ9WYJGHUDrv2N\n"
    "i5tJF6CNiPnlzs3BUfECRbE4JSk+jvy8+VoGiFE8qsH/j78x2fjgQhAQFV7P7Zxy\n"
    "dBTZ1wEkNpZNW2qnaK1SKBLa+xf6E06YRIq5uaI+HWH8SY1y5VbRgzq40EKg3yxP\n"
    "06fz+uYAUIFJoLNfhwRCc3Q6pQVuMX3yAjHAes4gk4moGcLQ5p7HAh39yeylZc1J\n"
    "41sx/jKwLIkPE6Rr1Nf4pxdsxf9SA4yOEiAkDgq04DVxn8hgYFdUtBCuiuVC2heA\n"
    "EiqVEa+8QZjuw8Gj0EbHXcRd1nInvGqRS1o9Is7YBdQN57X1AYveGBNNqjICSb7c\n"
    "awuw1EawTDrs13VUlJVEsbQ0/O/1aaV73mCdOQ8azqL2KTv1Ewu1xbquE2S+kdQU\n"
    "To9TUwat3wUA6cwXh1EfpS/3fJ0aGah5hdpRyoCLDlsSn8tkrjMfFFX0viC+GxHc\n"
    "sI1ANRYvqSFC2X1VRZfDg+wD6E21BccmifG4yWc=\n"
    "-----END CERTIFICATE-----\n"
    // Root YE
    "-----BEGIN CERTIFICATE-----\n"
    "MIIB2TCCAWCgAwIBAgIRAKQCa6LvbHwg1AR+XmWmk4AwCgYIKoZIzj0EAwMwLjEL\n"
    "MAkGA1UEBhMCVVMxDTALBgNVBAoTBElTUkcxEDAOBgNVBAMTB1Jvb3QgWUUwHhcN\n"
    "MjUwOTAzMDAwMDAwWhcNNDUwOTAyMjM1OTU5WjAuMQswCQYDVQQGEwJVUzENMAsG\n"
    "A1UEChMESVNSRzEQMA4GA1UEAxMHUm9vdCBZRTB2MBAGByqGSM49AgEGBSuBBAAi\n"
    "A2IABDwS/6vhrcVqcbBo+wgdI3fwn9x7DNJJOY/lTOti0vkwuRN87RhEhTH17E7X\n"
    "yFjWsPYhIPt/wzOqxTd2b+4ZJNy9ID04YywF9U5zasDVyGSNErVNtz8uSGh5izW8\n"
    "7j77GaNCMEAwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0O\n"
    "BBYEFKPIJlqOoUzQNWP8myPIOq5W809WMAoGCCqGSM49BAMDA2cAMGQCMHhMr8N9\n"
    "LdL1VQKs9BdV81r76eXRB6mtjuNjzk6/lBsPNToWLTDzGYgtQKO1jl63uAIwGV7m\n"
    "onyF377c+MM1oqVNs17sgu7F9YKZwgLmVbeOMDbKAXHtKMDLbiGllCcs8f47\n"
    "-----END CERTIFICATE-----\n"
    ;

const char* const kDefaultPinnedHost = "api.grantry.dev";

namespace {

/// The host part of a URL, lower-cased, without port or path.
std::string HostOf(const std::string& url) {
  const std::size_t scheme = url.find("://");
  if (scheme == std::string::npos) return std::string();

  std::string rest = url.substr(scheme + 3);
  const std::size_t end = rest.find_first_of("/:");
  std::string host = end == std::string::npos ? rest : rest.substr(0, end);

  std::transform(host.begin(), host.end(), host.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return host;
}

}  // namespace

bool ShouldPin(const Options& options) {
  if (options.pin_certificate.has_value()) return *options.pin_certificate;
  if (!options.certificate_pins.empty()) return true;
  return HostOf(options.api_base_url) == kDefaultPinnedHost;
}

std::vector<std::string> PinsFor(const Options& options) {
  if (!options.certificate_pins.empty()) return options.certificate_pins;
  return std::vector<std::string>(std::begin(kDefaultCertificatePins),
                                  std::end(kDefaultCertificatePins));
}

const char* TrustAnchorsFor(const std::vector<std::string>& pins) {
  const std::vector<std::string> built_in(std::begin(kDefaultCertificatePins),
                                          std::end(kDefaultCertificatePins));
  return pins == built_in ? kDefaultTrustAnchorsPem : nullptr;
}

}  // namespace internal
}  // namespace grantry
