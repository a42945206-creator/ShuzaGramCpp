// Crypto-primitive checks for the MTProto handshake port, verified against
// vectors from the actual upstream libraries the Go source depends on
// (gotd/ige) rather than hand-derived expected values -- see
// NOTES/transport-handshake-plan.md for where each came from. Byte arrays
// below are transcribed directly from gotd/ige's ige_test.go (not via hex
// strings) to avoid transcription drift.

#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

#include "shuzagram/mtproto/crypto/aes_ige.hpp"
#include "shuzagram/mtproto/crypto/rsa.hpp"
#include "shuzagram/mtproto/crypto/rsa_pad.hpp"

namespace {

int g_failures = 0;

void Check(bool ok, const std::string& what) {
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s\n", what.c_str());
        ++g_failures;
    }
}

struct IgeVector {
    std::vector<std::uint8_t> key;
    std::vector<std::uint8_t> iv;
    std::vector<std::uint8_t> plaintext;
    std::vector<std::uint8_t> ciphertext;
};

// The two official gotd/ige test vectors (ige_test.go), themselves the
// classic OpenSSL IGE mode test vectors.
const IgeVector kVectors[] = {
    {
        {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
        {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F},
        std::vector<std::uint8_t>(32, 0x00),
        {0x1A, 0x85, 0x19, 0xA6, 0x55, 0x7B, 0xE6, 0x52, 0xE9, 0xDA, 0x8E, 0x43, 0xDA, 0x4E, 0xF4, 0x45,
         0x3C, 0xF4, 0x56, 0xB4, 0xCA, 0x48, 0x8A, 0xA3, 0x83, 0xC7, 0x9C, 0x98, 0xB3, 0x47, 0x97, 0xCB},
    },
    {
        {0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x6E, 0x20, 0x69, 0x6D, 0x70, 0x6C, 0x65},
        {0x6D, 0x65, 0x6E, 0x74, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x6F, 0x66, 0x20, 0x49, 0x47, 0x45,
         0x20, 0x6D, 0x6F, 0x64, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x4F, 0x70, 0x65, 0x6E, 0x53, 0x53},
        {0x99, 0x70, 0x64, 0x87, 0xA1, 0xCD, 0xE6, 0x13, 0xBC, 0x6D, 0xE0, 0xB6, 0xF2, 0x4B, 0x1C, 0x7A,
         0xA4, 0x48, 0xC8, 0xB9, 0xC3, 0x40, 0x3E, 0x34, 0x67, 0xA8, 0xCA, 0xD8, 0x93, 0x40, 0xF5, 0x3B},
        {0x4C, 0x2E, 0x20, 0x4C, 0x65, 0x74, 0x27, 0x73, 0x20, 0x68, 0x6F, 0x70, 0x65, 0x20, 0x42, 0x65,
         0x6E, 0x20, 0x67, 0x6F, 0x74, 0x20, 0x69, 0x74, 0x20, 0x72, 0x69, 0x67, 0x68, 0x74, 0x21, 0x0A},
    },
};

void TestAesIgeOfficialVectors() {
    using shuzagram::mtproto::crypto::IgeDecrypt;
    using shuzagram::mtproto::crypto::IgeEncrypt;

    int i = 0;
    for (const auto& v : kVectors) {
        ++i;
        const auto ciphertext = IgeEncrypt(v.key, v.iv, v.plaintext);
        Check(ciphertext == v.ciphertext, "AES-IGE vector " + std::to_string(i) + " encrypt matches gotd/ige");

        const auto plaintext = IgeDecrypt(v.key, v.iv, v.ciphertext);
        Check(plaintext == v.plaintext, "AES-IGE vector " + std::to_string(i) + " decrypt matches gotd/ige");
    }
}

// gotd/td's crypto/rsa_pad_test.go: TestRSAPad. Fixed public key + an
// all-zero randomness source ("testutil.ZeroRand{}") + 144 'a' bytes must
// produce this exact 256-byte ciphertext. Verifies RsaPad, RsaPublicKey::
// FromPkcs1Pem and RsaPublicKey::EncryptRaw all agree with upstream
// byte-for-byte.
const char* const kTestRsaPublicKeyPem =
    "-----BEGIN RSA PUBLIC KEY-----\n"
    "MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g\n"
    "5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO\n"
    "62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/\n"
    "+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9\n"
    "t6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs\n"
    "5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB\n"
    "-----END RSA PUBLIC KEY-----\n";

std::vector<std::uint8_t> HexToBytes(const std::string& hex) {
    std::vector<std::uint8_t> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(static_cast<std::uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return out;
}

void TestRsaPadOfficialVector() {
    using shuzagram::mtproto::crypto::RsaPad;
    using shuzagram::mtproto::crypto::RsaPublicKey;

    const RsaPublicKey key = RsaPublicKey::FromPkcs1Pem(kTestRsaPublicKeyPem);
    const std::vector<std::uint8_t> data(144, 'a');
    const auto zero_rand = [](std::uint8_t* buf, std::size_t len) { std::fill(buf, buf + len, 0); };

    const auto encrypted = RsaPad(data, key, zero_rand);
    Check(encrypted.size() == 256, "RsaPad output is 256 bytes");

    const std::string expected_hex =
        "bf68719e836806b040cd261ecaf66eb3c4ba19f3bbea3031b2e6cf29167bab647201d101b291dc"
        "5b716a42e789a38d947fe59e9bcce8f30ef46a946743ea8b6babbce7fc0afc46b802aa453e83471d82a4dfad83f971f35"
        "0b4b4fb474cd1c48fdf427e4b5fecce9ec3178ae7dac3985856fdefa21d6fdc5e0e0fd8a57bc4f51580d637d372be8d87"
        "c9aa3fde8e6f8287bcb3be846aadcdd59465375479e248f62ed438f9804fbe36d41ca906243a5f740f3937949aa149ba8"
        "a8b8e68b3f3e1e3cd3f946387520e21eee55845e1f015a919a22f6a72bfaecd2cae946c91983b41f9ffabe97963bbde8f"
        "30eaf5fd3c5b8cecab8711bd269e441b6084f385726ff0";
    Check(encrypted == HexToBytes(expected_hex), "RsaPad matches gotd/td's TestRSAPad vector exactly");
}

void TestRsaGenerateSaveLoadRoundTrip() {
    using shuzagram::mtproto::crypto::RsaPrivateKey;

    const RsaPrivateKey key = RsaPrivateKey::Generate(2048);
    const std::string pem = key.ToPkcs1Pem();
    Check(pem.find("-----BEGIN RSA PRIVATE KEY-----") == 0, "generated key PEM has the PKCS#1 header Go expects");

    const RsaPrivateKey reloaded = RsaPrivateKey::FromPkcs1Pem(pem);
    Check(reloaded.Fingerprint() == key.Fingerprint(), "PEM round-trip preserves the key (same fingerprint)");
}

void TestRsaPadUnpadRoundTrip() {
    using shuzagram::mtproto::crypto::RsaPad;
    using shuzagram::mtproto::crypto::RsaPrivateKey;
    using shuzagram::mtproto::crypto::RsaUnpad;

    const RsaPrivateKey key = RsaPrivateKey::Generate(2048);
    std::vector<std::uint8_t> payload(100);
    for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<std::uint8_t>(i);

    const auto encrypted = RsaPad(payload, key.PublicKey());
    const auto decoded = RsaUnpad(encrypted, key);

    Check(decoded.size() == 192, "RsaUnpad always returns the full 192-byte data_with_padding");
    Check(std::equal(payload.begin(), payload.end(), decoded.begin()),
          "RsaUnpad recovers the original payload from its own RsaPad output");
}

} // namespace

int main() {
    TestAesIgeOfficialVectors();
    TestRsaPadOfficialVector();
    TestRsaGenerateSaveLoadRoundTrip();
    TestRsaPadUnpadRoundTrip();
    if (g_failures == 0) {
        std::printf("all mtproto crypto tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d mtproto crypto test(s) failed\n", g_failures);
    return 1;
}
