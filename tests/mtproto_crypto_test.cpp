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
#include "shuzagram/mtproto/crypto/dh.hpp"
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

// The official worked example from
// https://core.telegram.org/mtproto/samples-auth_key -- "Server DH inner
// data decomposition" static case, also gotd/td's crypto/dh_test.go:
// TestGAB/Static. Real dh_prime, real g_a from a real (if illustrative)
// handshake, a fixed secret exponent b, and the g_b Telegram's own docs say
// that combination must produce. Exercises ModPow and CheckDHParams
// together against a source with zero connection to this codebase.
void TestDiffieHellmanOfficialVector() {
    using shuzagram::mtproto::crypto::CheckDHParams;
    using shuzagram::mtproto::crypto::ModPow;

    const auto dh_prime = HexToBytes(
        "C71CAEB9C6B1C9048E6C522F70F13F73"
        "980D40238E3E21C14934D037563D930F"
        "48198A0AA7C14058229493D22530F4DB"
        "FA336F6E0AC925139543AED44CCE7C37"
        "20FD51F69458705AC68CD4FE6B6B13AB"
        "DC9746512969328454F18FAF8C595F64"
        "2477FE96BB2A941D5BCD1D4AC8CC4988"
        "0708FA9B378E3C4F3A9060BEE67CF9A4"
        "A4A695811051907E162753B56B0F6B41"
        "0DBA74D8A84B2A14B3144E0EF1284754"
        "FD17ED950D5965B4B9DD46582DB1178D"
        "169C6BC465B0D6FF9CA3928FEF5B9AE4"
        "E418FC15E83EBEA0F87FA9FF5EED7005"
        "0DED2849F47BF959D956850CE929851F"
        "0D8115F635B105EE2E4E15D04B2454BF"
        "6F4FADF034B10403119CD8E3B92FCC5B");
    const auto g_a = HexToBytes(
        "262AABA621CC4DF587DC94CF8252258C"
        "0B9337DFB47545A49CDD5C9B8EAE7236"
        "C6CADC40B24E88590F1CC2CC762EBF1C"
        "F11DCC0B393CAAD6CEE4EE5848001C73"
        "ACBB1D127E4CB93072AA3D1C8151B6FB"
        "6AA6124B7CD782EAF981BDCFCE9D7A00"
        "E423BD9D194E8AF78EF6501F415522E4"
        "4522281C79D906DDB79C72E9C63D83FB"
        "2A940FF779DFB5F2FD786FB4AD71C9F0"
        "8CF48758E534E9815F634F1E3A80A5E1"
        "C2AF210C5AB762755AD4B2126DFA61A7"
        "7FA9DA967D65DFD0AFB5CDF26C4D4E1A"
        "88B180F4E0D0B45BA1484F95CB2712B5"
        "0BF3F5968D9D55C99C0FB9FB67BFF56D"
        "7D4481B634514FBA3488C4CDA2FC0659"
        "990E8E868B28632875A9AA703BCDCE8F");
    const auto b = HexToBytes(
        "6F620AFA575C9233EB4C014110A7BCAF49464F798A18A0981FEA1E05E8DA"
        "67D9681E0FD6DF0EDF0272AE3492451A84502F2EFC0DA18741A5FB80BD82296919A70FAA6D07CBBBCA2037EA7D3E327B61D"
        "585ED3373EE0553A91CBD29B01FA9A89D479CA53D57BDE3A76FBD922A923A0A38B922C1D0701F53FF52D7EA9217080163A64901"
        "E766EB6A0F20BC391B64B9D1DD2CD13A7D0C946A3A7DF8CEC9E2236446F646C42CFE2B60A2A8D776E56C8D7519B08B88ED0970E"
        "10D12A8C9E355D765F2B7BBB7B4CA9360083435523CB0D57D2B106FD14F94B4EEE79D8AC131CA56AD389C84FE279716F8124A54"
        "3337FB9EA3D988EC5FA63D90A4BA3970E7A39E5C0DE5");
    const auto want_g_b = HexToBytes(
        "73700E7BFC7AEEC828EB8E0DCC04D09A"
        "0DD56A1B4B35F72F0B55FCE7DB7EBB72"
        "D7C33C5D4AA59E1C74D09B01AE536B31"
        "8CFED436AFDB15FE9EB4C70D7F0CB14E"
        "46DBBDE9053A64304361EB358A9BB32E"
        "9D5C2843FE87248B89C3F066A7D5876D"
        "61657ACC52B0D81CD683B2A0FA93E8AD"
        "AB20377877F3BC3369BBF57B10F5B589"
        "E65A9C27490F30A0C70FFCFD3453F5B3"
        "79C1B9727A573CFFDCA8D23C721B135B"
        "92E529B1CDD2F7ABD4F34DAC4BE1EEAF"
        "60993DDE8ED45890E4F47C26F2C0B2E0"
        "37BB502739C8824F2A99E2B1E7E41658"
        "3417CC79A8807A4BDAC6A5E9805D4F61"
        "86C37D66F6988C9F9C752896F3D34D25"
        "529263FAF2670A09B2A59CE35264511F");

    const std::vector<std::uint8_t> g2 = {0x02};
    const auto g_b = ModPow(g2, b, dh_prime);
    Check(g_b == want_g_b, "ModPow(g=2, b, dh_prime) matches the official Telegram sample's g_b");

    try {
        CheckDHParams(dh_prime, 2, g_a, g_b);
        Check(true, "CheckDHParams accepts the official sample's (dh_prime, g, g_a, g_b)");
    } catch (const std::exception& e) {
        Check(false, std::string("CheckDHParams unexpectedly rejected the official sample: ") + e.what());
    }
}

void TestTempAesKeysAndServerSaltSelfConsistent() {
    using namespace shuzagram::mtproto;
    using namespace shuzagram::mtproto::crypto;

    Int256 new_nonce{};
    Int128 server_nonce{};
    for (std::size_t i = 0; i < new_nonce.size(); ++i) new_nonce[i] = static_cast<std::uint8_t>(i + 1);
    for (std::size_t i = 0; i < server_nonce.size(); ++i) server_nonce[i] = static_cast<std::uint8_t>(0x80 + i);

    std::vector<std::uint8_t> key, iv;
    TempAesKeys(new_nonce, server_nonce, key, iv);
    Check(key.size() == 32, "TempAesKeys key is 32 bytes (AES-256)");
    Check(iv.size() == 32, "TempAesKeys iv is 32 bytes (two IGE IVs)");

    // encrypt/decrypt through IGE with these derived keys should round-trip
    // -- ties TempAesKeys to the already-verified IGE implementation.
    const std::vector<std::uint8_t> plaintext(64, 0x42);
    const auto ciphertext = IgeEncrypt(key, iv, plaintext);
    Check(IgeDecrypt(key, iv, ciphertext) == plaintext, "TempAesKeys-derived key/iv round-trip through AES-IGE");

    const std::int64_t salt1 = ServerSalt(new_nonce, server_nonce);
    const std::int64_t salt2 = ServerSalt(new_nonce, server_nonce);
    Check(salt1 == salt2, "ServerSalt is deterministic for the same nonces");

    std::array<std::uint8_t, 256> auth_key{};
    for (std::size_t i = 0; i < auth_key.size(); ++i) auth_key[i] = static_cast<std::uint8_t>(i);
    const Int128 hash1 = NonceHash1(new_nonce, auth_key);
    const Int128 hash1_again = NonceHash1(new_nonce, auth_key);
    Check(hash1 == hash1_again, "NonceHash1 is deterministic");
}

void TestDataWithHashRoundTrip() {
    using namespace shuzagram::mtproto::crypto;

    const std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    const auto wrapped = DataWithHash(payload);
    Check(wrapped.size() % 16 == 0, "DataWithHash output is padded to a multiple of 16");
    Check(wrapped.size() >= payload.size() + 20, "DataWithHash output holds the SHA1 prefix plus the payload");

    const auto recovered = GuessDataWithHash(wrapped);
    Check(recovered == payload, "GuessDataWithHash recovers the exact original payload");
}

} // namespace

int main() {
    TestAesIgeOfficialVectors();
    TestRsaPadOfficialVector();
    TestRsaGenerateSaveLoadRoundTrip();
    TestRsaPadUnpadRoundTrip();
    TestDiffieHellmanOfficialVector();
    TestTempAesKeysAndServerSaltSelfConsistent();
    TestDataWithHashRoundTrip();
    if (g_failures == 0) {
        std::printf("all mtproto crypto tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d mtproto crypto test(s) failed\n", g_failures);
    return 1;
}
