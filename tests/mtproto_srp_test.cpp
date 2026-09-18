// Crypto-primitive checks for MTProto's 2FA SRP protocol (srp.hpp).
// TestSrpClientProofOfficialVector ports gotd/td's own TestSRP
// (crypto/srp/srp_test.go) byte-for-byte -- the strongest verification
// available, matching the discipline used for the AES-IGE/RSA_PAD/DH
// vectors elsewhere in this project. TestServerAgreesWithClient then
// closes the loop: an independently-implemented server (SrpMakeChallenge/
// SrpCalcM1) must arrive at the exact same M1 a genuine client computes,
// not just agree with itself.

#include <cstdio>
#include <cstring>
#include <string>

#include "shuzagram/mtproto/crypto/srp.hpp"

namespace {

using namespace shuzagram::mtproto::crypto;

int g_failures = 0;

void Check(bool ok, const std::string& what) {
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s\n", what.c_str());
        ++g_failures;
    }
}

std::vector<std::uint8_t> HexToBytes(const std::string& hex) {
    std::vector<std::uint8_t> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(static_cast<std::uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return out;
}

std::vector<std::uint8_t> BigEndianUint32InLast4Bytes(std::size_t size, std::uint32_t value) {
    std::vector<std::uint8_t> out(size, 0);
    out[size - 4] = static_cast<std::uint8_t>(value >> 24);
    out[size - 3] = static_cast<std::uint8_t>(value >> 16);
    out[size - 2] = static_cast<std::uint8_t>(value >> 8);
    out[size - 1] = static_cast<std::uint8_t>(value);
    return out;
}

// NOTE: deliberately takes a std::string, not two chained
// std::string("...").begin()/.end() calls -- that pattern constructs TWO
// separate temporary strings (one per call) and forms a range spanning
// unrelated objects, which is undefined behavior (silently reads garbage
// stack memory, differently on every run). Found via ASan while chasing
// exactly this bug in this file's first draft.
std::vector<std::uint8_t> Ascii(const std::string& s) { return {s.begin(), s.end()}; }

// gotd/td crypto/srp/srp_test.go's TestSRP, transcribed field-for-field.
void TestSrpClientProofOfficialVector() {
    const auto password = Ascii("123123");
    const auto salt1 = HexToBytes("4D11FB6BEC38F9D2546BB0F61E4F1C99A1BC0DB8F0D5F35B1291B37B213123D7ED48F3C6794D495B");
    const auto salt2 = HexToBytes("A1B181AAFE88188680AE32860D60BB01");
    const auto srp_b = HexToBytes(
        "9C52401A6A8084EC82F01C3725D3FB448BD2F0C909F9D97726EAC4B7A74172D9"
        "52F02466BE6734FA274D2B7429E27397F10372D66B400B80A5C5AE3F28B17BF3"
        "105D7A2D2A885998CDC2DEFC208AEC217AB58859A9ABC2374AD93DC285F4B3FB"
        "CAFF4143D7888F2425BD2FB711B25609CEB21757D935B1EF2F042173AD0CE2FE"
        "0E474DAC53914BD25A8A9AED4AEA8953D55CB88621DB37B871EA0D04393AC098"
        "7F68094CCC9DE8239251375D8FFFD263316CD528C097B7BC9FB919FBEDB76C52"
        "5DF3413C374EE076D97A1E6D352BB7CC80FD13651B04B32E2E48C5268150842C"
        "FD07CF855958B1B5EA9C36FDAD697FE3AEC8DCC6B1EFEC36874AF226204676CF");
    const auto random = BigEndianUint32InLast4Bytes(256, 1);

    const auto expected_a = BigEndianUint32InLast4Bytes(256, 3);
    const auto expected_m1 = HexToBytes("999DF906BDA2C6CBB52F503406EBA2D0D0503ACE0CC302C38F13EE5010AD4051");
    Check(expected_m1.size() == 32, "the official test vector's expected M1 is 32 bytes (sanity-check on hex transcription)");

    const auto answer = SrpClientProof(password, salt1, salt2, srp_b, random);
    Check(answer.a == expected_a, "SrpClientProof computes the exact official g_a for random=1 (g_a == g)");
    Check(answer.m1 == expected_m1, "SrpClientProof computes the exact official M1");
}

// The server implementation (SrpMakeChallenge/SrpCalcM1) is a SEPARATE
// port from a separate Go source file (internal/app/account/srp.go, not
// gotd/td's client package) -- this proves it agrees with a genuinely
// independent client computation for a real password/verifier, not just
// with itself.
void TestServerAgreesWithClient() {
    const auto password = Ascii("hunter2");
    std::vector<std::uint8_t> salt1 = {0xEC, 0xF8, 0x73, 0x76, 0x65, 0xBC, 0x77, 0x5A}; // baseSalt1
    // A real account's salt1 is baseSalt1 + 32 random bytes; any 32 extra
    // bytes work here since this test doesn't validate against
    // validateNewPasswordSettings's exact-length rule.
    for (int i = 0; i < 32; ++i) salt1.push_back(static_cast<std::uint8_t>(i));
    const auto salt2 = SrpBaseSalt2();

    const auto verifier = SrpComputeVerifier(password, salt1, salt2);

    const auto challenge = SrpMakeChallenge(verifier);

    const auto client_random = BigEndianUint32InLast4Bytes(256, 0xDEADBEEF);
    const auto client_answer = SrpClientProof(password, salt1, salt2, challenge.b, client_random);

    const auto server_m1 = SrpCalcM1(salt1, verifier, challenge.b_secret, challenge.b, client_answer.a);
    Check(server_m1 == client_answer.m1,
          "the server's independently-implemented SrpCalcM1 agrees with a genuine client's M1");

    // An attacker who doesn't know the password but tries the SAME random
    // exponent computes the SAME public A (A depends only on the random
    // exponent, never on the password) but a DIFFERENT M1 (M1 depends on
    // x, which does depend on the password). auth.checkPassword's actual
    // gate is "does the client's claimed M1 equal the server's
    // independently-derived expectation for that A" -- so the meaningful
    // check is against server_m1, not just against the genuine client's M1.
    const auto wrong_password = Ascii("wrong");
    const auto wrong_answer = SrpClientProof(wrong_password, salt1, salt2, challenge.b, client_random);
    Check(wrong_answer.a == client_answer.a, "A depends only on the random exponent, not the password (sanity check)");
    Check(wrong_answer.m1 != server_m1, "a wrong password's claimed M1 does not match the server's expectation");
}

void TestPadToHash() {
    Check(SrpPadToHash({1, 2, 3}).size() == 256, "SrpPadToHash pads a short input to 256 bytes");
    Check(SrpPadToHash({1, 2, 3})[255] == 3, "SrpPadToHash left-pads (short input lands at the tail)");
    std::vector<std::uint8_t> long_input(300, 0xAB);
    long_input[299] = 0x42;
    const auto padded = SrpPadToHash(long_input);
    Check(padded.size() == 256 && padded[255] == 0x42, "SrpPadToHash truncates a long input, keeping the LAST 256 bytes");
}

} // namespace

int main() {
    TestPadToHash();
    TestSrpClientProofOfficialVector();
    TestServerAgreesWithClient();
    if (g_failures == 0) {
        std::printf("all mtproto srp tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d mtproto srp test(s) failed\n", g_failures);
    return 1;
}
