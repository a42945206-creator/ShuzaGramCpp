// Wire-format/crypto checks for transport::CreateObfuscated2Streams and
// transport::AcceptObfuscated2, cross-checked against gotd/td's own test
// vector (github.com/iamxvbaba/td@v1.3.3, mtproxy/obfuscated2/
// obfuscated2_test.go's TestEncrypt) -- same discipline as
// mtproto_srp_test.cpp's use of the official gotd/td SRP vector. Not
// invented inputs/outputs. The reversal step (getDecryptInit in the Go
// source) has no standalone public entry point here to test directly, but
// a bug in it would desync the decrypt key/iv and make
// TestCreateStreamsMatchesGoEncryptVector's decrypt-side assertion fail.

#include <cstdio>
#include <string>

#include "shuzagram/mtproto/transport/obfuscated2.hpp"

namespace {

using namespace shuzagram::mtproto::transport;

int g_failures = 0;

void Check(bool ok, const std::string& what) {
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s\n", what.c_str());
        ++g_failures;
    }
}

// TestEncrypt (obfuscated2_test.go): a specific 64-byte "rand" source, a
// 16-byte secret, protocol=0xdddddddd, dc=2. generateKeys derives streams
// from `rand` BEFORE any encryption -- exactly what CreateObfuscated2Streams
// takes as `init` -- so this vector tests CreateObfuscated2Streams directly.
//
// generateKeys itself, BEFORE the test's own assertions run, already spends
// 64 bytes of the encrypt stream encrypting the header
// (k.encrypt.XORKeyStream(encryptedInit[:], init[:]) inside generateKeys) --
// so by the time the Go test calls k.encrypt.XORKeyStream on "abcd", that
// stream is already at keystream position 64, not 0. decrypt is never
// touched by generateKeys, so its first use in the test really is at
// position 0. This mirrors that exactly, rather than re-deriving fresh
// streams and getting position 0 for both.
void TestCreateStreamsMatchesGoEncryptVector() {
    // clang-format off
    const std::array<std::uint8_t, 64> rand = {
        245, 118, 143, 80, 183, 49, 38, 10, 70, 190, 16, 39, 194, 238, 170,
        57, 53, 6, 36, 240, 182, 218, 89, 235, 165, 108, 129, 254, 69, 16,
        194, 224, 182, 29, 61, 211, 35, 238, 2, 56, 134, 51, 227, 131, 122,
        12, 28, 36, 250, 111, 41, 204, 215, 36, 190, 111, 65, 111, 247, 176,
        38, 246, 204, 230,
    };
    // clang-format on
    const std::vector<std::uint8_t> secret = {0x8a, 0x96, 0xef, 0x6e, 0x42, 0xa1, 0x8c, 0x21,
                                               0x83, 0x75, 0x80, 0xcd, 0x1c, 0x91, 0xc5, 0xa8};

    auto keys = CreateObfuscated2Streams(rand, secret);

    std::array<std::uint8_t, 64> header_scratch{};
    keys.encrypt.XorKeyStream(header_scratch.data(), rand.data(), rand.size());

    const std::array<std::uint8_t, 4> payload = {'a', 'b', 'c', 'd'};
    std::array<std::uint8_t, 4> encrypted{};
    keys.encrypt.XorKeyStream(encrypted.data(), payload.data(), payload.size());
    Check((encrypted == std::array<std::uint8_t, 4>{202, 122, 130, 38}),
          "encrypt stream (at keystream position 64, after generateKeys's own header encryption) matches gotd/td's "
          "TestEncrypt expected ciphertext for \"abcd\"");

    std::array<std::uint8_t, 4> decrypted_of_payload{};
    keys.decrypt.XorKeyStream(decrypted_of_payload.data(), payload.data(), payload.size());
    Check((decrypted_of_payload == std::array<std::uint8_t, 4>{143, 113, 25, 130}),
          "decrypt stream (untouched by generateKeys, so still at position 0; applied to the SAME plaintext per "
          "the Go test's own quirky assertion) matches gotd/td's TestEncrypt expected value");
}

// Feeds AcceptObfuscated2 the ACTUAL WIRE BYTES a real client would send
// (gotd/td's own k.header from that same TestEncrypt case: init[0:56] raw +
// the encrypt-stream-applied tail) and checks it recovers the real
// protocol=0xdddddddd/dc=2 the client encoded -- this is the server-side
// half TestEncrypt itself never exercises (it only tests the client's own
// encrypt/decrypt streams, not a server accepting them).
void TestAcceptObfuscated2RecoversMetadataFromRealWireBytes() {
    // clang-format off
    const std::array<std::uint8_t, 64> wire_header = {
        245, 118, 143, 80, 183, 49, 38, 10, 70, 190, 16, 39, 194, 238, 170, 57, 53, 6, 36, 240,
        182, 218, 89, 235, 165, 108, 129, 254, 69, 16, 194, 224, 182, 29, 61, 211, 35, 238,
        2, 56, 134, 51, 227, 131, 122, 12, 28, 36, 250, 111, 41, 204, 215, 36, 190, 111,
        190, 162, 221, 225, 109, 197, 157, 210,
    };
    // clang-format on
    const std::vector<std::uint8_t> secret = {0x8a, 0x96, 0xef, 0x6e, 0x42, 0xa1, 0x8c, 0x21,
                                               0x83, 0x75, 0x80, 0xcd, 0x1c, 0x91, 0xc5, 0xa8};

    const auto result = AcceptObfuscated2(wire_header, secret);
    Check((result.metadata.protocol == std::array<std::uint8_t, 4>{0xdd, 0xdd, 0xdd, 0xdd}),
          "AcceptObfuscated2 recovers the real protocol tag 0xdddddddd from real wire bytes");
    Check(result.metadata.dc == 2, "AcceptObfuscated2 recovers dc=2 from real wire bytes");
}

// No MTProxy secret (this project's own real deployment shape: a direct
// DC, not a proxy) -- round-trips through a full client/server simulation
// built from the SAME raw init, since there's no official secret-less
// vector to cross-check against.
void TestAcceptObfuscated2RoundTripsWithoutSecret() {
    std::array<std::uint8_t, 64> init{};
    for (std::size_t i = 0; i < init.size(); ++i) init[i] = static_cast<std::uint8_t>((i * 37 + 11) & 0xFF);
    // Bytes 4:8 must be non-zero for this to be a legal obfuscated2 init
    // (see obfuscated2-transport-plan.md's detection rule) -- already true
    // here incidentally, but assert it so a future change to the formula
    // above can't silently produce an illegal fixture.
    Check(init[4] != 0 || init[5] != 0 || init[6] != 0 || init[7] != 0, "fixture satisfies the non-zero-tail rule");

    const std::vector<std::uint8_t> no_secret;
    auto client = CreateObfuscated2Streams(init, no_secret);

    // Simulate what a real client does: encrypt the protocol+dc tail with
    // its own "encrypt" stream, leave bytes 0:56 as sent in the clear.
    std::array<std::uint8_t, 4> protocol = {0xef, 0xef, 0xef, 0xef}; // abridged's ObfuscatedTag
    std::uint16_t dc = 5;
    std::array<std::uint8_t, 64> wire = init;
    wire[56] = protocol[0];
    wire[57] = protocol[1];
    wire[58] = protocol[2];
    wire[59] = protocol[3];
    wire[60] = static_cast<std::uint8_t>(dc & 0xFF);
    wire[61] = static_cast<std::uint8_t>(dc >> 8);
    client.encrypt.XorKeyStream(wire.data(), wire.data(), wire.size());
    std::copy(init.begin(), init.begin() + 56, wire.begin()); // bytes 0:56 travel in the clear

    auto accepted = AcceptObfuscated2(wire, no_secret);
    Check(accepted.metadata.protocol == protocol, "round-trip without a secret recovers the protocol tag");
    Check(accepted.metadata.dc == dc, "round-trip without a secret recovers the dc id");

    // Now prove the derived streams are actually usable for real traffic in
    // both directions, continuing from keystream position 64.
    const std::array<std::uint8_t, 5> client_to_server = {'h', 'e', 'l', 'l', 'o'};
    std::array<std::uint8_t, 5> on_wire{};
    client.encrypt.XorKeyStream(on_wire.data(), client_to_server.data(), client_to_server.size());
    std::array<std::uint8_t, 5> server_sees{};
    accepted.keys.decrypt.XorKeyStream(server_sees.data(), on_wire.data(), on_wire.size());
    Check(server_sees == client_to_server, "server's decrypt stream reads real client->server traffic correctly");

    const std::array<std::uint8_t, 5> server_to_client = {'w', 'o', 'r', 'l', 'd'};
    std::array<std::uint8_t, 5> on_wire2{};
    accepted.keys.encrypt.XorKeyStream(on_wire2.data(), server_to_client.data(), server_to_client.size());
    std::array<std::uint8_t, 5> client_sees{};
    client.decrypt.XorKeyStream(client_sees.data(), on_wire2.data(), on_wire2.size());
    Check(client_sees == server_to_client, "client's decrypt stream reads real server->client traffic correctly");
}

} // namespace

int main() {
    TestCreateStreamsMatchesGoEncryptVector();
    TestAcceptObfuscated2RecoversMetadataFromRealWireBytes();
    TestAcceptObfuscated2RoundTripsWithoutSecret();
    if (g_failures == 0) {
        std::printf("all mtproto obfuscated2 tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d mtproto obfuscated2 test(s) failed\n", g_failures);
    return 1;
}
