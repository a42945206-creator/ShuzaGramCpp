// Tests for MTProto 2.0 message encryption (shuzagram::mtproto::crypto::
// EncryptMessage/DecryptMessage and their building blocks), verified
// against gotd/td's own official test vectors (crypto/key_test.go:
// TestAuthKeyID/TestCalcKey, crypto/cipher_padding_test.go) rather than
// self-consistency alone.

#include <cstdio>
#include <string>
#include <vector>

#include "shuzagram/mtproto/crypto/message_cipher.hpp"

namespace {

using namespace shuzagram::mtproto;
using namespace shuzagram::mtproto::crypto;

int g_failures = 0;

void Check(bool ok, const std::string& what) {
    if (ok) {
        std::printf("ok: %s\n", what.c_str());
    } else {
        std::fprintf(stderr, "FAIL: %s\n", what.c_str());
        ++g_failures;
    }
}

AuthKeyBytes SequentialKey() {
    AuthKeyBytes k{};
    for (int i = 0; i < 256; ++i) k[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(i);
    return k;
}

// key_test.go: TestAuthKeyID. auth_key = bytes 0..255.
void TestAuthKeyIdOfficialVector() {
    const AuthKeyBytes k = SequentialKey();
    const std::array<std::uint8_t, 8> want_id = {50, 209, 88, 110, 164, 87, 223, 200};
    const std::array<std::uint8_t, 8> want_aux_hash = {73, 22, 214, 189, 183, 247, 142, 104};

    Check(AuthKeyId(k) == want_id, "AuthKeyId matches gotd/td's TestAuthKeyID vector");
    Check(AuthKeyAuxHash(k) == want_aux_hash, "AuthKeyAuxHash matches gotd/td's TestAuthKeyID vector");
}

// key_test.go: TestCalcKey. Same auth_key, msg_key = bytes 0..15, both
// Client and Server sides have their own exact expected (key, iv) pairs.
void TestDeriveMessageKeysOfficialVectors() {
    const AuthKeyBytes k = SequentialKey();
    Int128 msg_key{};
    for (int i = 0; i < 16; ++i) msg_key[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(i);

    {
        std::vector<std::uint8_t> key, iv;
        DeriveMessageKeys(k, msg_key, Side::kClient, key, iv);
        const std::vector<std::uint8_t> want_key = {112, 78,  208, 156, 139, 65,  102, 138, 232, 249, 157,
                                                      36,  71,  56,  247, 29,  189, 220, 68,  70,  155, 107,
                                                      189, 74,  168, 87,  61,  208, 66,  189, 5,   158};
        const std::vector<std::uint8_t> want_iv = {77,  38,  96,  0,   165, 80,  237, 171, 191, 76,  124,
                                                     228, 15,  208, 4,   60,  201, 34,  48,  24,  76,  211,
                                                     23,  165, 204, 156, 36,  130, 253, 59,  147, 24};
        Check(key == want_key, "DeriveMessageKeys(Client) key matches gotd/td's TestCalcKey vector");
        Check(iv == want_iv, "DeriveMessageKeys(Client) iv matches gotd/td's TestCalcKey vector");
    }
    {
        std::vector<std::uint8_t> key, iv;
        DeriveMessageKeys(k, msg_key, Side::kServer, key, iv);
        const std::vector<std::uint8_t> want_key = {33,  119, 37,  121, 155, 36,  88,  6,   69,  129, 116,
                                                      161, 252, 251, 200, 131, 144, 104, 7,   177, 80,  51,
                                                      253, 208, 234, 43,  77,  105, 207, 156, 54,  78};
        const std::vector<std::uint8_t> want_iv = {102, 154, 101, 56,  145, 122, 79,  165, 108, 163, 35,
                                                     96,  164, 49,  201, 22,  11,  228, 173, 136, 113, 64,
                                                     152, 13,  171, 145, 206, 123, 220, 71,  255, 188};
        Check(key == want_key, "DeriveMessageKeys(Server) key matches gotd/td's TestCalcKey vector");
        Check(iv == want_iv, "DeriveMessageKeys(Server) iv matches gotd/td's TestCalcKey vector");
    }
}

// cipher_padding_test.go: TestCountPadding / TestCountPaddingJitter.
void TestCountPaddingInvariants() {
    bool all_ok = true;
    for (int l = 0; l < 4096 && all_ok; ++l) {
        for (const std::uint8_t rand_byte : {0x00, 0x01, 0x0F, 0x7F, 0xF0, 0xFF}) {
            const int padding = CountPadding(l, static_cast<std::uint8_t>(rand_byte));
            const int total = l + padding;
            if (padding < 12 || padding > 1024 || total % 16 != 0 ||
                CountPadding(l, static_cast<std::uint8_t>(rand_byte & 0x0F)) != padding) {
                all_ok = false;
                break;
            }
        }
    }
    Check(all_ok, "CountPadding satisfies MTProto 2.0's 12..1024, 16-aligned invariants for l in [0,4096)");

    const int base = CountPadding(64, 0x00);
    const int jittered = CountPadding(64, 0x0F);
    Check(jittered == base + 0x0F * 16, "CountPadding's random component adds exactly randByte&0xF extra 16-byte blocks");
    Check(base != jittered, "CountPadding's random component actually changes the total length");
}

// cipher_test.go: TestCipher (checkSame, both directions).
void TestEncryptDecryptRoundTrip() {
    AuthKeyBytes auth_key{};
    const auto random_key = SystemRandomBytes(256);
    std::copy(random_key.begin(), random_key.end(), auth_key.begin());

    const std::vector<std::uint8_t> message = {'d', 'a', 't', 'a', 0, 0, 0, 0}; // padded to a multiple of 4 already... (int32-aligned)
    const std::int64_t session_id = 123456789;

    for (const Side sender : {Side::kClient, Side::kServer}) {
        const EncryptedMessage wire =
            EncryptMessage(auth_key, /*salt=*/0, session_id, /*message_id=*/111, /*seq_no=*/1, message, sender);

        TLBuffer encoded;
        wire.Encode(encoded);
        EncryptedMessage roundtripped;
        TLBuffer decode_buf;
        decode_buf.buf = encoded.buf;
        roundtripped.Decode(decode_buf);
        Check(roundtripped.auth_key_id == wire.auth_key_id && roundtripped.msg_key == wire.msg_key &&
                  roundtripped.encrypted_data == wire.encrypted_data,
              "EncryptedMessage::Encode/Decode round-trips the wire envelope");

        const EncryptedMessageData decrypted = DecryptMessage(auth_key, roundtripped, OppositeSide(sender));
        Check(decrypted.session_id == session_id,
              std::string("DecryptMessage recovers session_id when encrypted as ") +
                  (sender == Side::kClient ? "Client" : "Server"));
        Check(decrypted.message_data == message,
              std::string("DecryptMessage recovers the exact message bytes when encrypted as ") +
                  (sender == Side::kClient ? "Client" : "Server"));

        // Decrypting with the SAME side as the sender (instead of the
        // opposite) must fail: msg_key was derived from the sender's own
        // 36-byte auth_key slice, and using the wrong slice recomputes a
        // different msg_key.
        bool wrong_side_rejected = false;
        try {
            DecryptMessage(auth_key, roundtripped, sender);
        } catch (const std::exception&) {
            wrong_side_rejected = true;
        }
        Check(wrong_side_rejected, "DecryptMessage rejects decrypting with the sender's own side instead of the opposite");
    }
}

void TestDecryptRejectsTamperedCiphertext() {
    AuthKeyBytes auth_key{};
    const auto random_key = SystemRandomBytes(256);
    std::copy(random_key.begin(), random_key.end(), auth_key.begin());

    const std::vector<std::uint8_t> message = {1, 2, 3, 4};
    EncryptedMessage wire = EncryptMessage(auth_key, 0, 42, 100, 1, message, Side::kClient);
    wire.encrypted_data[0] ^= 0xFF; // flip a bit in the ciphertext

    bool rejected = false;
    try {
        DecryptMessage(auth_key, wire, Side::kServer);
    } catch (const std::exception&) {
        rejected = true;
    }
    Check(rejected, "DecryptMessage's msg_key check rejects a tampered ciphertext (AEAD-like integrity)");
}

} // namespace

int main() {
    TestAuthKeyIdOfficialVector();
    TestDeriveMessageKeysOfficialVectors();
    TestCountPaddingInvariants();
    TestEncryptDecryptRoundTrip();
    TestDecryptRejectsTamperedCiphertext();

    if (g_failures == 0) {
        std::printf("all mtproto message cipher tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d mtproto message cipher test(s) failed\n", g_failures);
    return 1;
}
