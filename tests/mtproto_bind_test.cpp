// Crypto-layer checks for auth.bindTempAuthKey's encrypted_message envelope
// (kdf_v1.hpp + crypto/bind.hpp). There's no official published hex vector
// for this envelope (unlike aes_ige/rsa_pad/dh), so verification instead
// mirrors gotd/td's own TestEncryptBindMessage (crypto/bind_test.go): fixed
// deterministic key material and an all-0xCD "random" stream so every byte
// of the construction is checked by hand, then cross-checked against this
// project's own DecryptBindAuthKeyInner (the function the server actually
// calls) to prove the two directions genuinely agree with each other, not
// just with themselves.

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>

#include "shuzagram/mtproto/crypto/aes_ige.hpp"
#include "shuzagram/mtproto/crypto/bind.hpp"
#include "shuzagram/mtproto/crypto/kdf_v1.hpp"

namespace {

using namespace shuzagram::mtproto;
using namespace shuzagram::mtproto::crypto;

int g_failures = 0;

void Check(bool ok, const std::string& what) {
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s\n", what.c_str());
        ++g_failures;
    }
}

AuthKeyBytes MakeKey(std::uint8_t seed_byte_0) {
    AuthKeyBytes key{};
    for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<std::uint8_t>(seed_byte_0 - i);
    return key;
}

void FixedRandom(std::uint8_t* out, std::size_t len) { std::memset(out, 0xCD, len); }

std::int64_t AuthKeyIdAsInt64(const AuthKeyBytes& key) {
    const auto id = AuthKeyId(key);
    std::int64_t v;
    std::memcpy(&v, id.data(), 8);
    return v;
}

// Mirrors TestEncryptBindMessage byte-for-byte: same key-generation formula
// (255 - i), same fixed 0xCD random stream, same field values.
void TestEncryptBindMessageMatchesGoTestConstruction() {
    const AuthKeyBytes perm_key = MakeKey(255);
    const std::int64_t msg_id = 0x011223344556677;

    messages::BindAuthKeyInner inner;
    inner.nonce = 0x0001020304050607;
    inner.temp_auth_key_id = 0x0011223344556677;
    inner.perm_auth_key_id = AuthKeyIdAsInt64(perm_key);
    inner.temp_session_id = 0x010203040506070;
    inner.expires_at = 1735689600;

    const auto encrypted = EncryptBindMessage(perm_key, msg_id, inner, FixedRandom);

    EncryptedMessage msg;
    TLBuffer msg_buf;
    msg_buf.buf = encrypted;
    msg.Decode(msg_buf);
    Check(msg.auth_key_id == AuthKeyId(perm_key), "encrypted_message's auth_key_id is the permanent key's own id");
    Check(msg.encrypted_data.size() % 16 == 0, "encrypted_data is a whole number of AES blocks");

    std::vector<std::uint8_t> key, iv;
    KeysV1(perm_key, msg.msg_key, key, iv);
    const auto plaintext = IgeDecrypt(key, iv, msg.encrypted_data);
    // 16(random) + 8(msg_id) + 4(seq_no) + 4(len) + 40(bind_auth_key_inner)
    constexpr std::size_t kPrefixAndBodyLen = 16 + 8 + 4 + 4 + 40;
    Check(plaintext.size() >= kPrefixAndBodyLen, "decrypted plaintext holds at least the envelope + body");
    const std::vector<std::uint8_t> envelope(plaintext.begin(), plaintext.begin() + kPrefixAndBodyLen);
    Check(msg.msg_key == MessageKeyV1(envelope), "msg_key is SHA1(envelope-before-padding)[4:20]");

    TLBuffer b;
    b.buf = plaintext;
    std::uint8_t random_prefix[16];
    b.ConsumeN(random_prefix, 16);
    bool all_cd = true;
    for (auto c : random_prefix) all_cd &= (c == 0xCD);
    Check(all_cd, "the 16-byte random prefix is exactly the injected random stream");
    Check(b.Long() == msg_id, "envelope carries the given msg_id");
    Check(b.Int32() == 0, "envelope's seq_no is always 0");
    Check(b.Int32() == 40, "envelope's declared body length is bind_auth_key_inner's exact 40 bytes");

    b.ConsumeID(messages::BindAuthKeyInner::kTypeId);
    messages::BindAuthKeyInner decoded;
    decoded.DecodeBare(b);
    Check(decoded.nonce == inner.nonce && decoded.temp_auth_key_id == inner.temp_auth_key_id &&
              decoded.perm_auth_key_id == inner.perm_auth_key_id && decoded.temp_session_id == inner.temp_session_id &&
              decoded.expires_at == inner.expires_at,
          "decoded bind_auth_key_inner matches every field of the original");
}

// The function the server actually calls: prove it recovers exactly what
// EncryptBindMessage put in, independent of the manual decode above.
void TestDecryptBindAuthKeyInnerRoundTrip() {
    const AuthKeyBytes perm_key = MakeKey(0x77);
    messages::BindAuthKeyInner inner;
    inner.nonce = 42;
    inner.temp_auth_key_id = 1234567890123;
    inner.perm_auth_key_id = AuthKeyIdAsInt64(perm_key);
    inner.temp_session_id = 987654321;
    inner.expires_at = 1700000000;

    const auto encrypted = EncryptBindMessage(perm_key, /*msg_id=*/9999, inner, FixedRandom);
    const auto decrypted = DecryptBindAuthKeyInner(perm_key, encrypted);
    Check(decrypted.nonce == inner.nonce && decrypted.temp_auth_key_id == inner.temp_auth_key_id &&
              decrypted.perm_auth_key_id == inner.perm_auth_key_id &&
              decrypted.temp_session_id == inner.temp_session_id && decrypted.expires_at == inner.expires_at,
          "DecryptBindAuthKeyInner recovers exactly what EncryptBindMessage encrypted");
}

void TestDecryptRejectsTamperedCiphertext() {
    const AuthKeyBytes perm_key = MakeKey(0x11);
    messages::BindAuthKeyInner inner;
    inner.nonce = 1;
    inner.temp_auth_key_id = 2;
    inner.perm_auth_key_id = AuthKeyIdAsInt64(perm_key);
    inner.temp_session_id = 3;
    inner.expires_at = 1600000000;
    auto encrypted = EncryptBindMessage(perm_key, 1, inner, FixedRandom);

    encrypted.back() ^= 0x01; // flip one bit deep inside encrypted_data
    try {
        DecryptBindAuthKeyInner(perm_key, encrypted);
        Check(false, "decrypting a tampered envelope should throw");
    } catch (const BindEncryptedMessageInvalidError&) {
        Check(true, "tampered ciphertext is rejected via the msg_key integrity check");
    }
}

void TestDecryptRejectsWrongKey() {
    const AuthKeyBytes perm_key = MakeKey(0x22);
    const AuthKeyBytes wrong_key = MakeKey(0x33);
    messages::BindAuthKeyInner inner;
    inner.nonce = 1;
    inner.temp_auth_key_id = 2;
    inner.perm_auth_key_id = AuthKeyIdAsInt64(perm_key);
    inner.temp_session_id = 3;
    inner.expires_at = 1600000000;
    const auto encrypted = EncryptBindMessage(perm_key, 1, inner, FixedRandom);

    try {
        DecryptBindAuthKeyInner(wrong_key, encrypted);
        Check(false, "decrypting with the wrong permanent key should throw");
    } catch (const BindEncryptedMessageInvalidError&) {
        Check(true, "wrong key is rejected (auth_key_id mismatch, checked before touching AES)");
    }
}

void TestEncryptRejectsZeroKey() {
    AuthKeyBytes zero_key{};
    messages::BindAuthKeyInner inner;
    try {
        EncryptBindMessage(zero_key, 1, inner, FixedRandom);
        Check(false, "encrypting with an all-zero key should throw");
    } catch (const std::invalid_argument&) {
        Check(true, "EncryptBindMessage rejects an all-zero permanent key");
    }
}

} // namespace

int main() {
    TestEncryptBindMessageMatchesGoTestConstruction();
    TestDecryptBindAuthKeyInnerRoundTrip();
    TestDecryptRejectsTamperedCiphertext();
    TestDecryptRejectsWrongKey();
    TestEncryptRejectsZeroKey();
    if (g_failures == 0) {
        std::printf("all mtproto bind tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d mtproto bind test(s) failed\n", g_failures);
    return 1;
}
