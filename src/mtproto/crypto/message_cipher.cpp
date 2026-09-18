#include "shuzagram/mtproto/crypto/message_cipher.hpp"

#include <cstring>
#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "shuzagram/mtproto/crypto/aes_ige.hpp"

namespace shuzagram::mtproto::crypto {

namespace {

int SideOffset(Side side) { return side == Side::kClient ? 0 : 8; }

std::array<std::uint8_t, 20> Sha1(const std::uint8_t* data, std::size_t len) {
    std::array<std::uint8_t, 20> out{};
    SHA1(data, len, out.data());
    return out;
}

std::array<std::uint8_t, 32> Sha256TwoPart(const std::uint8_t* a, std::size_t a_len, const std::uint8_t* b,
                                            std::size_t b_len) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    std::array<std::uint8_t, 32> out{};
    unsigned int out_len = 0;
    const bool ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) && EVP_DigestUpdate(ctx, a, a_len) &&
                     EVP_DigestUpdate(ctx, b, b_len) && EVP_DigestFinal_ex(ctx, out.data(), &out_len);
    if (ctx) EVP_MD_CTX_free(ctx);
    if (!ok) throw std::runtime_error("SHA256 (two-part) failed");
    return out;
}

// sha256_a = SHA256(msg_key + substr(auth_key, x, 36))
std::array<std::uint8_t, 32> Sha256A(const AuthKeyBytes& auth_key, const Int128& msg_key, int x) {
    return Sha256TwoPart(msg_key.data(), msg_key.size(), auth_key.data() + x, 36);
}
// sha256_b = SHA256(substr(auth_key, 40+x, 36) + msg_key)
std::array<std::uint8_t, 32> Sha256B(const AuthKeyBytes& auth_key, const Int128& msg_key, int x) {
    return Sha256TwoPart(auth_key.data() + 40 + x, 36, msg_key.data(), msg_key.size());
}

void ComposeKeyOrIv(const std::array<std::uint8_t, 32>& a, const std::array<std::uint8_t, 32>& b,
                     std::vector<std::uint8_t>& out) {
    // substr(a,0,8) + substr(b,8,16) + substr(a,24,8)
    out.assign(a.begin(), a.begin() + 8);
    out.insert(out.end(), b.begin() + 8, b.begin() + 24);
    out.insert(out.end(), a.begin() + 24, a.begin() + 32);
}

} // namespace

std::array<std::uint8_t, 8> AuthKeyId(const AuthKeyBytes& auth_key) {
    const auto digest = Sha1(auth_key.data(), auth_key.size());
    std::array<std::uint8_t, 8> out{};
    std::copy(digest.begin() + 12, digest.end(), out.begin());
    return out;
}

std::array<std::uint8_t, 8> AuthKeyAuxHash(const AuthKeyBytes& auth_key) {
    const auto digest = Sha1(auth_key.data(), auth_key.size());
    std::array<std::uint8_t, 8> out{};
    std::copy(digest.begin(), digest.begin() + 8, out.begin());
    return out;
}

Int128 MessageKey(const AuthKeyBytes& auth_key, const std::vector<std::uint8_t>& plaintext_padded, Side side) {
    const int x = SideOffset(side);
    // msg_key_large = SHA256(substr(auth_key, 88+x, 32) + plaintext_padded)
    const auto large = Sha256TwoPart(auth_key.data() + 88 + x, 32, plaintext_padded.data(), plaintext_padded.size());
    Int128 out{};
    std::copy(large.begin() + 8, large.begin() + 24, out.begin());
    return out;
}

void DeriveMessageKeys(const AuthKeyBytes& auth_key, const Int128& msg_key, Side side, std::vector<std::uint8_t>& key,
                        std::vector<std::uint8_t>& iv) {
    const int x = SideOffset(side);
    const auto a = Sha256A(auth_key, msg_key, x);
    const auto b = Sha256B(auth_key, msg_key, x);
    ComposeKeyOrIv(a, b, key);
    ComposeKeyOrIv(b, a, iv); // aes_iv swaps the (a, b) argument order vs. aes_key
}

int CountPadding(int plaintext_len, std::uint8_t rand_byte) {
    int padding = (16 - (plaintext_len % 16)) % 16;
    if (padding < 12) padding += 16;
    padding += (rand_byte & 0x0F) * 16;
    return padding;
}

void EncryptedMessage::Encode(TLBuffer& b) const {
    b.Put(auth_key_id.data(), auth_key_id.size());
    b.PutInt128(msg_key);
    b.Put(encrypted_data.data(), encrypted_data.size());
}

void EncryptedMessage::Decode(TLBuffer& b) {
    if (b.buf.size() < 24) throw BufferUnderrunError();
    std::memcpy(auth_key_id.data(), b.buf.data(), 8);
    b.buf.erase(b.buf.begin(), b.buf.begin() + 8);
    msg_key = b.GetInt128();
    encrypted_data = std::move(b.buf);
    b.buf.clear();
}

EncryptedMessage EncryptMessage(const AuthKeyBytes& auth_key, std::int64_t salt, std::int64_t session_id,
                                 std::int64_t message_id, std::int32_t seq_no,
                                 const std::vector<std::uint8_t>& message_data, Side encrypt_as,
                                 const RandomFill& rand) {
    TLBuffer plaintext;
    plaintext.PutLong(salt);
    plaintext.PutLong(session_id);
    plaintext.PutLong(message_id);
    plaintext.PutInt32(seq_no);
    plaintext.PutInt32(static_cast<std::int32_t>(message_data.size()));
    plaintext.Put(message_data.data(), message_data.size());

    const std::size_t offset = plaintext.buf.size();
    std::uint8_t rand_byte;
    rand(&rand_byte, 1);
    const int padding = CountPadding(static_cast<int>(offset), rand_byte);
    plaintext.buf.resize(offset + static_cast<std::size_t>(padding));
    rand(plaintext.buf.data() + offset, static_cast<std::size_t>(padding));

    const Int128 msg_key = MessageKey(auth_key, plaintext.buf, encrypt_as);
    std::vector<std::uint8_t> key, iv;
    DeriveMessageKeys(auth_key, msg_key, encrypt_as, key, iv);

    EncryptedMessage out;
    out.auth_key_id = AuthKeyId(auth_key);
    out.msg_key = msg_key;
    out.encrypted_data = IgeEncrypt(key, iv, plaintext.buf);
    return out;
}

EncryptedMessageData DecryptMessage(const AuthKeyBytes& auth_key, const EncryptedMessage& encrypted,
                                     Side decrypt_as) {
    if (encrypted.auth_key_id != AuthKeyId(auth_key)) throw std::runtime_error("unknown auth key id");
    if (encrypted.encrypted_data.size() % 16 != 0) throw std::runtime_error("invalid encrypted data padding");

    const Side sender_side = OppositeSide(decrypt_as);
    std::vector<std::uint8_t> key, iv;
    DeriveMessageKeys(auth_key, encrypted.msg_key, sender_side, key, iv);
    const std::vector<std::uint8_t> plaintext = IgeDecrypt(key, iv, encrypted.encrypted_data);

    if (MessageKey(auth_key, plaintext, sender_side) != encrypted.msg_key) {
        throw std::runtime_error("msg_key is invalid");
    }

    if (plaintext.size() < 32) throw std::runtime_error("encrypted message data too short");
    TLBuffer b;
    b.buf = plaintext;
    EncryptedMessageData out;
    out.salt = b.Long();
    out.session_id = b.Long();
    out.message_id = b.Long();
    out.seq_no = b.Int32();
    const std::int32_t message_data_len = b.Int32();

    constexpr std::int32_t kMaxPadding = 1024;
    const auto remaining = static_cast<std::int32_t>(b.buf.size());
    if (message_data_len < 0) throw std::runtime_error("message length is invalid: negative");
    if (message_data_len % 4 != 0) throw std::runtime_error("message length is invalid: not divisible by 4");
    if (message_data_len > remaining) throw std::runtime_error("message length exceeds available data");
    if (remaining - message_data_len > kMaxPadding) throw std::runtime_error("padding of message is too big");

    out.message_data.assign(b.buf.begin(), b.buf.begin() + message_data_len);
    return out;
}

} // namespace shuzagram::mtproto::crypto
