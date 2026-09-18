#include "shuzagram/mtproto/crypto/bind.hpp"

#include <algorithm>
#include <stdexcept>

#include "shuzagram/mtproto/crypto/aes_ige.hpp"
#include "shuzagram/mtproto/crypto/kdf_v1.hpp"

// Ported from gotd/td's crypto/bind.go (EncryptBindMessage) and
// internal/app/auth/service.go's decryptBindAuthKeyInner.
namespace shuzagram::mtproto::crypto {

namespace {

constexpr std::size_t kBlockSize = 16;
// random(16) + msg_id(8) + seq_no(4) + msg_len(4), all before the payload.
constexpr std::size_t kEnvelopeHeaderLen = 16 + 8 + 4 + 4;

} // namespace

std::vector<std::uint8_t> EncryptBindMessage(const AuthKeyBytes& perm_key, std::int64_t msg_id,
                                              const messages::BindAuthKeyInner& inner, const RandomFill& rand) {
    if (std::all_of(perm_key.begin(), perm_key.end(), [](std::uint8_t b) { return b == 0; })) {
        throw std::invalid_argument("permanent key is zero");
    }

    TLBuffer payload;
    inner.Encode(payload);

    TLBuffer plaintext;
    std::uint8_t random_prefix[16];
    rand(random_prefix, sizeof(random_prefix));
    plaintext.Put(random_prefix, sizeof(random_prefix));
    plaintext.PutLong(msg_id);
    plaintext.PutInt32(0); // seq_no is always 0 for this envelope
    plaintext.PutInt32(static_cast<std::int32_t>(payload.buf.size()));
    plaintext.Put(payload.buf);

    // msg_key is computed over the envelope BEFORE random padding is
    // appended -- the padding itself carries no information to authenticate.
    const Int128 msg_key = MessageKeyV1(plaintext.buf);

    const std::size_t rem = plaintext.buf.size() % kBlockSize;
    if (rem != 0) {
        const std::size_t padding_len = kBlockSize - rem;
        const std::size_t offset = plaintext.buf.size();
        plaintext.buf.resize(offset + padding_len);
        rand(plaintext.buf.data() + offset, padding_len);
    }

    std::vector<std::uint8_t> key, iv;
    KeysV1(perm_key, msg_key, key, iv);

    EncryptedMessage msg;
    msg.auth_key_id = AuthKeyId(perm_key);
    msg.msg_key = msg_key;
    msg.encrypted_data = IgeEncrypt(key, iv, plaintext.buf);

    TLBuffer out;
    msg.Encode(out);
    return out.buf;
}

messages::BindAuthKeyInner DecryptBindAuthKeyInner(const AuthKeyBytes& perm_key,
                                                    const std::vector<std::uint8_t>& encrypted_message) {
    EncryptedMessage msg;
    try {
        TLBuffer b;
        b.buf = encrypted_message;
        msg.Decode(b);
    } catch (const std::exception&) {
        throw BindEncryptedMessageInvalidError();
    }
    if (msg.auth_key_id != AuthKeyId(perm_key) || msg.encrypted_data.empty() ||
        msg.encrypted_data.size() % kBlockSize != 0) {
        throw BindEncryptedMessageInvalidError();
    }

    std::vector<std::uint8_t> key, iv;
    KeysV1(perm_key, msg.msg_key, key, iv);
    const std::vector<std::uint8_t> plaintext = IgeDecrypt(key, iv, msg.encrypted_data);
    if (plaintext.size() < kEnvelopeHeaderLen) throw BindEncryptedMessageInvalidError();

    try {
        TLBuffer b;
        b.buf = plaintext;
        std::uint8_t random_prefix[16];
        b.ConsumeN(random_prefix, sizeof(random_prefix));
        b.Long();  // msg_id: not checked -- see the header comment on this
                   // function and NOTES/bind-temp-auth-key-plan.md.
        b.Int32(); // seq_no: always 0, not checked either.
        const std::int32_t msg_len = b.Int32();
        if (msg_len <= 0) throw BindEncryptedMessageInvalidError();

        const std::size_t body_end = kEnvelopeHeaderLen + static_cast<std::size_t>(msg_len);
        if (body_end > plaintext.size()) throw BindEncryptedMessageInvalidError();
        if (msg.msg_key != MessageKeyV1(std::vector<std::uint8_t>(plaintext.begin(), plaintext.begin() + static_cast<long>(body_end)))) {
            throw BindEncryptedMessageInvalidError();
        }

        TLBuffer body;
        body.buf.assign(plaintext.begin() + static_cast<long>(kEnvelopeHeaderLen), plaintext.begin() + static_cast<long>(body_end));
        if (body.PeekID() != messages::BindAuthKeyInner::kTypeId) throw BindEncryptedMessageInvalidError();
        body.ConsumeID(messages::BindAuthKeyInner::kTypeId);
        messages::BindAuthKeyInner inner;
        inner.DecodeBare(body);
        return inner;
    } catch (const BindEncryptedMessageInvalidError&) {
        throw;
    } catch (const std::exception&) {
        throw BindEncryptedMessageInvalidError();
    }
}

} // namespace shuzagram::mtproto::crypto
