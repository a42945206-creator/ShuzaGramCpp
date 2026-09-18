#include "shuzagram/mtproto/crypto/rsa_pad.hpp"

#include <algorithm>
#include <stdexcept>

#include <openssl/sha.h>

#include "shuzagram/mtproto/crypto/aes_ige.hpp"

namespace shuzagram::mtproto::crypto {

namespace {

constexpr std::size_t kDataWithPaddingLen = 192;
constexpr std::size_t kTempKeySize = 32; // AES-256 key
constexpr std::size_t kDataWithHashLen = kDataWithPaddingLen + SHA256_DIGEST_LENGTH; // 224

std::vector<std::uint8_t> Sha256(const std::vector<std::uint8_t>& data) {
    std::vector<std::uint8_t> out(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), out.data());
    return out;
}

std::vector<std::uint8_t> Concat(const std::vector<std::uint8_t>& a, const std::vector<std::uint8_t>& b) {
    std::vector<std::uint8_t> out;
    out.reserve(a.size() + b.size());
    out.insert(out.end(), a.begin(), a.end());
    out.insert(out.end(), b.begin(), b.end());
    return out;
}

std::vector<std::uint8_t> XorBytes(const std::vector<std::uint8_t>& a, const std::vector<std::uint8_t>& b) {
    std::vector<std::uint8_t> out(a.size());
    for (std::size_t i = 0; i < a.size(); ++i) out[i] = a[i] ^ b[i];
    return out;
}

void ReverseInPlace(std::vector<std::uint8_t>& v) { std::reverse(v.begin(), v.end()); }

// Compares two big-endian byte strings of equal length, both left-padded to
// kRsaByteLen conceptually (RSA moduli/ciphertexts here are already exactly
// that length in practice for a 2048-bit key).
bool GreaterOrEqual(const std::vector<std::uint8_t>& a, const std::vector<std::uint8_t>& b) {
    if (a.size() != b.size()) throw std::runtime_error("RSA_PAD modulus comparison length mismatch");
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (a[i] != b[i]) return a[i] > b[i];
    }
    return true; // equal
}

const std::vector<std::uint8_t>& ZeroIv32() {
    static const std::vector<std::uint8_t> kZero(32, 0);
    return kZero;
}

} // namespace

std::vector<std::uint8_t> RsaPad(const std::vector<std::uint8_t>& data, const RsaPublicKey& key,
                                  const RandomFill& rand) {
    if (data.size() > kRsaPadDataLimit) throw std::invalid_argument("RSA_PAD: data longer than 144 bytes");

    // 1) data_with_padding := data + random_padding_bytes, exactly 192 bytes.
    std::vector<std::uint8_t> data_with_padding(kDataWithPaddingLen, 0);
    std::copy(data.begin(), data.end(), data_with_padding.begin());
    rand(data_with_padding.data() + data.size(), kDataWithPaddingLen - data.size());

    // 2) data_pad_reversed := BYTE_REVERSE(data_with_padding).
    std::vector<std::uint8_t> data_pad_reversed = data_with_padding;
    ReverseInPlace(data_pad_reversed);

    for (;;) {
        // 3) A random 32-byte temp_key.
        std::vector<std::uint8_t> temp_key(kTempKeySize);
        rand(temp_key.data(), temp_key.size());

        // 4) data_with_hash := data_pad_reversed + SHA256(temp_key + data_with_padding).
        std::vector<std::uint8_t> data_with_hash =
            Concat(data_pad_reversed, Sha256(Concat(temp_key, data_with_padding)));
        // (Concat already yields exactly kDataWithHashLen == 192+32 bytes.)

        // 5) aes_encrypted := AES256_IGE(data_with_hash, temp_key, zero IV).
        std::vector<std::uint8_t> iv(32, 0);
        const std::vector<std::uint8_t> aes_encrypted = IgeEncrypt(temp_key, iv, data_with_hash);

        // 6) temp_key_xor := temp_key XOR SHA256(aes_encrypted).
        const std::vector<std::uint8_t> temp_key_xor = XorBytes(temp_key, Sha256(aes_encrypted));

        // 7) key_aes_encrypted := temp_key_xor + aes_encrypted, exactly 256 bytes.
        const std::vector<std::uint8_t> key_aes_encrypted = Concat(temp_key_xor, aes_encrypted);
        static_assert(kTempKeySize + kDataWithHashLen == kRsaByteLen);

        // 8) Reject and retry if key_aes_encrypted >= RSA modulus.
        if (GreaterOrEqual(key_aes_encrypted, key.N())) continue;

        // 9) encrypted_data := RSA(key_aes_encrypted, server_pubkey).
        return key.EncryptRaw(key_aes_encrypted);
    }
}

std::vector<std::uint8_t> RsaUnpad(const std::vector<std::uint8_t>& data, const RsaPrivateKey& key) {
    const std::vector<std::uint8_t> encrypted_data = key.DecryptRaw(data);

    const std::vector<std::uint8_t> temp_key_xor(encrypted_data.begin(),
                                                   encrypted_data.begin() + kTempKeySize);
    const std::vector<std::uint8_t> aes_encrypted(encrypted_data.begin() + kTempKeySize, encrypted_data.end());

    const std::vector<std::uint8_t> temp_key = XorBytes(temp_key_xor, Sha256(aes_encrypted));

    const std::vector<std::uint8_t> data_with_hash = IgeDecrypt(temp_key, ZeroIv32(), aes_encrypted);

    std::vector<std::uint8_t> data_with_padding(data_with_hash.begin(),
                                                  data_with_hash.begin() + kDataWithPaddingLen);
    ReverseInPlace(data_with_padding);

    const std::vector<std::uint8_t> hash(data_with_hash.begin() + kDataWithPaddingLen, data_with_hash.end());
    if (hash != Sha256(Concat(temp_key, data_with_padding))) {
        throw std::runtime_error("RSA_PAD: hash mismatch (wrong key or corrupted data)");
    }
    return data_with_padding;
}

} // namespace shuzagram::mtproto::crypto
