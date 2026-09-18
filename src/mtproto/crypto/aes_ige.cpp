#include "shuzagram/mtproto/crypto/aes_ige.hpp"

#include <stdexcept>

#include <openssl/evp.h>

namespace shuzagram::mtproto::crypto {

namespace {

constexpr std::size_t kBlockSize = 16;

// OpenSSL has no built-in IGE mode, so this uses EVP's ECB cipher purely as
// a single-block AES primitive (padding disabled, one block per call) and
// implements the IGE chaining by hand, exactly like gotd/ige does against
// Go's block cipher.Block interface.
class RawAesBlock {
public:
    RawAesBlock(const std::vector<std::uint8_t>& key, bool encrypt) : encrypt_(encrypt) {
        const EVP_CIPHER* cipher = nullptr;
        switch (key.size()) {
            case 16: cipher = EVP_aes_128_ecb(); break;
            case 24: cipher = EVP_aes_192_ecb(); break;
            case 32: cipher = EVP_aes_256_ecb(); break;
            default: throw std::invalid_argument("AES key must be 16, 24 or 32 bytes");
        }
        ctx_ = EVP_CIPHER_CTX_new();
        if (!ctx_) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
        const int ok = encrypt ? EVP_EncryptInit_ex(ctx_, cipher, nullptr, key.data(), nullptr)
                                : EVP_DecryptInit_ex(ctx_, cipher, nullptr, key.data(), nullptr);
        if (!ok) {
            EVP_CIPHER_CTX_free(ctx_);
            throw std::runtime_error("EVP cipher init failed");
        }
        EVP_CIPHER_CTX_set_padding(ctx_, 0);
    }

    ~RawAesBlock() { EVP_CIPHER_CTX_free(ctx_); }

    RawAesBlock(const RawAesBlock&) = delete;
    RawAesBlock& operator=(const RawAesBlock&) = delete;

    void Crypt(const std::uint8_t* in, std::uint8_t* out) {
        int out_len = 0;
        const int ok = encrypt_ ? EVP_EncryptUpdate(ctx_, out, &out_len, in, static_cast<int>(kBlockSize))
                                 : EVP_DecryptUpdate(ctx_, out, &out_len, in, static_cast<int>(kBlockSize));
        if (!ok || out_len != static_cast<int>(kBlockSize)) throw std::runtime_error("AES block operation failed");
    }

private:
    EVP_CIPHER_CTX* ctx_;
    bool encrypt_;
};

void XorBlock(std::uint8_t* dst, const std::uint8_t* a, const std::uint8_t* b) {
    for (std::size_t i = 0; i < kBlockSize; ++i) dst[i] = a[i] ^ b[i];
}

void CheckIgeArgs(const std::vector<std::uint8_t>& iv, const std::vector<std::uint8_t>& data) {
    if (iv.size() != 2 * kBlockSize) throw std::invalid_argument("IGE iv must be 32 bytes (two block IVs)");
    if (data.size() % kBlockSize != 0) throw std::invalid_argument("IGE data must be a multiple of the block size");
}

} // namespace

std::vector<std::uint8_t> IgeEncrypt(const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& iv,
                                      const std::vector<std::uint8_t>& data) {
    CheckIgeArgs(iv, data);
    RawAesBlock cipher(key, /*encrypt=*/true);
    std::vector<std::uint8_t> out(data.size());

    // c/m start as the two halves of iv; after each block, c becomes this
    // block's ciphertext and m becomes this block's plaintext (encrypt.go).
    std::uint8_t c[kBlockSize];
    std::uint8_t m[kBlockSize];
    std::copy(iv.begin(), iv.begin() + kBlockSize, c);
    std::copy(iv.begin() + kBlockSize, iv.end(), m);

    for (std::size_t o = 0; o < data.size(); o += kBlockSize) {
        std::uint8_t block[kBlockSize];
        XorBlock(block, data.data() + o, c);
        cipher.Crypt(block, block);
        XorBlock(out.data() + o, block, m);

        std::copy(out.begin() + static_cast<long>(o), out.begin() + static_cast<long>(o + kBlockSize), c);
        std::copy(data.begin() + static_cast<long>(o), data.begin() + static_cast<long>(o + kBlockSize), m);
    }
    return out;
}

std::vector<std::uint8_t> IgeDecrypt(const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& iv,
                                      const std::vector<std::uint8_t>& data) {
    CheckIgeArgs(iv, data);
    RawAesBlock cipher(key, /*encrypt=*/false);
    std::vector<std::uint8_t> out(data.size());

    std::uint8_t c[kBlockSize];
    std::uint8_t m[kBlockSize];
    std::copy(iv.begin(), iv.begin() + kBlockSize, c);
    std::copy(iv.begin() + kBlockSize, iv.end(), m);

    for (std::size_t o = 0; o < data.size(); o += kBlockSize) {
        std::uint8_t t[kBlockSize];
        std::copy(data.begin() + static_cast<long>(o), data.begin() + static_cast<long>(o + kBlockSize), t);

        std::uint8_t block[kBlockSize];
        XorBlock(block, data.data() + o, m);
        cipher.Crypt(block, block);
        XorBlock(out.data() + o, block, c);

        std::copy(out.begin() + static_cast<long>(o), out.begin() + static_cast<long>(o + kBlockSize), m);
        std::copy(t, t + kBlockSize, c);
    }
    return out;
}

} // namespace shuzagram::mtproto::crypto
