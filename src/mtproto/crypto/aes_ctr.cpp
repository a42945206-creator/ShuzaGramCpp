#include "shuzagram/mtproto/crypto/aes_ctr.hpp"

#include <openssl/evp.h>

#include <stdexcept>
#include <utility>

namespace shuzagram::mtproto::crypto {

struct Aes256CtrStream::Impl {
    EVP_CIPHER_CTX* ctx = nullptr;
};

Aes256CtrStream::Aes256CtrStream(const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& iv)
    : impl_(new Impl) {
    if (key.size() != 32) throw std::runtime_error("Aes256CtrStream: key must be 32 bytes");
    if (iv.size() != 16) throw std::runtime_error("Aes256CtrStream: iv must be 16 bytes");

    impl_->ctx = EVP_CIPHER_CTX_new();
    if (!impl_->ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    if (EVP_EncryptInit_ex(impl_->ctx, EVP_aes_256_ctr(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(impl_->ctx);
        throw std::runtime_error("EVP_EncryptInit_ex(aes-256-ctr) failed");
    }
}

Aes256CtrStream::~Aes256CtrStream() {
    if (impl_) {
        if (impl_->ctx) EVP_CIPHER_CTX_free(impl_->ctx);
        delete impl_;
    }
}

Aes256CtrStream::Aes256CtrStream(Aes256CtrStream&& other) noexcept : impl_(std::exchange(other.impl_, nullptr)) {}

Aes256CtrStream& Aes256CtrStream::operator=(Aes256CtrStream&& other) noexcept {
    if (this != &other) {
        if (impl_) {
            if (impl_->ctx) EVP_CIPHER_CTX_free(impl_->ctx);
            delete impl_;
        }
        impl_ = std::exchange(other.impl_, nullptr);
    }
    return *this;
}

void Aes256CtrStream::XorKeyStream(std::uint8_t* dst, const std::uint8_t* src, std::size_t len) {
    if (len == 0) return;
    int out_len = 0;
    // CTR is a genuine stream cipher in OpenSSL: EVP_EncryptUpdate here never
    // buffers a partial block internally between calls (unlike CBC/ECB) --
    // every input byte becomes an output byte immediately, which is exactly
    // the "keystream position keeps advancing across calls" behavior
    // XorKeyStream needs. In-place (dst == src) is explicitly supported by
    // OpenSSL for stream modes.
    if (EVP_EncryptUpdate(impl_->ctx, dst, &out_len, src, static_cast<int>(len)) != 1) {
        throw std::runtime_error("EVP_EncryptUpdate(aes-256-ctr) failed");
    }
}

} // namespace shuzagram::mtproto::crypto
