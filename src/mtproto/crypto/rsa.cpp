#include "shuzagram/mtproto/crypto/rsa.hpp"

#include <cstdio>
#include <memory>
#include <stdexcept>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include "shuzagram/mtproto/tl_buffer.hpp"

namespace shuzagram::mtproto::crypto {

namespace {

using BignumPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using CtxPtr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;
using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;

BignumPtr MakeBignum() { return {BN_new(), &BN_free}; }

BignumPtr BytesToBignum(const std::vector<std::uint8_t>& b) {
    BignumPtr bn = MakeBignum();
    if (!BN_bin2bn(b.data(), static_cast<int>(b.size()), bn.get())) {
        throw std::runtime_error("BN_bin2bn failed");
    }
    return bn;
}

std::vector<std::uint8_t> BignumToBytes(const BIGNUM* bn, std::size_t fixed_len) {
    std::vector<std::uint8_t> out(fixed_len);
    if (BN_num_bytes(bn) > static_cast<int>(fixed_len)) {
        throw std::runtime_error("RSA raw transform result does not fit in the expected length");
    }
    if (!BN_bn2binpad(bn, out.data(), static_cast<int>(fixed_len))) {
        throw std::runtime_error("BN_bn2binpad failed");
    }
    return out;
}

// z^e mod n (or c^d mod n) via OpenSSL BIGNUM, padded/checked to fixed_len
// bytes -- the shared implementation of both RsaPublicKey::EncryptRaw and
// RsaPrivateKey::DecryptRaw (rsaEncrypt/rsaDecrypt in gotd/td's crypto/rsa.go).
std::vector<std::uint8_t> ModExp(const std::vector<std::uint8_t>& base, const std::vector<std::uint8_t>& exponent,
                                  const std::vector<std::uint8_t>& modulus, std::size_t fixed_len) {
    CtxPtr ctx(BN_CTX_new(), &BN_CTX_free);
    BignumPtr b = BytesToBignum(base);
    BignumPtr e = BytesToBignum(exponent);
    BignumPtr n = BytesToBignum(modulus);
    BignumPtr result = MakeBignum();
    if (!BN_mod_exp(result.get(), b.get(), e.get(), n.get(), ctx.get())) {
        throw std::runtime_error("BN_mod_exp failed");
    }
    return BignumToBytes(result.get(), fixed_len);
}

std::vector<std::uint8_t> GetBnParamBytes(EVP_PKEY* pkey, const char* param_name) {
    BIGNUM* raw = nullptr;
    if (!EVP_PKEY_get_bn_param(pkey, param_name, &raw)) {
        throw std::runtime_error(std::string("EVP_PKEY_get_bn_param(") + param_name + ") failed");
    }
    BignumPtr bn(raw, &BN_free);
    std::vector<std::uint8_t> out(static_cast<std::size_t>(BN_num_bytes(bn.get())));
    BN_bn2bin(bn.get(), out.data());
    return out;
}

} // namespace

RsaPublicKey::RsaPublicKey(std::vector<std::uint8_t> n, std::vector<std::uint8_t> e)
    : n_(std::move(n)), e_(std::move(e)) {}

namespace {

// Minimal DER reader for RSAPublicKey ::= SEQUENCE { modulus INTEGER,
// publicExponent INTEGER } -- exactly the two fields this project needs,
// nothing else in the ASN.1/X.509 universe.
class DerReader {
public:
    DerReader(const unsigned char* data, long len) : p_(data), len_(static_cast<std::size_t>(len)) {}

    std::uint8_t ReadTag() {
        if (pos_ >= len_) throw std::runtime_error("DER: unexpected end reading tag");
        return p_[pos_++];
    }

    std::size_t ReadLength() {
        const std::uint8_t first = ReadTag();
        if (first < 0x80) return first;
        const int n = first & 0x7F;
        std::size_t out = 0;
        for (int i = 0; i < n; ++i) out = (out << 8) | ReadTag();
        return out;
    }

    std::vector<std::uint8_t> ReadInteger() {
        if (ReadTag() != 0x02) throw std::runtime_error("DER: expected INTEGER tag");
        const std::size_t len = ReadLength();
        if (pos_ + len > len_) throw std::runtime_error("DER: INTEGER length exceeds buffer");
        std::size_t start = pos_;
        std::size_t n = len;
        // Strip the leading zero byte ASN.1 DER adds when the high bit of
        // the first real byte would otherwise be mistaken for a sign bit.
        if (n > 1 && p_[start] == 0x00) {
            ++start;
            --n;
        }
        std::vector<std::uint8_t> out(p_ + start, p_ + start + n);
        pos_ += len;
        return out;
    }

    void EnterSequence() {
        if (ReadTag() != 0x30) throw std::runtime_error("DER: expected SEQUENCE tag");
        ReadLength(); // outer length, unused: contents are read to the end anyway
    }

private:
    const unsigned char* p_;
    std::size_t len_;
    std::size_t pos_ = 0;
};

} // namespace

RsaPublicKey RsaPublicKey::FromPkcs1Pem(const std::string& pem) {
    BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), &BIO_free);
    char* name = nullptr;
    char* header = nullptr;
    unsigned char* der = nullptr;
    long der_len = 0;
    if (!PEM_read_bio(bio.get(), &name, &header, &der, &der_len)) {
        throw std::runtime_error("failed to parse RSA public key PEM framing");
    }
    OPENSSL_free(name);
    OPENSSL_free(header);
    struct DerFree {
        void operator()(unsigned char* p) const { OPENSSL_free(p); }
    };
    std::unique_ptr<unsigned char, DerFree> der_guard(der);

    DerReader reader(der, der_len);
    reader.EnterSequence();
    std::vector<std::uint8_t> n = reader.ReadInteger();
    std::vector<std::uint8_t> e = reader.ReadInteger();
    return RsaPublicKey(std::move(n), std::move(e));
}

std::vector<std::uint8_t> RsaPublicKey::EncryptRaw(const std::vector<std::uint8_t>& data) const {
    return ModExp(data, e_, n_, kRsaByteLen);
}

std::int64_t RsaPublicKey::Fingerprint() const {
    // rsa_public_key#... n:string e:string = RSAPublicKey (bare TL); fingerprint
    // is SHA1 of that serialization, low 8 bytes read little-endian
    // (crypto/rsa_fingerprint.go). TL `bytes` here must carry n/e without a
    // leading zero sign byte -- BignumToBytes-free vectors already come from
    // BN_bn2bin, which never adds one, matching Go's big.Int.Bytes().
    TLBuffer buf;
    buf.PutBytes(n_);
    buf.PutBytes(e_);
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1(buf.buf.data(), buf.buf.size(), digest);
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<std::uint64_t>(digest[12 + i]) << (8 * i);
    return static_cast<std::int64_t>(v);
}

RsaPrivateKey RsaPrivateKey::Generate(int bits) {
    PkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr), &EVP_PKEY_CTX_free);
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) <= 0) {
        throw std::runtime_error("failed to initialize RSA keygen");
    }
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_generate(ctx.get(), &raw) <= 0) throw std::runtime_error("RSA key generation failed");
    PkeyPtr pkey(raw, &EVP_PKEY_free);

    return RsaPrivateKey(
        GetBnParamBytes(pkey.get(), OSSL_PKEY_PARAM_RSA_N), GetBnParamBytes(pkey.get(), OSSL_PKEY_PARAM_RSA_E),
        GetBnParamBytes(pkey.get(), OSSL_PKEY_PARAM_RSA_D), GetBnParamBytes(pkey.get(), OSSL_PKEY_PARAM_RSA_FACTOR1),
        GetBnParamBytes(pkey.get(), OSSL_PKEY_PARAM_RSA_FACTOR2),
        GetBnParamBytes(pkey.get(), OSSL_PKEY_PARAM_RSA_EXPONENT1),
        GetBnParamBytes(pkey.get(), OSSL_PKEY_PARAM_RSA_EXPONENT2),
        GetBnParamBytes(pkey.get(), OSSL_PKEY_PARAM_RSA_COEFFICIENT1));
}

RsaPrivateKey RsaPrivateKey::FromPkcs1Pem(const std::string& pem) {
    BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), &BIO_free);
    EVP_PKEY* raw = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
    if (!raw) throw std::runtime_error("failed to parse RSA private key PEM");
    PkeyPtr pkey(raw, &EVP_PKEY_free);
    return RsaPrivateKey(
        GetBnParamBytes(pkey.get(), OSSL_PKEY_PARAM_RSA_N), GetBnParamBytes(pkey.get(), OSSL_PKEY_PARAM_RSA_E),
        GetBnParamBytes(pkey.get(), OSSL_PKEY_PARAM_RSA_D), GetBnParamBytes(pkey.get(), OSSL_PKEY_PARAM_RSA_FACTOR1),
        GetBnParamBytes(pkey.get(), OSSL_PKEY_PARAM_RSA_FACTOR2),
        GetBnParamBytes(pkey.get(), OSSL_PKEY_PARAM_RSA_EXPONENT1),
        GetBnParamBytes(pkey.get(), OSSL_PKEY_PARAM_RSA_EXPONENT2),
        GetBnParamBytes(pkey.get(), OSSL_PKEY_PARAM_RSA_COEFFICIENT1));
}

std::string RsaPrivateKey::ToPkcs1Pem() const {
    // Rebuild an EVP_PKEY from the raw components to hand to the PEM
    // writer. p/q/dP/dQ/qInv (the CRT parameters) must all be present:
    // OpenSSL's *traditional* PKCS#1 encoder treats a zero/absent CRT field
    // as malformed ("illegal zero content"), not as "recompute it" -- even
    // though nothing in this class ever uses them (every private-key
    // operation here is a single BN_mod_exp with n/d, see DecryptRaw).
    PkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr), &EVP_PKEY_CTX_free);
    BignumPtr n = BytesToBignum(n_);
    BignumPtr e = BytesToBignum(e_);
    BignumPtr d = BytesToBignum(d_);
    BignumPtr p = BytesToBignum(p_);
    BignumPtr q = BytesToBignum(q_);
    BignumPtr dp = BytesToBignum(dp_);
    BignumPtr dq = BytesToBignum(dq_);
    BignumPtr qinv = BytesToBignum(qinv_);

    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n.get());
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e.get());
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, d.get());
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR1, p.get());
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR2, q.get());
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT1, dp.get());
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT2, dq.get());
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, qinv.get());
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);

    EVP_PKEY* raw = nullptr;
    if (!ctx || EVP_PKEY_fromdata_init(ctx.get()) <= 0 ||
        EVP_PKEY_fromdata(ctx.get(), &raw, EVP_PKEY_KEYPAIR, params) <= 0) {
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(bld);
        throw std::runtime_error("failed to rebuild RSA key for PEM export");
    }
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    PkeyPtr pkey(raw, &EVP_PKEY_free);

    BioPtr bio(BIO_new(BIO_s_mem()), &BIO_free);
    if (!PEM_write_bio_PrivateKey_traditional(bio.get(), pkey.get(), nullptr, nullptr, 0, nullptr, nullptr)) {
        throw std::runtime_error("failed to write RSA private key PEM");
    }
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio.get(), &data);
    return std::string(data, static_cast<std::size_t>(len));
}

RsaPrivateKey RsaPrivateKey::LoadOrGenerate(const std::string& path) {
    if (FILE* f = std::fopen(path.c_str(), "rb")) {
        std::string pem;
        char chunk[4096];
        std::size_t n;
        while ((n = std::fread(chunk, 1, sizeof(chunk), f)) > 0) pem.append(chunk, n);
        std::fclose(f);
        return FromPkcs1Pem(pem);
    }
    RsaPrivateKey key = Generate(kRsaKeyBits);
    const std::string pem = key.ToPkcs1Pem();
    if (FILE* f = std::fopen(path.c_str(), "wb")) {
        std::fwrite(pem.data(), 1, pem.size(), f);
        std::fclose(f);
    } else {
        throw std::runtime_error("failed to write RSA key to " + path);
    }
    return key;
}

RsaPublicKey RsaPrivateKey::PublicKey() const { return RsaPublicKey(n_, e_); }

std::vector<std::uint8_t> RsaPrivateKey::DecryptRaw(const std::vector<std::uint8_t>& data) const {
    return ModExp(data, d_, n_, kRsaByteLen);
}

} // namespace shuzagram::mtproto::crypto
