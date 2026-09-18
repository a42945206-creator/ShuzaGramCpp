#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

// Port of the RSA pieces of internal/mtprotoedge/rsakey.go (server key
// load/generate) and gotd/td's crypto/rsa.go + crypto/rsa_fingerprint.go
// (raw MTProto RSA transform + fingerprint).
//
// MTProto's RSA is deliberately NOT PKCS#1/OAEP: it's the bare modular
// exponentiation (z^e mod n / c^d mod n) with MTProto's own RSA_PAD padding
// scheme layered on top separately (see rsa_pad.hpp). Built on OpenSSL's
// modern EVP_PKEY + BIGNUM APIs (no deprecated low-level RSA_* calls).
namespace shuzagram::mtproto::crypto {

// RSAKeyBits: MTProto requires a 2048-bit server key.
inline constexpr int kRsaKeyBits = 2048;
// Raw transform input/output is always exactly this many bytes (256 = 2048 bits).
inline constexpr std::size_t kRsaByteLen = kRsaKeyBits / 8;

class BigNum; // opaque RAII BIGNUM* wrapper, defined in the .cpp

class RsaPublicKey {
public:
    RsaPublicKey(std::vector<std::uint8_t> n, std::vector<std::uint8_t> e);

    // Parses a PKCS#1 "RSA PUBLIC KEY" PEM block (the format Telegram's own
    // public keys, and this project's test fixtures, ship in) -- a bare DER
    // SEQUENCE { modulus INTEGER, publicExponent INTEGER }, hand-decoded
    // rather than via OpenSSL's legacy RSA* type. PEM framing/base64 still
    // goes through OpenSSL's (non-deprecated) generic PEM_read_bio.
    static RsaPublicKey FromPkcs1Pem(const std::string& pem);

    // z^e mod n, result padded to exactly kRsaByteLen bytes.
    std::vector<std::uint8_t> EncryptRaw(const std::vector<std::uint8_t>& data) const;

    // MTProto's RSAFingerprint: SHA1(TL-serialized (n, e))[12:20] as a
    // little-endian int64.
    std::int64_t Fingerprint() const;

    const std::vector<std::uint8_t>& N() const { return n_; }
    const std::vector<std::uint8_t>& E() const { return e_; }

private:
    std::vector<std::uint8_t> n_;
    std::vector<std::uint8_t> e_;
};

class RsaPrivateKey {
public:
    static RsaPrivateKey Generate(int bits = kRsaKeyBits);

    // Parses a PKCS#1 "RSA PRIVATE KEY" PEM block (matches Go's
    // x509.MarshalPKCS1PrivateKey / pem.Decode pairing in rsakey.go).
    static RsaPrivateKey FromPkcs1Pem(const std::string& pem);
    std::string ToPkcs1Pem() const;

    // Loads path if it exists, otherwise generates a new kRsaKeyBits key and
    // writes it there (creating parent directories). 1:1 port of
    // LoadOrGenerateRSAKey (internal/mtprotoedge/rsakey.go).
    static RsaPrivateKey LoadOrGenerate(const std::string& path);

    RsaPublicKey PublicKey() const;
    std::int64_t Fingerprint() const { return PublicKey().Fingerprint(); }

    // c^d mod n. Throws std::runtime_error if the result doesn't fit in
    // kRsaByteLen bytes (mirrors Go's FillBytes-checked rsaDecrypt).
    std::vector<std::uint8_t> DecryptRaw(const std::vector<std::uint8_t>& data) const;

private:
    // p, q and the CRT exponents/coefficient are carried alongside (n, e, d)
    // purely because OpenSSL's *traditional* PKCS#1 PEM encoder refuses to
    // serialize an RSAPrivateKey ASN.1 structure missing them (it treats a
    // zero/absent CRT field as "illegal zero content", not "recompute me").
    // Every actual crypto operation this class performs (DecryptRaw,
    // Fingerprint, PublicKey) uses only n/e/d.
    RsaPrivateKey(std::vector<std::uint8_t> n, std::vector<std::uint8_t> e, std::vector<std::uint8_t> d,
                  std::vector<std::uint8_t> p, std::vector<std::uint8_t> q, std::vector<std::uint8_t> dp,
                  std::vector<std::uint8_t> dq, std::vector<std::uint8_t> qinv)
        : n_(std::move(n)),
          e_(std::move(e)),
          d_(std::move(d)),
          p_(std::move(p)),
          q_(std::move(q)),
          dp_(std::move(dp)),
          dq_(std::move(dq)),
          qinv_(std::move(qinv)) {}

    std::vector<std::uint8_t> n_;
    std::vector<std::uint8_t> e_;
    std::vector<std::uint8_t> d_;
    std::vector<std::uint8_t> p_;
    std::vector<std::uint8_t> q_;
    std::vector<std::uint8_t> dp_;
    std::vector<std::uint8_t> dq_;
    std::vector<std::uint8_t> qinv_;
};

} // namespace shuzagram::mtproto::crypto
