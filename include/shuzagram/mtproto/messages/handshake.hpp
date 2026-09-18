#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "shuzagram/mtproto/tl_buffer.hpp"

// TL structs for the MTProto key-exchange handshake, 1:1 against
// gotd/td's mt/tl_*_gen.go (generated code) -- field order and every type
// id below is copied from that generated source, not reconstructed from
// the public schema by hand.
namespace shuzagram::mtproto::messages {

// req_pq#60469778 nonce:int128 = ResPQ; (legacy)
inline constexpr std::uint32_t kReqPqRequestTypeId = 0x60469778;
// req_pq_multi#be7e8ef1 nonce:int128 = ResPQ;
inline constexpr std::uint32_t kReqPqMultiRequestTypeId = 0xbe7e8ef1;

// Either legacy req_pq or req_pq_multi -- both carry just a nonce, so the
// server's read side (server_exchange.cpp) only needs to know which type id
// it saw, not decode two different shapes.
struct ReqPq {
    std::uint32_t type_id = 0;
    Int128 nonce{};

    void Decode(TLBuffer& b) {
        type_id = b.PeekID();
        if (type_id != kReqPqRequestTypeId && type_id != kReqPqMultiRequestTypeId) {
            throw UnexpectedIdError(type_id);
        }
        b.ConsumeID(type_id);
        nonce = b.GetInt128();
    }
};

// resPQ#05162463 nonce:int128 server_nonce:int128 pq:string
//   server_public_key_fingerprints:Vector long = ResPQ;
struct ResPq {
    static constexpr std::uint32_t kTypeId = 0x05162463;

    Int128 nonce{};
    Int128 server_nonce{};
    std::vector<std::uint8_t> pq;
    std::vector<std::int64_t> server_public_key_fingerprints;

    void Encode(TLBuffer& b) const {
        b.PutID(kTypeId);
        b.PutInt128(nonce);
        b.PutInt128(server_nonce);
        b.PutBytes(pq);
        b.PutVectorHeader(server_public_key_fingerprints.size());
        for (const auto v : server_public_key_fingerprints) b.PutLong(v);
    }
};

// req_DH_params#d712e4be nonce:int128 server_nonce:int128 p:string q:string
//   public_key_fingerprint:long encrypted_data:string = Server_DH_Params;
struct ReqDhParams {
    static constexpr std::uint32_t kTypeId = 0xd712e4be;

    Int128 nonce{};
    Int128 server_nonce{};
    std::vector<std::uint8_t> p;
    std::vector<std::uint8_t> q;
    std::int64_t public_key_fingerprint = 0;
    std::vector<std::uint8_t> encrypted_data;

    void Decode(TLBuffer& b) {
        b.ConsumeID(kTypeId);
        nonce = b.GetInt128();
        server_nonce = b.GetInt128();
        p = b.GetBytes();
        q = b.GetBytes();
        public_key_fingerprint = b.Long();
        encrypted_data = b.GetBytes();
    }
};

// The three p_q_inner_data* variants (mt/tl_p_q_inner_data_gen.go). All
// three carry the same first six fields; DC/TempDC append dc (and
// TempDC also expires_in). Modeled as one struct with an enum discriminant
// rather than three C++ types, since server_exchange.cpp only branches on
// "was a DC present" and "was it PFS", not on distinct behavior otherwise.
enum class PqInnerDataKind { kPlain, kDc, kTempDc };

struct PqInnerData {
    static constexpr std::uint32_t kPlainTypeId = 0x83c95aec;
    static constexpr std::uint32_t kDcTypeId = 0xa9f55f95;
    static constexpr std::uint32_t kTempDcTypeId = 0x56fddf88;

    PqInnerDataKind kind = PqInnerDataKind::kPlain;
    std::vector<std::uint8_t> pq;
    std::vector<std::uint8_t> p;
    std::vector<std::uint8_t> q;
    Int128 nonce{};
    Int128 server_nonce{};
    Int256 new_nonce{};
    int dc = 0;         // kDc, kTempDc only
    int expires_in = 0; // kTempDc only

    // Decodes whichever of the three variants is present. Throws
    // UnexpectedIdError for anything else (in particular, the
    // non-standard p_q_inner_data_temp#3c6a84d4 some iOS clients send for
    // PFS -- a known gap, see NOTES/transport-handshake-plan.md).
    static PqInnerData Decode(TLBuffer& b) {
        const std::uint32_t id = b.PeekID();
        PqInnerData d;
        switch (id) {
            case kPlainTypeId: d.kind = PqInnerDataKind::kPlain; break;
            case kDcTypeId: d.kind = PqInnerDataKind::kDc; break;
            case kTempDcTypeId: d.kind = PqInnerDataKind::kTempDc; break;
            default: throw UnexpectedIdError(id);
        }
        b.ConsumeID(id);
        d.pq = b.GetBytes();
        d.p = b.GetBytes();
        d.q = b.GetBytes();
        d.nonce = b.GetInt128();
        d.server_nonce = b.GetInt128();
        d.new_nonce = b.GetInt256();
        if (d.kind != PqInnerDataKind::kPlain) d.dc = b.Int();
        if (d.kind == PqInnerDataKind::kTempDc) d.expires_in = b.Int();
        return d;
    }
};

// server_DH_inner_data#b5890dba nonce:int128 server_nonce:int128 g:int
//   dh_prime:string g_a:string server_time:int = Server_DH_inner_data;
struct ServerDhInnerData {
    static constexpr std::uint32_t kTypeId = 0xb5890dba;

    Int128 nonce{};
    Int128 server_nonce{};
    int g = 0;
    std::vector<std::uint8_t> dh_prime;
    std::vector<std::uint8_t> g_a;
    int server_time = 0;

    void Encode(TLBuffer& b) const {
        b.PutID(kTypeId);
        b.PutInt128(nonce);
        b.PutInt128(server_nonce);
        b.PutInt32(g);
        b.PutBytes(dh_prime);
        b.PutBytes(g_a);
        b.PutInt32(server_time);
    }
};

// server_DH_params_ok#d0e8075c nonce:int128 server_nonce:int128
//   encrypted_answer:string = Server_DH_Params;
//
// (server_DH_params_fail exists in the schema too, but this server never
// sends it -- see NOTES/transport-handshake-plan.md.)
struct ServerDhParamsOk {
    static constexpr std::uint32_t kTypeId = 0xd0e8075c;

    Int128 nonce{};
    Int128 server_nonce{};
    std::vector<std::uint8_t> encrypted_answer;

    void Encode(TLBuffer& b) const {
        b.PutID(kTypeId);
        b.PutInt128(nonce);
        b.PutInt128(server_nonce);
        b.PutBytes(encrypted_answer);
    }
};

// set_client_DH_params#f5045f1f nonce:int128 server_nonce:int128
//   encrypted_data:string = Set_client_DH_params_answer;
struct SetClientDhParams {
    static constexpr std::uint32_t kTypeId = 0xf5045f1f;

    Int128 nonce{};
    Int128 server_nonce{};
    std::vector<std::uint8_t> encrypted_data;

    void Decode(TLBuffer& b) {
        b.ConsumeID(kTypeId);
        nonce = b.GetInt128();
        server_nonce = b.GetInt128();
        encrypted_data = b.GetBytes();
    }
};

// client_DH_inner_data#6643b654 nonce:int128 server_nonce:int128
//   retry_id:long g_b:string = Client_DH_Inner_Data;
struct ClientDhInnerData {
    static constexpr std::uint32_t kTypeId = 0x6643b654;

    Int128 nonce{};
    Int128 server_nonce{};
    std::int64_t retry_id = 0;
    std::vector<std::uint8_t> g_b;

    void Decode(TLBuffer& b) {
        b.ConsumeID(kTypeId);
        nonce = b.GetInt128();
        server_nonce = b.GetInt128();
        retry_id = b.Long();
        g_b = b.GetBytes();
    }
    void Encode(TLBuffer& b) const {
        b.PutID(kTypeId);
        b.PutInt128(nonce);
        b.PutInt128(server_nonce);
        b.PutLong(retry_id);
        b.PutBytes(g_b);
    }
};

// dh_gen_ok#3bcbf734 nonce:int128 server_nonce:int128
//   new_nonce_hash1:int128 = Set_client_DH_params_answer;
//
// (dh_gen_retry#46dc1fb9 / dh_gen_fail#a69dae02 exist in the schema for the
// client-detected-mismatch paths; this server's flow always succeeds or
// throws before reaching this message, so only Ok is modeled.)
struct DhGenOk {
    static constexpr std::uint32_t kTypeId = 0x3bcbf734;

    Int128 nonce{};
    Int128 server_nonce{};
    Int128 new_nonce_hash1{};

    void Encode(TLBuffer& b) const {
        b.PutID(kTypeId);
        b.PutInt128(nonce);
        b.PutInt128(server_nonce);
        b.PutInt128(new_nonce_hash1);
    }
};

} // namespace shuzagram::mtproto::messages
