// Validation-logic checks for auth::BindTempAuthKey (the auth.bindTempAuthKey
// business logic on top of crypto::DecryptBindAuthKeyInner and the store
// interfaces), using simple in-memory fakes of IAuthKeyStore/
// ITempAuthKeyBindingStore instead of a live Postgres -- this exercises
// every reject path fast and deterministically. The one thing these fakes
// deliberately do NOT reproduce is the real `telesrv_bind_temp_auth_key`
// database function's own re-validation/Layer-merge logic -- that's covered
// separately, against the actual live schema, in tests/auth_store_smoke.cpp
// (not run by ctest; needs live credentials).

#include <chrono>
#include <cstdio>
#include <cstring>
#include <map>
#include <optional>
#include <string>

#include "shuzagram/auth/bind_temp_auth_key.hpp"
#include "shuzagram/mtproto/crypto/bind.hpp"

namespace {

using namespace shuzagram;

int g_failures = 0;

void Check(bool ok, const std::string& what) {
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s\n", what.c_str());
        ++g_failures;
    }
}

std::array<std::uint8_t, 8> MakeId(std::uint64_t seed) {
    std::array<std::uint8_t, 8> id{};
    std::memcpy(id.data(), &seed, 8);
    return id;
}

mtproto::crypto::AuthKeyBytes MakeKey(std::uint8_t fill) {
    mtproto::crypto::AuthKeyBytes key{};
    key.fill(fill);
    return key;
}

std::int64_t NowUnix() {
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

class FakeAuthKeyStore final : public store::IAuthKeyStore {
public:
    void Save(const store::AuthKeyData& key) override { keys_[key.id] = key; }
    std::optional<store::AuthKeyData> Get(const std::array<std::uint8_t, 8>& id) override {
        const auto it = keys_.find(id);
        return it == keys_.end() ? std::nullopt : std::optional(it->second);
    }
    void UpdateClientInfo(const std::array<std::uint8_t, 8>&, const store::AuthKeyClientInfo&) override {}
    void Delete(const std::array<std::uint8_t, 8>& id) override { keys_.erase(id); }
    std::optional<store::AuthKeyData> Revalidate(const std::array<std::uint8_t, 8>& id) override { return Get(id); }
    store::AuthKeyBindingKeys LoadBindingKeys(const std::array<std::uint8_t, 8>& temp_id,
                                               const std::array<std::uint8_t, 8>& perm_id) override {
        store::AuthKeyBindingKeys out;
        if (const auto t = Get(temp_id)) {
            out.temporary = *t;
            out.temporary_found = true;
        }
        if (const auto p = Get(perm_id)) {
            out.permanent = *p;
            out.permanent_found = true;
        }
        return out;
    }

private:
    std::map<std::array<std::uint8_t, 8>, store::AuthKeyData> keys_;
};

class FakeTempAuthKeyBindingStore final : public store::ITempAuthKeyBindingStore {
public:
    domain::TempAuthKeyBindingResult SaveWithState(const domain::TempAuthKeyBinding& binding) override {
        const auto it = bindings_.find(binding.temp_auth_key_id);
        if (it != bindings_.end() && it->second.perm_auth_key_id != binding.perm_auth_key_id) {
            throw store::TempAuthKeyAlreadyBoundError();
        }
        bindings_[binding.temp_auth_key_id] = binding;
        return {};
    }
    std::optional<domain::TempAuthKeyBinding> GetByTemp(const std::array<std::uint8_t, 8>& id) override {
        const auto it = bindings_.find(id);
        return it == bindings_.end() ? std::nullopt : std::optional(it->second);
    }

private:
    std::map<std::array<std::uint8_t, 8>, domain::TempAuthKeyBinding> bindings_;
};

// A fully self-consistent request: builds a real encrypted_message under
// perm_key that exactly matches every other field, so tests can start from
// "this succeeds" and mutate exactly one thing.
auth::BindTempAuthKeyRequest MakeValidRequest(const std::array<std::uint8_t, 8>& temp_id,
                                               const mtproto::crypto::AuthKeyBytes& perm_key,
                                               std::int64_t perm_id_int64, std::int64_t session_id, int expires_at) {
    mtproto::messages::BindAuthKeyInner inner;
    inner.nonce = 777;
    std::memcpy(&inner.temp_auth_key_id, temp_id.data(), 8);
    inner.perm_auth_key_id = perm_id_int64;
    inner.temp_session_id = session_id;
    inner.expires_at = expires_at;

    auth::BindTempAuthKeyRequest req;
    req.temp_auth_key_id = temp_id;
    req.temp_session_id = session_id;
    req.perm_auth_key_id = perm_id_int64;
    req.nonce = inner.nonce;
    req.expires_at = expires_at;
    req.encrypted_message = mtproto::crypto::EncryptBindMessage(perm_key, /*msg_id=*/1, inner);
    return req;
}

struct Fixture {
    FakeAuthKeyStore auth_keys;
    FakeTempAuthKeyBindingStore temp_keys;
    mtproto::crypto::AuthKeyBytes perm_key = MakeKey(0x55);
    std::array<std::uint8_t, 8> perm_id = MakeId(0xAAAAAAAA);
    std::array<std::uint8_t, 8> temp_id = MakeId(0xBBBBBBBB);
    std::int64_t perm_id_int64;
    std::int64_t session_id = 42;
    int expires_at;

    Fixture() {
        std::memcpy(&perm_id_int64, perm_id.data(), 8);
        expires_at = static_cast<int>(NowUnix()) + 3600;

        store::AuthKeyData perm;
        perm.id = perm_id;
        perm.value = perm_key;
        perm.expires_at = 0; // permanent
        auth_keys.Save(perm);

        store::AuthKeyData temp;
        temp.id = temp_id;
        temp.value = MakeKey(0x66);
        temp.expires_at = expires_at;
        auth_keys.Save(temp);
    }

    auth::BindTempAuthKeyRequest ValidRequest() const {
        return MakeValidRequest(temp_id, perm_key, perm_id_int64, session_id, expires_at);
    }
};

void TestHappyPath() {
    Fixture f;
    const auto result = auth::BindTempAuthKey(f.auth_keys, f.temp_keys, f.ValidRequest());
    (void)result;
    const auto stored = f.temp_keys.GetByTemp(f.temp_id);
    Check(stored.has_value() && stored->perm_auth_key_id == f.perm_id_int64 && stored->nonce == 777 &&
              stored->temp_session_id == f.session_id && stored->expires_at == f.expires_at,
          "happy path persists the exact binding");
}

void TestExpiresAtInvalid() {
    Fixture f;
    auto req = f.ValidRequest();
    req.expires_at = 0;
    try {
        auth::BindTempAuthKey(f.auth_keys, f.temp_keys, req);
        Check(false, "expires_at <= 0 should throw ExpiresAtInvalidError");
    } catch (const auth::ExpiresAtInvalidError&) {
        Check(true, "expires_at <= 0 throws ExpiresAtInvalidError");
    }
}

void TestTempKeyNotFound() {
    Fixture f;
    auto req = f.ValidRequest();
    req.temp_auth_key_id = MakeId(0xDEADBEEF); // never Saved
    try {
        auth::BindTempAuthKey(f.auth_keys, f.temp_keys, req);
        Check(false, "unknown temp_auth_key_id should throw TempAuthKeyEmptyError");
    } catch (const auth::TempAuthKeyEmptyError&) {
        Check(true, "unknown temp_auth_key_id throws TempAuthKeyEmptyError");
    }
}

void TestTempKeyExpired() {
    Fixture f;
    store::AuthKeyData expired_temp;
    expired_temp.id = f.temp_id;
    expired_temp.value = MakeKey(0x66);
    expired_temp.expires_at = static_cast<int>(NowUnix()) - 10; // already expired
    f.auth_keys.Save(expired_temp);

    // The request's own expires_at must still be positive to pass the
    // first check; it's the STORED key's expiry that must be in the past.
    auto req = f.ValidRequest();
    req.expires_at = expired_temp.expires_at;
    try {
        auth::BindTempAuthKey(f.auth_keys, f.temp_keys, req);
        Check(false, "an expired temp key should throw TempAuthKeyEmptyError");
    } catch (const auth::TempAuthKeyEmptyError&) {
        Check(true, "an expired temp key throws TempAuthKeyEmptyError");
    }
}

void TestPermKeyNotFound() {
    Fixture f;
    auto req = f.ValidRequest();
    req.perm_auth_key_id = 0x1234567890; // names no row in auth_keys
    try {
        auth::BindTempAuthKey(f.auth_keys, f.temp_keys, req);
        Check(false, "unknown perm_auth_key_id should throw EncryptedMessageInvalidError");
    } catch (const auth::EncryptedMessageInvalidError&) {
        Check(true, "unknown perm_auth_key_id throws EncryptedMessageInvalidError");
    }
}

void TestPermKeyNotActuallyPermanent() {
    Fixture f;
    store::AuthKeyData not_perm;
    not_perm.id = f.perm_id;
    not_perm.value = f.perm_key;
    not_perm.expires_at = 999999999; // this row is itself temporary
    f.auth_keys.Save(not_perm);
    try {
        auth::BindTempAuthKey(f.auth_keys, f.temp_keys, f.ValidRequest());
        Check(false, "a claimed permanent key that's actually temporary should throw");
    } catch (const auth::EncryptedMessageInvalidError&) {
        Check(true, "a non-permanent claimed perm key throws EncryptedMessageInvalidError");
    }
}

void TestFieldMismatchAgainstProof() {
    Fixture f;
    {
        auto req = f.ValidRequest();
        req.nonce += 1; // no longer matches the encrypted bind_auth_key_inner
        try {
            auth::BindTempAuthKey(f.auth_keys, f.temp_keys, req);
            Check(false, "mismatched nonce should throw");
        } catch (const auth::EncryptedMessageInvalidError&) {
            Check(true, "mismatched nonce throws EncryptedMessageInvalidError");
        }
    }
    {
        auto req = f.ValidRequest();
        req.temp_session_id += 1; // this connection's session != the proof's
        try {
            auth::BindTempAuthKey(f.auth_keys, f.temp_keys, req);
            Check(false, "mismatched session_id should throw");
        } catch (const auth::EncryptedMessageInvalidError&) {
            Check(true, "mismatched session_id throws EncryptedMessageInvalidError");
        }
    }
}

void TestAlreadyBoundToDifferentPermKey() {
    Fixture f;
    auth::BindTempAuthKey(f.auth_keys, f.temp_keys, f.ValidRequest());

    // A second permanent key, with a fresh valid proof binding the SAME
    // temp key to it instead.
    const auto other_perm_id = MakeId(0xCCCCCCCC);
    std::int64_t other_perm_id_int64;
    std::memcpy(&other_perm_id_int64, other_perm_id.data(), 8);
    const auto other_perm_key = MakeKey(0x99);
    store::AuthKeyData other_perm;
    other_perm.id = other_perm_id;
    other_perm.value = other_perm_key;
    other_perm.expires_at = 0;
    f.auth_keys.Save(other_perm);

    const auto req = MakeValidRequest(f.temp_id, other_perm_key, other_perm_id_int64, f.session_id, f.expires_at);
    try {
        auth::BindTempAuthKey(f.auth_keys, f.temp_keys, req);
        Check(false, "re-binding to a different permanent key should throw");
    } catch (const store::TempAuthKeyAlreadyBoundError&) {
        Check(true, "re-binding an already-bound temp key to a different perm key throws TempAuthKeyAlreadyBoundError");
    }
}

void TestRebindToSamePermKeyIsIdempotent() {
    Fixture f;
    auth::BindTempAuthKey(f.auth_keys, f.temp_keys, f.ValidRequest());
    // A fresh proof, same nonce reused is fine here since it's a different
    // EncryptBindMessage call (different msg_id/random padding) but the
    // same logical binding.
    auth::BindTempAuthKey(f.auth_keys, f.temp_keys, f.ValidRequest());
    const auto stored = f.temp_keys.GetByTemp(f.temp_id);
    Check(stored.has_value() && stored->perm_auth_key_id == f.perm_id_int64,
          "re-binding to the SAME permanent key does not throw");
}

} // namespace

int main() {
    TestHappyPath();
    TestExpiresAtInvalid();
    TestTempKeyNotFound();
    TestTempKeyExpired();
    TestPermKeyNotFound();
    TestPermKeyNotActuallyPermanent();
    TestFieldMismatchAgainstProof();
    TestAlreadyBoundToDifferentPermKey();
    TestRebindToSamePermKeyIsIdempotent();
    if (g_failures == 0) {
        std::printf("all auth::BindTempAuthKey tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d auth::BindTempAuthKey test(s) failed\n", g_failures);
    return 1;
}
