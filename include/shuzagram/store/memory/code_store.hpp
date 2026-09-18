#pragma once

#include <mutex>
#include <unordered_map>

#include "shuzagram/store/code_store.hpp"

// The actual runtime CodeStore this project ships with, not just a test
// double: real ShuzaGram uses Redis with atomic Lua scripts
// (internal/store/redisstore) so concurrent verification attempts across
// many server processes stay linearizable. This project runs as one
// process, so a single std::mutex around an in-memory map gives the exact
// same atomicity guarantee the Lua scripts exist for, without taking on a
// Redis client dependency for a first slice. Revisit if this project ever
// needs to run more than one server process sharing login state.
//
// Codes do not expire on a timer in this slice (no TTL sweep) -- see
// NOTES/auth-sign-in-plan.md.
namespace shuzagram::store::memory {

class CodeStore final : public store::ICodeStore {
public:
    void Set(const std::string& phone_code_hash, const PhoneCode& code) override;
    std::optional<PhoneCode> Get(const std::string& phone_code_hash) override;
    void Del(const std::string& phone_code_hash) override;
    LoginCodeVerifyResult VerifyLogin(const std::string& phone_code_hash, const std::string& phone,
                                       const std::string& code, bool keep_for_sign_up,
                                       int default_max_attempts) override;
    std::optional<PhoneCode> ConsumeSignUpVerified(const std::string& phone_code_hash,
                                                    const std::string& phone) override;

private:
    std::mutex mu_;
    std::unordered_map<std::string, PhoneCode> codes_;
};

} // namespace shuzagram::store::memory
