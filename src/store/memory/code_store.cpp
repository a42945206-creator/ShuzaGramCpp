#include "shuzagram/store/memory/code_store.hpp"

namespace shuzagram::store::memory {

void CodeStore::Set(const std::string& phone_code_hash, const PhoneCode& code) {
    std::lock_guard<std::mutex> lock(mu_);
    codes_[phone_code_hash] = code;
}

std::optional<PhoneCode> CodeStore::Get(const std::string& phone_code_hash) {
    std::lock_guard<std::mutex> lock(mu_);
    const auto it = codes_.find(phone_code_hash);
    if (it == codes_.end()) return std::nullopt;
    return it->second;
}

void CodeStore::Del(const std::string& phone_code_hash) {
    std::lock_guard<std::mutex> lock(mu_);
    codes_.erase(phone_code_hash);
}

LoginCodeVerifyResult CodeStore::VerifyLogin(const std::string& phone_code_hash, const std::string& phone,
                                              const std::string& code, bool keep_for_sign_up,
                                              int default_max_attempts) {
    std::lock_guard<std::mutex> lock(mu_);
    const auto it = codes_.find(phone_code_hash);
    if (it == codes_.end() || it->second.phone != phone) {
        return {LoginCodeVerifyStatus::kMissing, {}};
    }

    if (it->second.code != code) {
        const int max_attempts = it->second.max_attempts > 0 ? it->second.max_attempts : default_max_attempts;
        ++it->second.attempts;
        if (it->second.attempts >= max_attempts) codes_.erase(it);
        return {LoginCodeVerifyStatus::kInvalid, {}};
    }

    PhoneCode accepted = it->second;
    if (keep_for_sign_up) {
        it->second.sign_up_verified = true;
        accepted.sign_up_verified = true;
    } else {
        codes_.erase(it);
    }
    return {LoginCodeVerifyStatus::kAccepted, accepted};
}

std::optional<PhoneCode> CodeStore::ConsumeSignUpVerified(const std::string& phone_code_hash,
                                                           const std::string& phone) {
    std::lock_guard<std::mutex> lock(mu_);
    const auto it = codes_.find(phone_code_hash);
    if (it == codes_.end() || it->second.phone != phone || !it->second.sign_up_verified) return std::nullopt;
    PhoneCode consumed = it->second;
    codes_.erase(it);
    return consumed;
}

} // namespace shuzagram::store::memory
