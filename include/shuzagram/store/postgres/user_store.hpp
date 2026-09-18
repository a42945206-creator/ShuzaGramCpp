#pragma once

#include "shuzagram/store/postgres/database.hpp"
#include "shuzagram/store/user_store.hpp"

namespace shuzagram::store::postgres {

// PostgreSQL implementation of store::IUserStore, ported from
// internal/store/postgres/user.go against the live `users` table schema
// (introspected from the running deployment: 39 columns as of the
// `premium_updated_at` migration).
class UserStore final : public store::IUserStore {
public:
    explicit UserStore(Database& db) : db_(db) {}

    std::optional<domain::User> ByID(std::int64_t id) override;
    std::vector<domain::User> ByIDs(const std::vector<std::int64_t>& ids) override;
    std::optional<domain::User> ByPhone(const std::string& phone) override;
    std::optional<domain::User> ByUsername(const std::string& username) override;
    domain::User Create(const domain::User& user) override;
    domain::User SetPremiumUntil(std::int64_t user_id, int until) override;
    domain::User SetVerified(std::int64_t user_id, bool verified) override;
    domain::User SetSupport(std::int64_t user_id, bool support) override;
    void UpdateLastSeen(std::int64_t user_id, int last_seen_at) override;
    domain::User UpdateProfile(std::int64_t user_id, const std::string& first_name,
                               const std::string& last_name, const std::string& about) override;
    domain::User UpdateUsername(std::int64_t user_id, const std::string& username) override;
    domain::User UpdatePhone(std::int64_t user_id, const std::string& phone) override;
    domain::User SetScamFake(std::int64_t user_id, bool scam, bool fake) override;
    std::vector<domain::User> SweepExpiredPremium(std::int64_t now, int limit) override;
    domain::User UpdateEmojiStatus(std::int64_t user_id, const domain::UserEmojiStatus& status) override;
    domain::User UpdateBirthday(std::int64_t user_id, const domain::Birthday& birthday) override;
    domain::User UpdatePersonalChannel(std::int64_t user_id, std::int64_t channel_id) override;
    domain::User UpdateColor(std::int64_t user_id, bool for_profile, const domain::PeerColor& color) override;

private:
    Database& db_;
};

} // namespace shuzagram::store::postgres
