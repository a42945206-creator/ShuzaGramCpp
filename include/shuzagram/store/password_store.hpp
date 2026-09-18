#pragma once

#include <cstdint>
#include <optional>

#include "shuzagram/domain/password.hpp"

// Port of the narrow slice of store.PasswordStore
// (internal/store/account.go) this project's auth.checkPassword needs:
// GetByUser and Save. LoginEmailOwner is not ported -- this project has no
// email-login flow to need it.
namespace shuzagram::store {

class IPasswordStore {
public:
    virtual ~IPasswordStore() = default;

    virtual std::optional<domain::PasswordSettings> GetByUser(std::int64_t user_id) = 0;

    // Upserts the complete row. Callers always pass the FULL settings
    // (this project never does a partial/merge update), matching the Go
    // source's own single upsert-everything SQL statement.
    virtual void Save(std::int64_t user_id, const domain::PasswordSettings& settings) = 0;
};

} // namespace shuzagram::store
