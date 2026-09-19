#include "shuzagram/users/update_birthday.hpp"

#include "shuzagram/domain/user_errors.hpp"

namespace shuzagram::users {

domain::User UpdateBirthday(store::IUserStore& users, std::int64_t user_id, domain::Birthday birthday) {
    const auto self = users.ByID(user_id);
    if (!self.has_value()) throw domain::UserNotFoundError();

    if (birthday.IsSet()) {
        if (!domain::ValidBirthday(birthday)) throw domain::BirthdayInvalidError();
    } else {
        birthday = domain::Birthday{}; // normalize to the clearing value
    }
    return users.UpdateBirthday(self->id, birthday);
}

} // namespace shuzagram::users
