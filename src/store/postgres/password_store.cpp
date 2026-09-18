#include "shuzagram/store/postgres/password_store.hpp"

#include <cstring>

// Ported from internal/store/postgres/account.go's PasswordStore
// (GetByUser/Save only). See the header for what's deliberately not
// tracked.
namespace shuzagram::store::postgres {

namespace {

std::vector<std::uint8_t> BytesFrom(const pqxx::field& f) {
    const auto raw = f.as<pqxx::bytes>();
    std::vector<std::uint8_t> out(raw.size());
    std::memcpy(out.data(), raw.data(), raw.size());
    return out;
}

// pqxx::binary_cast(vector) builds its bytes_view from the vector's own
// .data(), which an EMPTY std::vector is permitted to leave null -- and
// libpqxx's parameter encoder treats a null data pointer as SQL NULL, not
// an empty bytea, silently violating this table's NOT NULL bytea columns
// (found via a live-DB run: "null value in column srp_b_secret violates
// not-null constraint" from a perfectly valid empty-but-not-null Go-side
// default). std::string's .data() is guaranteed non-null even when empty
// (a C++11 guarantee vectors don't share), so routing through one side-
// steps the bug. The caller must keep the returned string alive for as
// long as the resulting bytes_view/param is used.
std::string BytesParam(const std::vector<std::uint8_t>& v) {
    return {reinterpret_cast<const char*>(v.data()), v.size()};
}

} // namespace

std::optional<domain::PasswordSettings> PasswordStore::GetByUser(std::int64_t user_id) {
    pqxx::work tx(db_.conn());
    const auto result = tx.exec(
        "SELECT has_recovery, has_secure_values, has_password, hint, secure_random, "
        "current_algo_salt1, current_algo_salt2, current_algo_g, current_algo_p, "
        "srp_id, srp_verifier, srp_b_secret, srp_b "
        "FROM account_passwords WHERE user_id = $1",
        pqxx::params{user_id});
    tx.commit();
    if (result.empty()) return std::nullopt;
    const auto& row = result[0];

    domain::PasswordSettings settings;
    settings.has_recovery = row["has_recovery"].as<bool>();
    settings.has_secure_values = row["has_secure_values"].as<bool>();
    settings.has_password = row["has_password"].as<bool>();
    settings.hint = row["hint"].as<std::string>();
    settings.secure_random = BytesFrom(row["secure_random"]);

    domain::PasswordAlgo algo;
    algo.salt1 = BytesFrom(row["current_algo_salt1"]);
    algo.salt2 = BytesFrom(row["current_algo_salt2"]);
    algo.g = row["current_algo_g"].as<int>();
    algo.p = BytesFrom(row["current_algo_p"]);
    settings.new_algo = algo;
    // The sole current_algo_* columns back BOTH new_algo (a fallback
    // default) and current_algo (the CURRENT verifier's actual algo) --
    // see PasswordStore's own doc comment. Only expose it as current_algo
    // once it's genuinely non-empty.
    if (!algo.salt1.empty() || !algo.salt2.empty() || !algo.p.empty() || algo.g != 0) {
        settings.current_algo = algo;
    }

    settings.srp_id = row["srp_id"].as<std::int64_t>();
    settings.srp_verifier = BytesFrom(row["srp_verifier"]);
    settings.srp_b_secret = BytesFrom(row["srp_b_secret"]);
    settings.srp_b = BytesFrom(row["srp_b"]);
    return settings;
}

void PasswordStore::Save(std::int64_t user_id, const domain::PasswordSettings& settings) {
    const domain::PasswordAlgo algo = settings.current_algo.value_or(settings.new_algo);
    // Named locals, not inline temporaries: binary_cast's bytes_view
    // borrows from these, so they must outlive the tx.exec call below.
    const std::string secure_random = BytesParam(settings.secure_random);
    const std::string salt1 = BytesParam(algo.salt1);
    const std::string salt2 = BytesParam(algo.salt2);
    const std::string p = BytesParam(algo.p);
    const std::string verifier = BytesParam(settings.srp_verifier);
    const std::string b_secret = BytesParam(settings.srp_b_secret);
    const std::string b = BytesParam(settings.srp_b);

    pqxx::work tx(db_.conn());
    tx.exec(
        "INSERT INTO account_passwords (user_id, has_recovery, has_secure_values, has_password, hint, "
        "secure_random, current_algo_salt1, current_algo_salt2, current_algo_g, current_algo_p, "
        "srp_id, srp_verifier, srp_b_secret, srp_b) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) "
        "ON CONFLICT (user_id) DO UPDATE SET "
        "has_recovery = EXCLUDED.has_recovery, has_secure_values = EXCLUDED.has_secure_values, "
        "has_password = EXCLUDED.has_password, hint = EXCLUDED.hint, secure_random = EXCLUDED.secure_random, "
        "current_algo_salt1 = EXCLUDED.current_algo_salt1, current_algo_salt2 = EXCLUDED.current_algo_salt2, "
        "current_algo_g = EXCLUDED.current_algo_g, current_algo_p = EXCLUDED.current_algo_p, "
        "srp_id = EXCLUDED.srp_id, srp_verifier = EXCLUDED.srp_verifier, "
        "srp_b_secret = EXCLUDED.srp_b_secret, srp_b = EXCLUDED.srp_b, updated_at = now()",
        pqxx::params{user_id, settings.has_recovery, settings.has_secure_values, settings.has_password,
                     settings.hint, pqxx::binary_cast(secure_random), pqxx::binary_cast(salt1),
                     pqxx::binary_cast(salt2), algo.g, pqxx::binary_cast(p), settings.srp_id,
                     pqxx::binary_cast(verifier), pqxx::binary_cast(b_secret), pqxx::binary_cast(b)});
    tx.commit();
}

} // namespace shuzagram::store::postgres
