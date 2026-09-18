// Manual smoke test against a real Postgres instance. Not run by `ctest`
// (needs live credentials); invoke directly:
//
//   SHUZAGRAM_PG_DSN="host=127.0.0.1 port=15432 dbname=telesrv_main \
//     user=telesrv password=..." ./build/tests/user_store_smoke
//
// NOTE: this process calls std::_Exit() instead of returning from main().
// The Ubuntu 26.04 libpqxx 7.10.0 package double-frees a static string
// during global destruction, independent of anything in this codebase --
// confirmed with a ~10-line program that does nothing but
// `pqxx::connection(dsn)` and one query. _Exit() skips static destructors
// entirely, which is safe here (the process is terminating and the OS
// reclaims everything), but is not a fix: a long-running server process
// linking this libpqxx build would need to either pin a different libpqxx
// version or track the upstream fix.

#include <cstdio>
#include <cstdlib>

#include "shuzagram/store/postgres/user_store.hpp"

int main() {
    const char* dsn = std::getenv("SHUZAGRAM_PG_DSN");
    if (!dsn) {
        std::printf("SHUZAGRAM_PG_DSN not set, skipping live smoke test\n");
        return 0;
    }

    shuzagram::store::postgres::Database db(dsn);
    shuzagram::store::postgres::UserStore store(db);

    pqxx::work probe(db.conn());
    const auto row = probe.exec("SELECT id FROM users ORDER BY id LIMIT 1");
    probe.commit();
    if (row.empty()) {
        std::printf("users table is empty, nothing to look up\n");
        return 0;
    }
    const std::int64_t id = row[0][0].as<std::int64_t>();

    const auto user = store.ByID(id);
    if (!user) {
        std::fprintf(stderr, "ByID(%lld) unexpectedly returned nothing\n", static_cast<long long>(id));
        std::_Exit(1);
    }

    std::printf("ByID(%lld) -> first_name=%s username=%s bot=%d premium_until=%d deleted=%d\n",
                static_cast<long long>(id), user->first_name.c_str(), user->username.c_str(), user->bot,
                user->premium_until, user->deleted);

    const auto by_ids = store.ByIDs({id});
    if (by_ids.size() != 1 || by_ids[0].id != id) {
        std::fprintf(stderr, "ByIDs([%lld]) returned unexpected result\n", static_cast<long long>(id));
        std::_Exit(1);
    }

    std::printf("smoke test passed\n");
    std::fflush(stdout);
    std::_Exit(0); // see the libpqxx-teardown note above
}
