#pragma once

#include <string>

#include <pqxx/pqxx>

// Thin connection holder. internal/store/postgres in the Go source runs on a
// pgxpool.Pool (a real connection pool with health checks and admission
// control, see internal/store/postgres/postgres_connection_admission.go);
// this first slice deliberately keeps a single pqxx::connection so the
// domain/store port can be verified end to end before that pooling layer is
// ported.
namespace shuzagram::store::postgres {

class Database {
public:
    explicit Database(const std::string& conninfo) : conn_(conninfo) {}

    pqxx::connection& conn() { return conn_; }

private:
    pqxx::connection conn_;
};

} // namespace shuzagram::store::postgres
