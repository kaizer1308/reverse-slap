// src/core/persist/session_store.cpp

#include "core/persist/session_store.hpp"

#include <windows.h>

#include <sqlite3.h>

#include <ctime>

namespace slop::core::persist {

namespace {

std::string now_iso_utc() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    gmtime_s(&tm, &t);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

} // namespace

session_store_t::~session_store_t() { close(); }

bool session_store_t::open(const std::string& path, std::string* error) {
    close();
    sqlite3* db = nullptr;
    if (sqlite3_open_v2(path.c_str(), &db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                        nullptr) != SQLITE_OK) {
        if (error) *error = db ? sqlite3_errmsg(db) : "cannot open store";
        if (db) sqlite3_close(db);
        return false;
    }
    db_ = db;
    char* msg = nullptr;
    const char* ddl =
        "CREATE TABLE IF NOT EXISTS sessions("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " name TEXT NOT NULL,"
        " created_at TEXT NOT NULL,"
        " data TEXT NOT NULL);"
        "CREATE TABLE IF NOT EXISTS kv("
        " key TEXT PRIMARY KEY, value TEXT NOT NULL);";
    if (sqlite3_exec(static_cast<sqlite3*>(db_), ddl, nullptr, nullptr,
                     &msg) != SQLITE_OK) {
        if (error) *error = msg ? msg : "schema init failed";
        sqlite3_free(msg);
        close();
        return false;
    }
    return true;
}

void session_store_t::close() {
    if (db_) {
        sqlite3_close(static_cast<sqlite3*>(db_));
        db_ = nullptr;
    }
}

std::optional<uint64_t> session_store_t::save_session(
    const std::string& name, const std::string& json_data,
    std::string* error) {
    if (!ok()) {
        if (error) *error = "store not open";
        return std::nullopt;
    }
    sqlite3* db = static_cast<sqlite3*>(db_);
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO sessions(name, created_at, data) VALUES(?,?,?)",
            -1, &st, nullptr) != SQLITE_OK) {
        if (error) *error = sqlite3_errmsg(db);
        return std::nullopt;
    }
    sqlite3_bind_text(st, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, now_iso_utc().c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, json_data.c_str(), -1, SQLITE_TRANSIENT);
    const bool done = sqlite3_step(st) == SQLITE_DONE;
    if (!done && error) *error = sqlite3_errmsg(db);
    const uint64_t id = done
        ? static_cast<uint64_t>(sqlite3_last_insert_rowid(db))
        : 0;
    sqlite3_finalize(st);
    if (!done) return std::nullopt;
    return id;
}

std::vector<session_meta_t> session_store_t::list_sessions() const {
    std::vector<session_meta_t> out;
    if (!ok()) return out;
    sqlite3* db = static_cast<sqlite3*>(db_);
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db,
            "SELECT id, name, created_at FROM sessions ORDER BY id DESC",
            -1, &st, nullptr) != SQLITE_OK)
        return out;
    while (sqlite3_step(st) == SQLITE_ROW) {
        session_meta_t m;
        m.id         = static_cast<uint64_t>(sqlite3_column_int64(st, 0));
        m.name       = reinterpret_cast<const char*>(sqlite3_column_text(st, 1));
        m.created_at = reinterpret_cast<const char*>(sqlite3_column_text(st, 2));
        out.push_back(std::move(m));
    }
    sqlite3_finalize(st);
    return out;
}

std::optional<session_store_t::row_t> session_store_t::load_session(
    uint64_t id) const {
    if (!ok()) return std::nullopt;
    sqlite3* db = static_cast<sqlite3*>(db_);
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db,
            "SELECT id, name, created_at, data FROM sessions WHERE id=?",
            -1, &st, nullptr) != SQLITE_OK)
        return std::nullopt;
    sqlite3_bind_int64(st, 1, static_cast<sqlite3_int64>(id));
    std::optional<row_t> out;
    if (sqlite3_step(st) == SQLITE_ROW) {
        row_t r;
        r.id         = static_cast<uint64_t>(sqlite3_column_int64(st, 0));
        r.name       = reinterpret_cast<const char*>(sqlite3_column_text(st, 1));
        r.created_at = reinterpret_cast<const char*>(sqlite3_column_text(st, 2));
        r.data       = reinterpret_cast<const char*>(sqlite3_column_text(st, 3));
        out = std::move(r);
    }
    sqlite3_finalize(st);
    return out;
}

bool session_store_t::delete_session(uint64_t id) {
    if (!ok()) return false;
    sqlite3* db = static_cast<sqlite3*>(db_);
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, "DELETE FROM sessions WHERE id=?",
                           -1, &st, nullptr) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(st, 1, static_cast<sqlite3_int64>(id));
    const bool ok = sqlite3_step(st) == SQLITE_DONE &&
                    sqlite3_changes(db) > 0;
    sqlite3_finalize(st);
    return ok;
}

bool session_store_t::kv_set(const std::string& key, const std::string& value) {
    if (!ok()) return false;
    sqlite3* db = static_cast<sqlite3*>(db_);
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO kv(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            -1, &st, nullptr) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, value.c_str(), -1, SQLITE_TRANSIENT);
    const bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

std::optional<std::string> session_store_t::kv_get(
    const std::string& key) const {
    if (!ok()) return std::nullopt;
    sqlite3* db = static_cast<sqlite3*>(db_);
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, "SELECT value FROM kv WHERE key=?",
                           -1, &st, nullptr) != SQLITE_OK)
        return std::nullopt;
    sqlite3_bind_text(st, 1, key.c_str(), -1, SQLITE_TRANSIENT);
    std::optional<std::string> out;
    if (sqlite3_step(st) == SQLITE_ROW)
        out = reinterpret_cast<const char*>(sqlite3_column_text(st, 0));
    sqlite3_finalize(st);
    return out;
}

std::string default_store_path() {
    char base[MAX_PATH]{};
    const DWORD n = GetEnvironmentVariableA("LOCALAPPDATA", base, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return {};
    CreateDirectoryA((std::string(base, n) + "\\reverse-slop").c_str(), nullptr);
    return std::string(base, n) + "\\reverse-slop\\sessions.db";
}

} // namespace slop::core::persist

