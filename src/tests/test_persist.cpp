// src/tests/test_persist.cpp
// SQLite session store roundtrips against a temp database file

#include "harness.hpp"

#include "core/persist/session_store.hpp"

#include <cstdio>
#include <cstdlib>
#include <process.h>
#include <string>

#include <windows.h>

using namespace slop::core::persist;

namespace {

std::string temp_db_path() {
    char path[MAX_PATH];
    std::snprintf(path, sizeof(path), "%s\\slop_sessions_%u.db",
                  std::getenv("TEMP"), static_cast<unsigned>(::_getpid()));
    return path;
}

} // namespace

TEST_CASE(session_store_roundtrip) {
    const std::string path = temp_db_path();
    remove(path.c_str());

    {
        session_store_t db;
        std::string err;
        REQUIRE(db.open(path, &err));
        REQUIRE(err.empty());

        auto id = db.save_session("first", R"({"pid":1234,"bps":[]})", &err);
        REQUIRE(id.has_value());
        REQUIRE_GT(*id, 0u);

        id = db.save_session("second", R"({"pid":42})", &err);
        REQUIRE(id.has_value());

        auto rows = db.list_sessions();
        REQUIRE_EQ(rows.size(), 2u);
        REQUIRE_STR_EQ(rows[0].name.c_str(), "second");   // newest first

        auto loaded = db.load_session(rows[1].id);
        REQUIRE(loaded.has_value());
        REQUIRE_STR_EQ(loaded->data.c_str(), R"({"pid":1234,"bps":[]})");

        // kv table
        REQUIRE(db.kv_set("layout_main", "{\"dock\":\"left\"}"));
        auto v = db.kv_get("layout_main");
        REQUIRE(v.has_value());
        REQUIRE_STR_EQ(v->c_str(), "{\"dock\":\"left\"}");

        // overwrite
        REQUIRE(db.kv_set("layout_main", "v2"));
        v = db.kv_get("layout_main");
        REQUIRE(v.has_value());
        REQUIRE_STR_EQ(v->c_str(), "v2");
    }

    // Reopen: data persists
    {
        session_store_t db;
        REQUIRE(db.open(path));
        auto rows = db.list_sessions();
        REQUIRE_EQ(rows.size(), 2u);

        REQUIRE(db.delete_session(rows[0].id));
        REQUIRE(!db.delete_session(rows[0].id));   // already gone
        REQUIRE_EQ(db.list_sessions().size(), 1u);
    }
    remove(path.c_str());
}

TEST_CASE(session_store_unopen_is_safe) {
    session_store_t db;
    REQUIRE(!db.ok());
    REQUIRE_EQ(db.list_sessions().size(), 0u);
    REQUIRE(!db.load_session(1).has_value());
    REQUIRE(!db.delete_session(1));
    REQUIRE(!db.kv_set("k", "v"));
    REQUIRE(!db.kv_get("k").has_value());
}

