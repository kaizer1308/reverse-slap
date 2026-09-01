#pragma once

// sqlite session snapshots plus a kv table, symbols keep their per hash
// json store

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace slop::core::persist {

struct session_meta_t {
    uint64_t    id = 0;
    std::string name;
    std::string created_at;
};

class session_store_t {
public:
    session_store_t() = default;
    ~session_store_t();

    session_store_t(const session_store_t&)            = delete;
    session_store_t& operator=(const session_store_t&) = delete;

    bool open(const std::string& path, std::string* error = nullptr);
    void close();
    bool ok() const { return db_ != nullptr; }

    // sessions
    std::optional<uint64_t> save_session(const std::string& name,
                                         const std::string& json_data,
                                         std::string* error = nullptr);
    struct row_t : session_meta_t {
        std::string data;
    };
    std::vector<session_meta_t> list_sessions() const;
    std::optional<row_t> load_session(uint64_t id) const;
    bool delete_session(uint64_t id);

    // key/value (layouts etc.)
    bool kv_set(const std::string& key, const std::string& value);
    std::optional<std::string> kv_get(const std::string& key) const;

private:
    void* db_ = nullptr;   // sqlite3*
};

std::string default_store_path();   // %LOCALAPPDATA%\reverse-slop\sessions.db

} // namespace slop::core::persist
