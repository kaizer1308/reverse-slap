// src/core/util/fs_tools.cpp

#include "core/util/fs_tools.hpp"

#include <windows.h>

#include <algorithm>
#include <fstream>
#include <functional>
#include <iterator>

namespace slop::core::util {

namespace {

std::wstring to_w(const std::string& s) {
    return std::wstring(s.begin(), s.end());
}

std::string lower_copy(std::string s) {
    for (char& c : s)
        c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    return s;
}

} // namespace

bool read_file(const std::string& path, std::vector<uint8_t>* out,
               size_t max_bytes, std::string* error) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        if (error) *error = "cannot open file";
        return false;
    }
    f.seekg(0, std::ios::end);
    const auto size = f.tellg();
    if (size < 0) {
        if (error) *error = "cannot stat file";
        return false;
    }
    f.seekg(0, std::ios::beg);
    const size_t len =
        static_cast<size_t>(std::min<uint64_t>(size, max_bytes));
    out->resize(len);
    f.read(reinterpret_cast<char*>(out->data()), len);
    return true;
}

bool write_file(const std::string& path, const std::vector<uint8_t>& bytes,
                bool append, std::string* error) {
    std::ofstream f(path, std::ios::binary |
                              (append ? std::ios::app : std::ios::trunc));
    if (!f) {
        if (error) *error = "cannot open file for writing";
        return false;
    }
    f.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
    return true;
}

std::vector<file_entry_t> list_directory(const std::string& dir,
                                         std::string* error) {
    std::vector<file_entry_t> out;
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW((to_w(dir) + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) {
        if (error) *error = "cannot list directory";
        return out;
    }
    do {
        if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L".."))
            continue;
        file_entry_t e;
        std::wstring wname(fd.cFileName);
        e.name.assign(wname.begin(), wname.end());
        e.path = dir + "\\" + e.name;
        ULARGE_INTEGER sz;
        sz.HighPart = fd.nFileSizeHigh;
        sz.LowPart = fd.nFileSizeLow;
        e.size = sz.QuadPart;
        e.directory = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        out.push_back(std::move(e));
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return out;
}

bool create_directory(const std::string& path, std::string* error) {
    if (!CreateDirectoryW(to_w(path).c_str(), nullptr)) {
        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            if (error) *error = "create failed";
            return false;
        }
    }
    return true;
}

bool delete_path(const std::string& path, std::string* error) {
    if (DeleteFileW(to_w(path).c_str())) return true;
    if (RemoveDirectoryW(to_w(path).c_str())) return true;
    if (error) *error = "delete failed";
    return false;
}

std::vector<file_entry_t> search_files(const std::string& root,
                                       const std::string& needle,
                                       size_t max_results) {
    std::vector<file_entry_t> out;
    const std::string needle_l = lower_copy(needle);

    std::function<void(const std::string&, int)> walk =
        [&](const std::string& dir, int depth) {
            if (depth > 8 || out.size() >= max_results) return;
            for (const auto& e : list_directory(dir)) {
                if (out.size() >= max_results) return;
                if (lower_copy(e.name).find(needle_l) != std::string::npos)
                    out.push_back(e);
                if (e.directory && depth < 8) walk(e.path, depth + 1);
            }
        };
    walk(root, 0);
    return out;
}


std::vector<grep_hit_t> grep_in_files(const std::string& root,
                                      const std::string& needle,
                                      const std::string& glob_suffix,
                                      size_t max_hits) {
    std::vector<grep_hit_t> out;
    const std::string needle_l = lower_copy(needle);

    std::function<void(const std::string&, int)> walk =
        [&](const std::string& dir, int depth) {
            if (out.size() >= max_hits || depth > 6) return;
            for (const auto& e : list_directory(dir)) {
                if (out.size() >= max_hits) return;
                if (e.directory) { walk(e.path, depth + 1); continue; }
                if (!glob_suffix.empty()) {
                    const std::string nl = lower_copy(e.name);
                    if (nl.rfind(lower_copy(glob_suffix)) ==
                        std::string::npos ||
                        nl.size() < glob_suffix.size())
                        continue;
                }
                std::ifstream f(e.path, std::ios::binary);
                if (!f) continue;
                std::string line;
                uint32_t lineno = 0;
                while (std::getline(f, line)) {
                    ++lineno;
                    if (lower_copy(line).find(needle_l) !=
                        std::string::npos) {
                        grep_hit_t hit;
                        hit.path = e.path;
                        hit.line = lineno;
                        hit.text = line.substr(
                            0, std::min<size_t>(line.size(), 240));
                        out.push_back(std::move(hit));
                        if (out.size() >= max_hits) return;
                    }
                }
            }
        };
    walk(root, 0);
    return out;
}

} // namespace slop::core::util


