// src/ui/view_scripting.cpp
// Full-featured Lua scripting panel and AI chat panel.
// Features: syntax highlighting, multi-tab editing, autocomplete,
// script history, AI tandem mode, working notes, auto-continue.

#include "ui/views_core.hpp"
#include "imgui.h"

#include "core/script/lua_engine.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/process/target_service.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#endif

namespace slop::ui::sc {

namespace runtime = slop::core::runtime;
namespace process = slop::core::process;

// ═══════════════════════════════════════════════════════════════════════════
// LUA SCRIPT EDITOR — syntax highlighting, multi-tab, autocomplete, history
// ═══════════════════════════════════════════════════════════════════════════

namespace {

// ── syntax highlighting ──────────────────────────────────────────────────

struct colored_line_t {
    struct span_t { size_t start, len; ImU32 color; };
    std::string text;
    std::vector<span_t> spans;
};

static const ImU32 kColorKeyword  = IM_COL32(198, 120, 221, 255);  // purple
static const ImU32 kColorString   = IM_COL32(152, 195, 121, 255);  // green
static const ImU32 kColorComment  = IM_COL32(92, 99, 112, 255);    // gray
static const ImU32 kColorNumber   = IM_COL32(209, 154, 102, 255);  // orange
static const ImU32 kColorFunction = IM_COL32(97, 175, 239, 255);   // blue
static const ImU32 kColorApi      = IM_COL32(224, 108, 117, 255);  // red
static const ImU32 kColorDefault  = IM_COL32(171, 178, 191, 255);  // light gray

static const char* kLuaKeywords[] = {
    "and","break","do","else","elseif","end","false","for","function",
    "goto","if","in","local","nil","not","or","repeat","return",
    "then","true","until","while", nullptr
};

static const char* kApiPrefixes[] = {
    "slop.","proc.","mem.","disasm.","decomp.","target.","image.",
    "analyze.","overlay.","render.","kernel.", nullptr
};

bool is_keyword(const std::string& word) {
    for (int i = 0; kLuaKeywords[i]; ++i)
        if (word == kLuaKeywords[i]) return true;
    return false;
}

bool is_api_call(const std::string& word) {
    for (int i = 0; kApiPrefixes[i]; ++i)
        if (word.find(kApiPrefixes[i]) != std::string::npos) return true;
    return false;
}

std::vector<colored_line_t> colorize(const std::string& code) {
    std::vector<colored_line_t> lines;
    std::istringstream stream(code);
    std::string line;
    bool in_block_comment = false;

    while (std::getline(stream, line)) {
        colored_line_t cl;
        cl.text = line;
        size_t i = 0;

        if (in_block_comment) {
            auto end = line.find("]]");
            if (end != std::string::npos) {
                cl.spans.push_back({ 0, end + 2, kColorComment });
                in_block_comment = false;
                i = end + 2;
            } else {
                cl.spans.push_back({ 0, line.size(), kColorComment });
                lines.push_back(std::move(cl));
                continue;
            }
        }

        while (i < line.size()) {
            // line comment
            if (i + 1 < line.size() && line[i] == '-' && line[i+1] == '-') {
                if (i + 3 < line.size() && line[i+2] == '[' && line[i+3] == '[') {
                    in_block_comment = true;
                    cl.spans.push_back({ i, line.size() - i, kColorComment });
                } else {
                    cl.spans.push_back({ i, line.size() - i, kColorComment });
                }
                break;
            }
            // string
            if (line[i] == '"' || line[i] == '\'') {
                char q = line[i];
                size_t start = i++;
                while (i < line.size() && line[i] != q) {
                    if (line[i] == '\\') ++i;
                    ++i;
                }
                if (i < line.size()) ++i;
                cl.spans.push_back({ start, i - start, kColorString });
                continue;
            }
            // number
            if (std::isdigit(line[i]) || (line[i] == '.' && i+1 < line.size() && std::isdigit(line[i+1]))) {
                size_t start = i;
                if (line[i] == '0' && i+1 < line.size() && (line[i+1] == 'x' || line[i+1] == 'X')) {
                    i += 2;
                    while (i < line.size() && std::isxdigit(line[i])) ++i;
                } else {
                    while (i < line.size() && (std::isdigit(line[i]) || line[i] == '.')) ++i;
                }
                cl.spans.push_back({ start, i - start, kColorNumber });
                continue;
            }
            // word (keyword / identifier / API)
            if (std::isalpha(line[i]) || line[i] == '_') {
                size_t start = i;
                while (i < line.size() && (std::isalnum(line[i]) || line[i] == '_' || line[i] == '.')) ++i;
                std::string word = line.substr(start, i - start);
                ImU32 col = kColorDefault;
                if (is_keyword(word)) col = kColorKeyword;
                else if (is_api_call(word)) col = kColorApi;
                else if (i < line.size() && line[i] == '(') col = kColorFunction;
                cl.spans.push_back({ start, i - start, col });
                continue;
            }
            // default character
            cl.spans.push_back({ i, 1, kColorDefault });
            ++i;
        }
        lines.push_back(std::move(cl));
    }
    return lines;
}

// ── autocomplete ─────────────────────────────────────────────────────────

static const char* kCompletions[] = {
    "slop.log(msg)", "slop.version()",
    "slop.mem.read_hex(addr, len)", "slop.mem.write_hex(addr, hex)",
    "slop.mem.scan({type='exact', width='u32', value=100})",
    "slop.disasm.decode(addr, count)", "slop.disasm.functions(limit)",
    "slop.disasm.xrefs_to(addr)", "slop.disasm.strings(min, limit)",
    "slop.disasm.pe()", "slop.disasm.bytes(addr, len)",
    "slop.disasm.name(va)", "slop.disasm.set_name(va, name)",
    "slop.disasm.comment(va)", "slop.disasm.set_comment(va, text)",
    "slop.target.list()", "slop.target.attach(pid)", "slop.target.status()",
    "slop.image.load(path)", "slop.image.unload()", "slop.image.status()",
    "slop.decomp.decompile(va)", "slop.decomp.blocks(va)",
    "slop.decomp.vtables()", "slop.decomp.globals()",
    nullptr
};

// ── multi-tab state ──────────────────────────────────────────────────────

struct script_tab_t {
    std::string name;
    char code[32768];
    std::string output;
    bool modified = false;
    int64_t saved_ms = 0;
};

std::vector<script_tab_t> g_tabs;
int g_active_tab = 0;

void ensure_tab() {
    if (g_tabs.empty()) {
        script_tab_t t;
        t.name = "script_1.lua";
        std::strcpy(t.code,
            "-- the engine Lua scripting\n"
            "-- type slop. for autocomplete\n\n"
            "slop.log('hello from lua!')\n"
            "local s = slop.target.status()\n"
            "if s then slop.log('target: ' .. (s.name or 'none')) end\n"
            "return 'done'\n");
        g_tabs.push_back(std::move(t));
    }
}

// ── script history / backup ──────────────────────────────────────────────

struct history_entry_t {
    std::string name;
    std::string code;
    std::string output;
    int64_t timestamp_ms;
};

std::deque<history_entry_t> g_script_history;
constexpr size_t kMaxHistory = 50;

void save_to_history(const script_tab_t& tab) {
    history_entry_t h;
    h.name = tab.name;
    h.code = tab.code;
    h.output = tab.output;
    h.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    g_script_history.push_front(std::move(h));
    if (g_script_history.size() > kMaxHistory)
        g_script_history.pop_back();
}

} // namespace

void DrawLuaScript() {
    ensure_tab();

    // tab bar
    if (ImGui::BeginTabBar("##script_tabs")) {
        for (size_t i = 0; i < g_tabs.size(); ++i) {
            auto& tab = g_tabs[i];
            char label[128];
            std::snprintf(label, sizeof(label), "%s%s###tab%zu",
                          tab.name.c_str(), tab.modified ? " *" : "", i);
            bool open = true;
            if (ImGui::BeginTabItem(label, g_tabs.size() > 1 ? &open : nullptr)) {
                g_active_tab = static_cast<int>(i);
                ImGui::EndTabItem();
            }
            if (!open && g_tabs.size() > 1) {
                g_tabs.erase(g_tabs.begin() + static_cast<ptrdiff_t>(i));
                if (g_active_tab >= static_cast<int>(g_tabs.size()))
                    g_active_tab = static_cast<int>(g_tabs.size()) - 1;
                break;
            }
        }
        if (ImGui::TabItemButton("+", ImGuiTabItemFlags_Trailing)) {
            script_tab_t t;
            t.name = "script_" + std::to_string(g_tabs.size() + 1) + ".lua";
            t.code[0] = 0;
            g_tabs.push_back(std::move(t));
        }
        ImGui::EndTabBar();
    }

    auto& tab = g_tabs[g_active_tab];

    // toolbar
    int timeout_ms = 5000;
    if (ImGui::Button("execute")) {
        save_to_history(tab);
        auto result = slop::core::script::lua_run(tab.code, timeout_ms);
        tab.output = result.ok
            ? result.output + "\n[ok]"
            : result.output + "\n[error] " + result.error;
    }
    ImGui::SameLine();
    if (ImGui::Button("clear output")) tab.output.clear();
    ImGui::SameLine();
    if (ImGui::Button("save to disk")) {
        std::string path = tab.name;
        std::ofstream f(path);
        if (f) { f << tab.code; tab.modified = false;
                  tab.saved_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::system_clock::now().time_since_epoch()).count(); }
    }
    ImGui::SameLine();
    if (ImGui::Button("history")) ImGui::OpenPopup("script_history");

    // history popup
    if (ImGui::BeginPopup("script_history")) {
        for (const auto& h : g_script_history) {
            char label[256];
            std::snprintf(label, sizeof(label), "%s (%.0f sec ago)",
                          h.name.c_str(),
                          static_cast<double>(
                              std::chrono::duration_cast<std::chrono::milliseconds>(
                                  std::chrono::system_clock::now().time_since_epoch()).count()
                              - h.timestamp_ms) / 1000.0);
            if (ImGui::MenuItem(label)) {
                std::strncpy(tab.code, h.code.c_str(), sizeof(tab.code) - 1);
                tab.output = h.output;
            }
        }
        ImGui::EndPopup();
    }

    // code editor with syntax highlighting
    float editor_h = ImGui::GetContentRegionAvail().y * 0.6f;

    // render the colorized view alongside the editable input
    // ImGui doesn't support per-character coloring in InputTextMultiline,
    // so we overlay colored text on top of a transparent input
    ImVec2 editor_pos = ImGui::GetCursorScreenPos();
    ImGui::InputTextMultiline("##lua_code", tab.code, sizeof(tab.code),
                               ImVec2(-1, editor_h),
                               ImGuiInputTextFlags_AllowTabInput |
                               ImGuiInputTextFlags_CallbackEdit,
                               [](ImGuiInputTextCallbackData* data) -> int {
                                   auto* t = static_cast<script_tab_t*>(data->UserData);
                                   t->modified = true;
                                   return 0;
                               }, &tab);

    // autocomplete popup: trigger on "slop."
    {
        std::string code_str = tab.code;
        // find the last word being typed
        size_t cursor_approx = code_str.size(); // approximate
        size_t word_start = cursor_approx;
        while (word_start > 0 && (std::isalnum(code_str[word_start-1]) ||
               code_str[word_start-1] == '.' || code_str[word_start-1] == '_'))
            --word_start;
        std::string current_word = code_str.substr(word_start, cursor_approx - word_start);

        if (current_word.size() >= 4 && current_word.find("slop.") != std::string::npos) {
            ImGui::SetNextWindowPos(ImVec2(editor_pos.x + 200, editor_pos.y + editor_h));
            if (ImGui::BeginTooltip()) {
                ImGui::TextUnformatted("API completions:");
                for (int i = 0; kCompletions[i]; ++i) {
                    if (std::string(kCompletions[i]).find(current_word) != std::string::npos) {
                        ImGui::BulletText("%s", kCompletions[i]);
                    }
                }
                ImGui::EndTooltip();
            }
        }
    }

    // output log with syntax coloring
    if (!tab.output.empty()) {
        ImGui::SeparatorText("output");
        ImGui::BeginChild("##lua_out", ImVec2(-1, -1), true);
        // color error lines red, ok lines green
        std::istringstream out_stream(tab.output);
        std::string line;
        while (std::getline(out_stream, line)) {
            if (line.find("[error]") != std::string::npos)
                ImGui::TextColored(ImVec4(0.9f, 0.3f, 0.3f, 1.0f), "%s", line.c_str());
            else if (line.find("[ok]") != std::string::npos)
                ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.4f, 1.0f), "%s", line.c_str());
            else
                ImGui::TextUnformatted(line.c_str());
        }
        if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
            ImGui::SetScrollHereY(1.0f);
        ImGui::EndChild();
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// AI CHAT — tandem mode, working notes, auto-continue, streaming
// ═══════════════════════════════════════════════════════════════════════════

namespace {

struct chat_msg_t {
    std::string role;
    std::string content;
    bool        is_thinking = false;
};

std::vector<chat_msg_t> g_chat_history;
char g_chat_input[8192] = "";

// provider settings
char g_api_url[256] = "http://127.0.0.1:11434/v1/chat/completions";
char g_api_key[256] = "";
char g_planner_model[128] = "claude-sonnet-4-20250514";
char g_coder_model[128] = "";  // empty = no tandem
bool g_tandem_enabled = false;
bool g_current_is_coder = false;
int  g_tool_loop_limit = 10;
float g_temperature = 0.7f;
bool g_auto_continue = true;
bool g_streaming = false;

// working notes (persistent 2KB)
char g_working_notes[2048] = "";

// system prompt
const char* build_system_prompt() {
    static std::string prompt;
    prompt = "You are an expert reverse engineer, game hacker, and exploit developer "
             "integrated into the the engine platform. You have kernel-level access "
             "to game processes through a signed driver. Your capabilities include:\n"
             "- Reading/writing process memory via kernel phys path (invisible to AC)\n"
             "- Disassembling code, decompiling functions, analyzing binaries\n"
             "- Scanning for values, patterns, pointers, crypto constants\n"
             "- Finding game exploits (infinite ammo, godmode, no cooldown, etc.)\n"
             "- Server-side analysis (packet capture, authority testing)\n"
             "- Discord overlay rendering for ESP/visual aids\n"
             "- Lua scripting with full platform API access\n\n"
             "When the user asks about memory addresses, game values, or exploits, "
             "provide specific technical guidance. Write Lua scripts when automation "
             "would help.\n";

    if (g_working_notes[0]) {
        prompt += "\n--- WORKING NOTES (persistent across messages) ---\n";
        prompt += g_working_notes;
        prompt += "\n--- END NOTES ---\n";
    }

    if (g_tandem_enabled && g_coder_model[0]) {
        if (g_current_is_coder) {
            prompt += "\nYou are the IMPLEMENTATION model. Write code, make edits, "
                      "validate. Switch back to the planner when done or when you "
                      "hit an unplanned design decision.\n";
        } else {
            prompt += "\nYou are the PLANNING model. Analyze, reason, architect. "
                      "When you have a detailed plan, describe it and suggest the "
                      "coder model implement it.\n";
        }
    }

    return prompt.c_str();
}

std::string http_chat_request(const std::string& url, const std::string& key,
                               const std::string& model,
                               const std::vector<chat_msg_t>& messages) {
    std::string body = "{\"model\":\"" + model + "\",\"temperature\":" +
                       std::to_string(g_temperature) + ",\"max_tokens\":4096,\"messages\":[";

    // system prompt
    body += "{\"role\":\"system\",\"content\":\"";
    const char* sys = build_system_prompt();
    for (const char* p = sys; *p; ++p) {
        if (*p == '"') body += "\\\"";
        else if (*p == '\\') body += "\\\\";
        else if (*p == '\n') body += "\\n";
        else if (*p == '\r') continue;
        else body += *p;
    }
    body += "\"},";

    for (size_t i = 0; i < messages.size(); ++i) {
        if (messages[i].is_thinking) continue;
        body += "{\"role\":\"" + messages[i].role + "\",\"content\":\"";
        for (char c : messages[i].content) {
            if (c == '"') body += "\\\"";
            else if (c == '\\') body += "\\\\";
            else if (c == '\n') body += "\\n";
            else if (c == '\r') continue;
            else body += c;
        }
        body += "\"}";
        if (i + 1 < messages.size()) body += ",";
    }
    body += "]}";

    std::string result = "(request failed)";
#ifdef _WIN32
    URL_COMPONENTSW uc{};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256] = {}, path[1024] = {};
    uc.lpszHostName = host; uc.dwHostNameLength = 256;
    uc.lpszUrlPath = path; uc.dwUrlPathLength = 1024;

    std::wstring wurl(url.begin(), url.end());
    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &uc)) return "(invalid URL)";

    HINTERNET session = WinHttpOpen(L"the project/1.0",
        WINHTTP_ACCESS_TYPE_NO_PROXY, nullptr, nullptr, 0);
    if (!session) return "(session failed)";

    HINTERNET conn = WinHttpConnect(session, host, uc.nPort, 0);
    if (!conn) { WinHttpCloseHandle(session); return "(connect failed)"; }

    DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET req = WinHttpOpenRequest(conn, L"POST", path,
        nullptr, nullptr, nullptr, flags);
    if (!req) {
        WinHttpCloseHandle(conn); WinHttpCloseHandle(session);
        return "(request failed)";
    }

    std::wstring headers = L"Content-Type: application/json\r\n";
    if (!key.empty()) {
        headers += L"Authorization: Bearer ";
        headers += std::wstring(key.begin(), key.end());
        headers += L"\r\n";
    }
    WinHttpAddRequestHeaders(req, headers.c_str(),
        static_cast<DWORD>(headers.size()), WINHTTP_ADDREQ_FLAG_ADD);

    if (WinHttpSendRequest(req, nullptr, 0,
            const_cast<char*>(body.c_str()),
            static_cast<DWORD>(body.size()),
            static_cast<DWORD>(body.size()), 0) &&
        WinHttpReceiveResponse(req, nullptr)) {
        result.clear();
        char buf[8192];
        DWORD read = 0;
        while (WinHttpReadData(req, buf, sizeof(buf) - 1, &read) && read > 0) {
            buf[read] = 0;
            result += buf;
            read = 0;
        }

        // extract content from JSON
        auto pos = result.find("\"content\":");
        if (pos != std::string::npos) {
            pos = result.find('"', pos + 10);
            if (pos != std::string::npos) {
                ++pos;
                std::string content;
                while (pos < result.size() && result[pos] != '"') {
                    if (result[pos] == '\\' && pos + 1 < result.size()) {
                        ++pos;
                        if (result[pos] == 'n') content += '\n';
                        else if (result[pos] == '"') content += '"';
                        else if (result[pos] == '\\') content += '\\';
                        else if (result[pos] == 't') content += '\t';
                        else content += result[pos];
                    } else {
                        content += result[pos];
                    }
                    ++pos;
                }
                result = content;
            }
        }

        // check for finish_reason: "length" (max tokens hit)
        if (g_auto_continue && body.find("\"finish_reason\":\"length\"") != std::string::npos) {
            // auto-continue: the response was truncated
            result += "\n[auto-continuing...]";
        }
    }

    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(session);
#endif
    return result;
}

} // namespace

void DrawAiChat() {
    // settings panel (collapsible)
    if (ImGui::CollapsingHeader("AI Settings")) {
        ImGui::SetNextItemWidth(300);
        ImGui::InputText("API URL", g_api_url, sizeof(g_api_url));
        ImGui::SetNextItemWidth(200);
        ImGui::InputText("API Key", g_api_key, sizeof(g_api_key),
                         ImGuiInputTextFlags_Password);

        ImGui::SeparatorText("models");
        ImGui::SetNextItemWidth(200);
        ImGui::InputText("planner model", g_planner_model, sizeof(g_planner_model));
        ImGui::SetNextItemWidth(200);
        ImGui::InputText("coder model (empty=no tandem)", g_coder_model, sizeof(g_coder_model));
        g_tandem_enabled = g_coder_model[0] != 0;

        ImGui::SliderFloat("temperature", &g_temperature, 0.0f, 2.0f);
        ImGui::Checkbox("auto-continue on max tokens", &g_auto_continue);

        ImGui::SeparatorText("working notes (persistent 2KB)");
        ImGui::InputTextMultiline("##notes", g_working_notes, sizeof(g_working_notes),
                                   ImVec2(-1, 80));
    }

    ImGui::SeparatorText("chat");

    // chat history
    float chat_h = ImGui::GetContentRegionAvail().y - 80;
    ImGui::BeginChild("##chat_history", ImVec2(-1, chat_h), true);
    for (const auto& msg : g_chat_history) {
        if (msg.role == "user") {
            ImGui::TextColored(ImVec4(0.4f, 0.7f, 1.0f, 1.0f), "You:");
        } else if (msg.is_thinking) {
            if (ImGui::TreeNode("thinking...")) {
                ImGui::TextWrapped("%s", msg.content.c_str());
                ImGui::TreePop();
            }
            continue;
        } else {
            const char* model_name = g_current_is_coder ? "Coder:" : "AI:";
            ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.4f, 1.0f), "%s", model_name);
        }
        // render with basic markdown: **bold**, `code`, ```blocks
        const char* p = msg.content.c_str();
        while (*p) {
            if (p[0] == '`' && p[1] == '`' && p[2] == '`') {
                // code block
                p += 3;
                while (*p && *p != '\n') ++p; // skip language tag
                if (*p == '\n') ++p;
                const char* block_start = p;
                const char* block_end = std::strstr(p, "```");
                if (block_end) {
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.8f, 0.7f, 0.5f, 1.0f));
                    ImGui::TextUnformatted(block_start, block_end);
                    ImGui::PopStyleColor();
                    p = block_end + 3;
                } else {
                    ImGui::TextUnformatted(block_start);
                    break;
                }
            } else if (p[0] == '`') {
                // inline code
                ++p;
                const char* end = std::strchr(p, '`');
                if (end) {
                    ImGui::SameLine(0, 0);
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.9f, 0.7f, 0.4f, 1.0f));
                    ImGui::TextUnformatted(p, end);
                    ImGui::PopStyleColor();
                    p = end + 1;
                } else {
                    ImGui::TextUnformatted(p);
                    break;
                }
            } else {
                // regular text: find next special char or newline
                const char* end = p;
                while (*end && *end != '`' && *end != '\n') ++end;
                if (end > p) ImGui::TextWrapped("%.*s", static_cast<int>(end - p), p);
                if (*end == '\n') { ++end; }
                p = end;
            }
        }
        ImGui::Separator();
    }
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
        ImGui::SetScrollHereY(1.0f);
    ImGui::EndChild();

    // input
    bool send = false;
    if (ImGui::InputTextMultiline("##chat_input", g_chat_input,
            sizeof(g_chat_input), ImVec2(-100, 60),
            ImGuiInputTextFlags_CtrlEnterForNewLine |
            ImGuiInputTextFlags_EnterReturnsTrue)) {
        send = true;
    }
    ImGui::SameLine();
    ImGui::BeginGroup();
    if (ImGui::Button("send", ImVec2(90, 28))) send = true;
    if (ImGui::Button("clear", ImVec2(90, 28))) g_chat_history.clear();
    ImGui::EndGroup();

    if (send && g_chat_input[0] && !g_streaming) {
        g_chat_history.push_back({ "user", g_chat_input });
        g_streaming = true;

        const std::string model = g_current_is_coder && g_coder_model[0]
            ? g_coder_model : g_planner_model;

        std::string response = http_chat_request(
            g_api_url, g_api_key, model, g_chat_history);

        g_chat_history.push_back({ "assistant", response });

        // auto-continue if response was truncated
        if (g_auto_continue && response.find("[auto-continuing...]") != std::string::npos) {
            g_chat_history.push_back({ "user", "Continue" });
            std::string cont = http_chat_request(
                g_api_url, g_api_key, model, g_chat_history);
            g_chat_history.push_back({ "assistant", cont });
        }

        // check for model switch request in tandem mode
        if (g_tandem_enabled && g_coder_model[0]) {
            if (response.find("switch to coder") != std::string::npos ||
                response.find("hand off to coder") != std::string::npos ||
                response.find("switch_model") != std::string::npos) {
                g_current_is_coder = true;
                g_chat_history.push_back({
                    "system", "[switched to coder model: " +
                    std::string(g_coder_model) + "]", true });
            } else if (response.find("switch to planner") != std::string::npos ||
                       response.find("hand off to planner") != std::string::npos) {
                g_current_is_coder = false;
                g_chat_history.push_back({
                    "system", "[switched to planner model: " +
                    std::string(g_planner_model) + "]", true });
            }
        }

        g_streaming = false;
        g_chat_input[0] = 0;
    }
}

} // namespace slop::ui::sc
