#include "ui/fonts.hpp"

#include <windows.h>

#include <string>
#include <vector>

#include "imgui.h"

namespace slop::ui::fonts {

namespace {

FontSet g_set;

std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string out((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), out.data(), n, nullptr, nullptr);
    return out;
}

std::string ExeDir() {
    wchar_t buf[MAX_PATH]{};
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return {};
    std::wstring w(buf, n);
    size_t slash = w.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return {};
    w.resize(slash);
    return WideToUtf8(w);
}

std::string WinFontsDir() {
    wchar_t buf[MAX_PATH]{};
    UINT n = GetWindowsDirectoryW(buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return {};
    std::wstring w(buf, n);
    w += L"\\Fonts";
    return WideToUtf8(w);
}

bool FileExists(const std::string& path) {
    DWORD a = GetFileAttributesA(path.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

std::string FindFirst(const std::vector<std::string>& candidates) {
    for (const auto& p : candidates)
        if (FileExists(p)) return p;
    return {};
}

ImFont* LoadOrDefault(ImFontAtlas* atlas, const std::vector<std::string>& candidates, float size) {
    const std::string path = FindFirst(candidates);
    if (!path.empty()) {
        ImFontConfig cfg;
        cfg.OversampleH = 2;
        cfg.OversampleV = 1;
        cfg.PixelSnapH = false;
        return atlas->AddFontFromFileTTF(path.c_str(), size, &cfg);
    }
    ImFontConfig cfg;
    cfg.SizePixels = size;
    return atlas->AddFontDefault(&cfg);
}

} // namespace

void Load(float dpi_scale) {
    if (dpi_scale < 0.5f) dpi_scale = 1.0f;

    const std::string exe = ExeDir();
    const std::string sys = WinFontsDir();

    const std::vector<std::string> ui_candidates = {
        exe + "\\assets\\fonts\\Inter.ttf",
        exe + "\\assets\\fonts\\InterVariable.ttf",
        exe + "\\..\\assets\\fonts\\Inter.ttf",
        exe + "\\..\\..\\assets\\fonts\\Inter.ttf",
        sys + "\\segoeui.ttf",
    };
    const std::vector<std::string> mono_candidates = {
        exe + "\\assets\\fonts\\JetBrainsMono-Regular.ttf",
        exe + "\\assets\\fonts\\JetBrainsMonoNL-Regular.ttf",
        exe + "\\..\\assets\\fonts\\JetBrainsMono-Regular.ttf",
        exe + "\\..\\..\\assets\\fonts\\JetBrainsMono-Regular.ttf",
        sys + "\\consola.ttf",
    };

    ImGuiIO& io = ImGui::GetIO();
    ImFontAtlas* atlas = io.Fonts;
    atlas->Clear();

    g_set.ui        = LoadOrDefault(atlas, ui_candidates,   15.0f * dpi_scale);
    g_set.ui_small  = LoadOrDefault(atlas, ui_candidates,   13.0f * dpi_scale);
    g_set.ui_header = LoadOrDefault(atlas, ui_candidates,   18.0f * dpi_scale);
    g_set.mono      = LoadOrDefault(atlas, mono_candidates, 14.0f * dpi_scale);

    io.FontDefault = g_set.ui;
}

const FontSet& Get() { return g_set; }

} // namespace slop::ui::fonts
