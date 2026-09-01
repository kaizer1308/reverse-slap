// src/core/process/process_icon.cpp

#include "core/process/process_icon.hpp"

#include <windows.h>
#include <objbase.h>
#include <shellapi.h>

namespace slop::core::process {

namespace {

// RAII for the handles this walk creates; several early-out paths otherwise leak
// a DC or a bitmap on failure
struct icon_guard_t {
    HICON h = nullptr;
    ~icon_guard_t() { if (h) ::DestroyIcon(h); }
};

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    const int n = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(),
                                       static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
                          out.data(), n);
    return out;
}

icon_bits_t bits_from_icon(HICON icon) {
    icon_bits_t out;

    // GetIconInfo hands back bitmap copies the caller owns; both must be
    // released on every exit path
    ICONINFO info{};
    if (::GetIconInfo(icon, &info) == 0) return out;
    struct bmp_guard_t {
        HBITMAP color;
        HBITMAP mask;
        ~bmp_guard_t() {
            if (color) ::DeleteObject(color);
            if (mask) ::DeleteObject(mask);
        }
    } bmps{info.hbmColor, info.hbmMask};

    if (bmps.color == nullptr) return out;

    BITMAP bm{};
    if (::GetObjectW(bmps.color, sizeof(bm), &bm) == 0) return out;
    if (bm.bmWidth <= 0 || bm.bmHeight <= 0 || bm.bmWidth > 512 || bm.bmHeight > 512)
        return out;

    HDC screen = ::GetDC(nullptr);
    if (screen == nullptr) return out;

    BITMAPINFO bi{};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = bm.bmWidth;
    // Negative height requests a top-down DIB, matching what canvas ImageData
    // expects; a bottom-up buffer would render the icon upside down
    bi.bmiHeader.biHeight = -bm.bmHeight;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    std::vector<uint8_t> pixels(static_cast<size_t>(bm.bmWidth) *
                                static_cast<size_t>(bm.bmHeight) * 4);
    const int copied = ::GetDIBits(screen, bmps.color, 0,
                                   static_cast<UINT>(bm.bmHeight), pixels.data(),
                                   &bi, DIB_RGB_COLORS);
    ::ReleaseDC(nullptr, screen);
    if (copied == 0) return out;

    // 32bpp icons carry their own alpha, but a 24bpp source leaves it zeroed,
    // which would render fully transparent. Fall back to opaque in that case
    bool any_alpha = false;
    for (size_t i = 3; i < pixels.size(); i += 4) {
        if (pixels[i] != 0) {
            any_alpha = true;
            break;
        }
    }
    if (!any_alpha)
        for (size_t i = 3; i < pixels.size(); i += 4) pixels[i] = 0xFF;

    out.width  = static_cast<uint32_t>(bm.bmWidth);
    out.height = static_cast<uint32_t>(bm.bmHeight);
    out.bgra   = std::move(pixels);
    return out;
}

} // namespace

icon_bits_t icon_for_path(const std::string& image_path, bool large) {
    if (image_path.empty()) return {};
    const std::wstring wide = widen(image_path);
    if (wide.empty()) return {};

    SHFILEINFOW sfi{};
    const UINT flags = SHGFI_ICON | (large ? SHGFI_LARGEICON : SHGFI_SMALLICON);
    // SHGetFileInfo touches the shell, which needs an apartment on this thread
    // Tolerate an already-initialised one rather than failing
    const HRESULT co = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    const bool uninit = SUCCEEDED(co) && co != S_FALSE;

    icon_bits_t out;
    if (::SHGetFileInfoW(wide.c_str(), FILE_ATTRIBUTE_NORMAL, &sfi, sizeof(sfi),
                         flags) != 0 &&
        sfi.hIcon != nullptr) {
        icon_guard_t guard{sfi.hIcon};
        out = bits_from_icon(guard.h);
    }

    if (uninit) ::CoUninitialize();
    return out;
}

} // namespace slop::core::process
