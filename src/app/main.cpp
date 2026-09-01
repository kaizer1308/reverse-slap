#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <dcomp.h>
#include <dwmapi.h>

#include <array>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <filesystem>
#include <string>
#include <chrono>
#include <thread>

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#include "ui/chrome.hpp"
#include "ui/dockspace.hpp"
#include "ui/fonts.hpp"
#include "ui/panels.hpp"
#include "ui/theme.hpp"
#include "ui/views_core.hpp"

#include "core/infra/app_control.hpp"
#include "core/infra/lifecycle.hpp"
#include "core/process/target_service.hpp"
#include "core/runtime/backend_registry.hpp"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// boot sequence for the loading screen

namespace {

namespace lifecycle = slop::core::infra::lifecycle;

std::string exe_dir_path() {
    char path[MAX_PATH]{};
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    std::string p(path);
    const size_t slash = p.find_last_of("\\/");
    return slash == std::string::npos ? "." : p.substr(0, slash);
}

void draw_loading_screen() {
    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(io.DisplaySize);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.02f, 0.02f, 0.03f, 1.0f));
    ImGui::Begin("##boot_splash", nullptr,
                 ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                 ImGuiWindowFlags_NoBringToFrontOnFocus |
                 ImGuiWindowFlags_NoSavedSettings);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImVec2 vp_min = ImGui::GetWindowPos();
    const float w = io.DisplaySize.x;
    const float h = io.DisplaySize.y;

    dl->AddRectFilled(vp_min, ImVec2(vp_min.x + w, vp_min.y + 3.0f),
                      IM_COL32(255, 122, 51, 235));

    const ImVec2 size(std::min(620.0f, w * 0.86f), 400.0f);
    const ImVec2 origin((w - size.x) * 0.5f, (h - size.y) * 0.5f);

    ImFont* big = slop::ui::fonts::Get().ui_header
                      ? slop::ui::fonts::Get().ui_header
                      : ImGui::GetFont();
    ImFont* mono = slop::ui::fonts::Get().mono
                       ? slop::ui::fonts::Get().mono
                       : ImGui::GetFont();

    ImGui::SetCursorPos(ImVec2(origin.x, origin.y));
    ImGui::BeginChild("##boot_panel", size, true,
                      ImGuiWindowFlags_NoScrollbar);

    ImGui::PushFont(big);
    ImGui::TextUnformatted("reverse-slop");
    ImGui::PopFont();
    ImGui::TextDisabled("windows reverse-engineering workbench, booting");
    ImGui::Separator();
    ImGui::Spacing();

    auto row = [](const char* label, const char* st) {
        if (std::strcmp(st, "ok") == 0)
            ImGui::TextColored(ImVec4(0.45f, 0.85f, 0.50f, 1.0f),
                               "[ ok ] %s", label);
        else if (std::strcmp(st, "fail") == 0)
            ImGui::TextColored(ImVec4(0.90f, 0.40f, 0.38f, 1.0f),
                               "[ !! ] %s", label);
        else if (std::strcmp(st, "run") == 0)
            ImGui::TextColored(ImVec4(0.95f, 0.75f, 0.35f, 1.0f),
                               "[ .. ] %s", label);
        else
            ImGui::TextDisabled("[    ] %s", label);
    };

    const auto boot = lifecycle::result();
    const auto cur  = lifecycle::stage();

    auto kernel_row = [&]() -> const char* {
        if (static_cast<int>(cur) > static_cast<int>(lifecycle::stage_t::kernel_bridge))
            return boot.kernel_ok ? "ok" : "fail";
        return lifecycle::stage_status(lifecycle::stage_t::kernel_bridge);
    };

    row(lifecycle::stage_label(lifecycle::stage_t::runtime_pool),
        lifecycle::stage_status(lifecycle::stage_t::runtime_pool));
    row(lifecycle::stage_label(lifecycle::stage_t::process_services),
        lifecycle::stage_status(lifecycle::stage_t::process_services));

    {
        const char* st = kernel_row();
        char label[160];
        std::snprintf(label, sizeof(label), "kernel bridge (slopdrvr)%s",
                      boot.kernel_attempted ? ", running mapper..." : "");
        if (std::strcmp(st, "ok") == 0)
            ImGui::TextColored(ImVec4(0.45f, 0.85f, 0.50f, 1.0f),
                               "[ ok ] %s", label);
        else if (std::strcmp(st, "fail") == 0)
            ImGui::TextColored(ImVec4(0.90f, 0.40f, 0.38f, 1.0f),
                               "[ !! ] %s", label);
        else
            ImGui::TextColored(ImVec4(0.95f, 0.75f, 0.35f, 1.0f),
                               "[ .. ] %s", label);
    }

    row(lifecycle::stage_label(lifecycle::stage_t::settings),
        lifecycle::stage_status(lifecycle::stage_t::settings));
    row(lifecycle::stage_label(lifecycle::stage_t::mcp_server),
        lifecycle::stage_status(lifecycle::stage_t::mcp_server));
    row("interface (imgui/dx11/freetype)",
        lifecycle::stage_status(lifecycle::stage_t::frontend));

    ImGui::Spacing();
    if (!boot.kernel_detail.empty()) {
        ImGui::PushFont(mono);
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.65f, 0.65f, 0.68f, 1.0f));
        ImGui::TextWrapped("%s", boot.kernel_detail.c_str());
        ImGui::PopStyleColor();
        ImGui::PopFont();
    }

    const float frac = static_cast<float>(static_cast<int>(cur)) /
                       static_cast<float>(lifecycle::kStageCount);
    ImGui::SetCursorPosY(size.y - 46.0f);
    ImGui::ProgressBar(frac, ImVec2(-1, 0), "");
    if (boot.first_run)
        ImGui::TextDisabled(
            "first launch: windows asks for administrator consent so the "
            "kernel bridge can load");
    else
        ImGui::TextDisabled("loading...");

    ImGui::EndChild();

    dl->AddRect(ImVec2(origin.x - 1, origin.y - 1),
                ImVec2(origin.x + size.x + 1, origin.y + size.y + 1),
                IM_COL32(70, 70, 78, 160), 4.0f);

    ImGui::End();
    ImGui::PopStyleColor();
    ImGui::PopStyleVar(2);
}

} // namespace

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "dcomp.lib")
#pragma comment(lib, "dwmapi.lib")

// win11 dwm backdrop constants, older sdks may not have them
#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif
#ifndef DWMWA_SYSTEMBACKDROP_TYPE
#define DWMWA_SYSTEMBACKDROP_TYPE 38
#endif
#ifndef DWMSBT_TRANSIENTWINDOW
#define DWMSBT_TRANSIENTWINDOW 3
#endif

namespace {

constexpr wchar_t kWindowClass[] = L"ReverseSlopMain";
constexpr wchar_t kWindowTitle[] = L"reverse-slop";

ID3D11Device*           g_device      = nullptr;
ID3D11DeviceContext*    g_context     = nullptr;
IDXGISwapChain1*        g_swapchain   = nullptr;
ID3D11RenderTargetView* g_rtv         = nullptr;
IDCompositionDevice*    g_dcomp_dev   = nullptr;
IDCompositionTarget*    g_dcomp_target = nullptr;
IDCompositionVisual*    g_dcomp_visual = nullptr;
HWND                    g_hwnd        = nullptr;
std::string             g_ini_path;

bool CreateRenderTarget() {
    ID3D11Texture2D* back_buffer = nullptr;
    if (FAILED(g_swapchain->GetBuffer(0, IID_PPV_ARGS(&back_buffer))))
        return false;
    const HRESULT hr = g_device->CreateRenderTargetView(back_buffer, nullptr, &g_rtv);
    back_buffer->Release();
    return SUCCEEDED(hr);
}

void CleanupRenderTarget() {
    if (g_rtv) { g_rtv->Release(); g_rtv = nullptr; }
}

bool CreateDeviceD3D(HWND hwnd) {
    D3D_FEATURE_LEVEL level{};
    if (FAILED(D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
            D3D11_CREATE_DEVICE_BGRA_SUPPORT, nullptr, 0, D3D11_SDK_VERSION,
            &g_device, &level, &g_context)))
        return false;

    IDXGIDevice1*  dxgi_device = nullptr;
    IDXGIAdapter*  adapter     = nullptr;
    IDXGIFactory2* factory     = nullptr;
    if (FAILED(g_device->QueryInterface(IID_PPV_ARGS(&dxgi_device))) ||
        FAILED(dxgi_device->GetAdapter(&adapter)) ||
        FAILED(adapter->GetParent(IID_PPV_ARGS(&factory)))) {
        if (factory)     factory->Release();
        if (adapter)     adapter->Release();
        if (dxgi_device) dxgi_device->Release();
        return false;
    }

    RECT rc{};
    GetClientRect(hwnd, &rc);
    const UINT w = (rc.right - rc.left) > 0 ? static_cast<UINT>(rc.right - rc.left) : 1;
    const UINT h = (rc.bottom - rc.top) > 0 ? static_cast<UINT>(rc.bottom - rc.top) : 1;

    // premultiplied alpha so dwm can blend the acrylic through the frame
    DXGI_SWAP_CHAIN_DESC1 sd{};
    sd.Width            = w;
    sd.Height           = h;
    sd.Format           = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage      = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.BufferCount      = 2;
    sd.SampleDesc.Count = 1;
    sd.SwapEffect       = DXGI_SWAP_EFFECT_FLIP_DISCARD;
    sd.AlphaMode        = DXGI_ALPHA_MODE_PREMULTIPLIED;
    sd.Scaling          = DXGI_SCALING_STRETCH;

    HRESULT hr = factory->CreateSwapChainForComposition(g_device, &sd, nullptr, &g_swapchain);
    factory->Release();
    adapter->Release();

    if (SUCCEEDED(hr))
        hr = DCompositionCreateDevice(dxgi_device, IID_PPV_ARGS(&g_dcomp_dev));
    dxgi_device->Release();
    if (FAILED(hr)) return false;

    if (FAILED(g_dcomp_dev->CreateTargetForHwnd(hwnd, TRUE, &g_dcomp_target))) return false;
    if (FAILED(g_dcomp_dev->CreateVisual(&g_dcomp_visual))) return false;
    g_dcomp_visual->SetContent(g_swapchain);
    g_dcomp_target->SetRoot(g_dcomp_visual);
    g_dcomp_dev->Commit();

    return CreateRenderTarget();
}

void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_dcomp_visual) { g_dcomp_visual->Release(); g_dcomp_visual = nullptr; }
    if (g_dcomp_target) { g_dcomp_target->Release(); g_dcomp_target = nullptr; }
    if (g_dcomp_dev)    { g_dcomp_dev->Release();    g_dcomp_dev    = nullptr; }
    if (g_swapchain)    { g_swapchain->Release();    g_swapchain    = nullptr; }
    if (g_context)      { g_context->Release();      g_context      = nullptr; }
    if (g_device)       { g_device->Release();       g_device       = nullptr; }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wparam, lparam))
        return 1;

    LRESULT chrome_out = 0;
    if (slop::ui::chrome::HandleMessage(hwnd, msg, wparam, lparam, chrome_out))
        return chrome_out;

    switch (msg) {
    case WM_SIZE:
        if (g_swapchain != nullptr && wparam != SIZE_MINIMIZED) {
            CleanupRenderTarget();
            g_swapchain->ResizeBuffers(0,
                static_cast<UINT>(LOWORD(lparam)),
                static_cast<UINT>(HIWORD(lparam)),
                DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wparam & 0xfff0) == SC_KEYMENU) return 0;
        break;
    case WM_DPICHANGED: {
        const RECT* r = reinterpret_cast<const RECT*>(lparam);
        SetWindowPos(hwnd, nullptr, r->left, r->top,
            r->right - r->left, r->bottom - r->top,
            SWP_NOZORDER | SWP_NOACTIVATE);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        break;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

std::string BuildIniFilePath() {
    char base[MAX_PATH]{};
    const DWORD n = GetEnvironmentVariableA("LOCALAPPDATA", base, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return {};
    std::string dir = std::string(base, n) + "\\reverse-slop";
    CreateDirectoryA(dir.c_str(), nullptr);
    return dir + "\\dock.ini";
}

float DpiScaleFor(HWND hwnd) {
    UINT dpi = GetDpiForWindow(hwnd);
    if (dpi == 0) dpi = 96;
    return static_cast<float>(dpi) / 96.0f;
}

void ApplyWindowChrome(HWND hwnd) {
    BOOL dark = TRUE;
    DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark));

    int backdrop = DWMSBT_TRANSIENTWINDOW; // acrylic
    DwmSetWindowAttribute(hwnd, DWMWA_SYSTEMBACKDROP_TYPE, &backdrop, sizeof(backdrop));

    MARGINS margins = { 1, 1, 1, 1 };
    DwmExtendFrameIntoClientArea(hwnd, &margins);

    SetWindowPos(hwnd, nullptr, 0, 0, 0, 0,
        SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
}

} // namespace

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int n_cmd_show) {
    if (!SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2))
        SetProcessDPIAware();

    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.lpszClassName = kWindowClass;
    RegisterClassExW(&wc);

    g_hwnd = CreateWindowExW(0, kWindowClass, kWindowTitle, WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1680, 980, nullptr, nullptr, hInstance, nullptr);
    if (g_hwnd == nullptr)
        return 1;

    slop::ui::chrome::Init(g_hwnd, DpiScaleFor(g_hwnd));
    ApplyWindowChrome(g_hwnd);

    if (!CreateDeviceD3D(g_hwnd)) {
        CleanupDeviceD3D();
        UnregisterClassW(kWindowClass, hInstance);
        return 1;
    }

    ShowWindow(g_hwnd, n_cmd_show != 0 ? n_cmd_show : SW_SHOWDEFAULT);
    UpdateWindow(g_hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags                    |= ImGuiConfigFlags_DockingEnable | ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigWindowsMoveFromTitleBarOnly = true;

    g_ini_path     = BuildIniFilePath();
    io.IniFilename = g_ini_path.empty() ? nullptr : g_ini_path.c_str();

    slop::ui::fonts::Load(DpiScaleFor(g_hwnd));
    slop::ui::theme::Apply();

    ImGui_ImplWin32_Init(g_hwnd);
    ImGui_ImplDX11_Init(g_device, g_context);

    slop::ui::panels::RegisterBuiltins();

    {
        slop::core::infra::lifecycle::config_t cfg;
        cfg.exe_dir = exe_dir_path();
        slop::core::infra::lifecycle::begin(std::move(cfg));
    }

    slop::ui::panels::AppendBootLog("reverse-slop 0.1.0 (phase 2)");
    slop::ui::panels::AppendBootLog("renderer initialized (directx 11, composition swapchain)");
    slop::ui::panels::AppendBootLog("chrome: borderless + dwm acrylic backdrop");
    slop::ui::panels::AppendBootLog("font backend: freetype");
    slop::ui::panels::AppendBootLog("theme: " + std::string(slop::ui::theme::Current().label));

    MSG msg{};
    bool quitting = false;
    while (!quitting) {
        while (PeekMessageW(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            if (msg.message == WM_QUIT) { quitting = true; break; }
        }
        if (quitting) break;

        // a front end can ask for a clean exit through here
        if (slop::core::infra::app_control::quit_requested()) break;

        slop::core::infra::lifecycle::advance();
        slop::core::infra::lifecycle::tick();
        slop::ui::scanner_view::Tick();

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        if (!slop::core::infra::lifecycle::booted())
            draw_loading_screen();
        else
            slop::ui::dockspace::Render();

        ImGui::Render();

        constexpr std::array<float, 4> clear_color = { 0.0f, 0.0f, 0.0f, 0.0f };
        ID3D11RenderTargetView* rtv = g_rtv;
        g_context->OMSetRenderTargets(1, &rtv, nullptr);
        g_context->ClearRenderTargetView(g_rtv, clear_color.data());
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_swapchain->Present(1, 0);
    }

    slop::core::infra::lifecycle::shutdown();

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    UnregisterClassW(kWindowClass, hInstance);
    return 0;
}


