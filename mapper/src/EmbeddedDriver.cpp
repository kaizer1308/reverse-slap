#include "EmbeddedDriver.h"
#include "P2CDriverBytes.h"
#include <Windows.h>
#include <intrin.h>
#include <cstdio>
#include <cstdarg>

// Forward declare from MapperCore.cpp
extern FILE* g_LogFile;
extern void FlushMapperLogFile();
static void EDDbgLog(const char* func, const char* fmt, ...) {
    char buf[2048];
    va_list args;
    va_start(args, fmt);
    int prefixLen = snprintf(buf, sizeof(buf), "[EmbeddedDriver][%s] ", func);
    if (prefixLen < 0) prefixLen = 0;
    vsnprintf(buf + prefixLen, sizeof(buf) - prefixLen, fmt, args);
    va_end(args);
    printf("%s\n", buf);
    fflush(stdout);
    OutputDebugStringA(buf);
    OutputDebugStringA("\n");
    if (g_LogFile) { fprintf(g_LogFile, "%s\n", buf); FlushMapperLogFile(); }
}
#define EDLOG(fmt, ...) EDDbgLog(__FUNCTION__, fmt, ##__VA_ARGS__)

unsigned char* g_P2CDriverData = nullptr;
size_t g_P2CDriverSize = 0;

static constexpr unsigned char XOR_KEY[] = {
    0x7A, 0xC3, 0x91, 0xE5, 0x3D, 0xF8, 0x46, 0xAB,
    0x1F, 0x82, 0xD7, 0x54, 0x69, 0xBE, 0x03, 0xC6
};

BOOL InitializeDriverData() {
    EDLOG("rawDataSize=%zu", rawDataSize);
    if (rawDataSize < 2) {
        EDLOG("ERROR: rawDataSize too small!");
        return FALSE;
    }

    g_P2CDriverData = (unsigned char*)VirtualAlloc(
        nullptr, rawDataSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!g_P2CDriverData) {
        EDLOG("ERROR: VirtualAlloc failed, GLE=%u", GetLastError());
        return FALSE;
    }
    EDLOG("Allocated %zu bytes at %p", rawDataSize, g_P2CDriverData);

    for (size_t i = 0; i < rawDataSize; i++) {
        g_P2CDriverData[i] = rawData[i] ^ XOR_KEY[i % sizeof(XOR_KEY)];
    }

    if (g_P2CDriverData[0] != 'M' || g_P2CDriverData[1] != 'Z') {
        EDLOG("ERROR: MZ validation failed! First bytes: 0x%02X 0x%02X", g_P2CDriverData[0], g_P2CDriverData[1]);
        SecureZeroMemory(g_P2CDriverData, rawDataSize);
        VirtualFree(g_P2CDriverData, 0, MEM_RELEASE);
        g_P2CDriverData = nullptr;
        return FALSE;
    }

    g_P2CDriverSize = rawDataSize;
    EDLOG("Driver data initialized OK, size=%zu, MZ validated", g_P2CDriverSize);
    return TRUE;
}

void ReleaseDriverData() {
    if (g_P2CDriverData) {
        SecureZeroMemory(g_P2CDriverData, g_P2CDriverSize);
        VirtualFree(g_P2CDriverData, 0, MEM_RELEASE);
        g_P2CDriverData = nullptr;
        g_P2CDriverSize = 0;
    }
}
